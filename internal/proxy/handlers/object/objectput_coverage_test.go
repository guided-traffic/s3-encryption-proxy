package object

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/guided-traffic/s3-encryption-proxy/internal/config"
	"github.com/guided-traffic/s3-encryption-proxy/internal/orchestration"
	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption"
)

// ---------------------------------------------------------------------------
// PUT: the client contract.
//
// Everything here drives a real HTTP request through the handler and then looks
// at two things only: what the client got back, and what the backend was asked
// to store. The bytes handed to the backend are checked by decrypting them
// again and comparing sha256 against what the client sent, so the assertions
// survive a change of storage format: whatever the pipeline does in between,
// a PUT has to store something that is not the plaintext and that reads back
// as the plaintext.
// ---------------------------------------------------------------------------

const ObjPutaesKey = "ZEsubBlmU+Pr61y+JOwO09c0LOrHs5LITaO0D4JzSZE="

// ObjPutopts describes the handler configuration a test needs. The zero value
// is an AES provider, strict HMAC, the production 5 MiB streaming threshold and
// a single upload worker.
type ObjPutopts struct {
	providerType string // "aes" (default) or "none"
	integrity    string // default: strict
	prefix       string // default: "s3ep-"
	threshold    int64  // default: 5 MiB
	segmentSize  int64  // default: 1 KiB, so auto-multipart parts stay small
	concurrency  int    // default: 1
	awsChunked   bool   // enable aws-chunked decoding
}

// ObjPutnewHandler wires a handler exactly like NewHandler does in production,
// with a real encryption manager behind it.
func ObjPutnewHandler(t *testing.T, backend *MockS3Backend, o ObjPutopts) *Handler {
	t.Helper()

	if o.providerType == "" {
		o.providerType = "aes"
	}
	if o.integrity == "" {
		o.integrity = config.HMACVerificationStrict
	}
	if o.prefix == "" {
		o.prefix = "s3ep-"
	}
	if o.threshold == 0 {
		o.threshold = 5 * 1024 * 1024
	}
	if o.segmentSize == 0 {
		o.segmentSize = 1024
	}
	if o.concurrency == 0 {
		o.concurrency = 1
	}

	provider := config.EncryptionProvider{Alias: "test-provider", Type: o.providerType}
	if o.providerType == "aes" {
		provider.Config = map[string]interface{}{"aes_key": ObjPutaesKey}
	}

	prefix := o.prefix
	cfg := &config.Config{
		Encryption: config.EncryptionConfig{
			EncryptionMethodAlias: "test-provider",
			MetadataKeyPrefix:     &prefix,
			IntegrityVerification: o.integrity,
			Providers:             []config.EncryptionProvider{provider},
		},
	}
	cfg.Optimizations.StreamingThreshold = o.threshold
	cfg.Optimizations.StreamingSegmentSize = o.segmentSize
	cfg.Optimizations.MultipartUploadConcurrency = o.concurrency
	cfg.Optimizations.CleanAWSSignatureV4Chunked = o.awsChunked

	encMgr, err := orchestration.NewManager(cfg)
	require.NoError(t, err)
	return NewHandler(backend, encMgr, cfg, testLogEntry())
}

// ObjPutdigest keeps large-payload comparisons out of the failure output.
func ObjPutdigest(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// ObjPutpayload builds a deterministic payload of n bytes.
func ObjPutpayload(n int) []byte {
	out := make([]byte, n)
	state := uint32(0x2545f491)
	for i := range out {
		state ^= state << 13
		state ^= state >> 17
		state ^= state << 5
		out[i] = byte(state)
	}
	return out
}

// ObjPutdo drives a request through the public entry point, so routing and the
// method switch are part of what is under test.
func ObjPutdo(h *Handler, req *http.Request, bucket, key string) *httptest.ResponseRecorder {
	req = mux.SetURLVars(req, map[string]string{"bucket": bucket, "key": key})
	rr := httptest.NewRecorder()
	h.Handle(rr, req)
	return rr
}

// ObjPuterrorDoc parses the S3 <Error> document out of a response body.
type ObjPuterrorDoc struct {
	XMLName xml.Name `xml:"Error"`
	Code    string   `xml:"Code"`
	Message string   `xml:"Message"`
}

func ObjPutparseError(t *testing.T, body []byte) ObjPuterrorDoc {
	t.Helper()
	var doc ObjPuterrorDoc
	require.NoError(t, xml.Unmarshal(body, &doc), "error response must be a parseable S3 error document")
	return doc
}

// ObjPutcapturePut records the single PutObject call a test expects and returns
// a pointer the test reads after the request. The body is drained inside the
// mock because the production code streams it lazily.
func ObjPutcapturePut(backend *MockS3Backend, etag, versionID string) *ObjPutstored {
	stored := &ObjPutstored{}
	out := &s3.PutObjectOutput{}
	if etag != "" {
		out.ETag = aws.String(etag)
	}
	if versionID != "" {
		out.VersionId = aws.String(versionID)
	}
	backend.On("PutObject", mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			in := args.Get(1).(*s3.PutObjectInput)
			stored.input = in
			if in.Body != nil {
				body, err := io.ReadAll(in.Body)
				stored.readErr = err
				stored.body = body
			}
		}).
		Return(out, nil)
	return stored
}

type ObjPutstored struct {
	input   *s3.PutObjectInput
	body    []byte
	readErr error
}

// ObjPutreadBack decrypts what the backend was handed, using the metadata the
// backend was handed, and returns the plaintext a later GET would produce.
func ObjPutreadBack(t *testing.T, h *Handler, key string, ciphertext []byte, metadata map[string]string) []byte {
	t.Helper()
	reader, err := h.encryptionMgr.DecryptData(t.Context(), bufio.NewReader(bytes.NewReader(ciphertext)), metadata, key)
	require.NoError(t, err)
	plain, err := io.ReadAll(reader)
	require.NoError(t, err)
	return plain
}

// ObjPutencryptionMetadata returns only the s3ep- (or configured prefix) keys.
func ObjPutencryptionMetadata(metadata map[string]string, prefix string) []string {
	keys := make([]string, 0, len(metadata))
	for k := range metadata {
		if strings.HasPrefix(k, prefix) {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	return keys
}

// ObjPutlookupMeta reads object metadata case-insensitively. It has to: the
// three PUT paths disagree on the case of a user metadata key (see
// TestObjPutUserMetadataKeyCaseDiffersPerPath).
func ObjPutlookupMeta(metadata map[string]string, key string) (string, bool) {
	for k, v := range metadata {
		if strings.EqualFold(k, key) {
			return v, true
		}
	}
	return "", false
}

// ObjPutallowedMetadata is the set CLAUDE.md declares as the only encryption
// metadata the proxy may write.
var ObjPutallowedMetadata = map[string]bool{
	"dek-algorithm":   true,
	"encrypted-dek":   true,
	"aes-iv":          true,
	"kek-algorithm":   true,
	"kek-fingerprint": true,
	"hmac":            true,
}

// ObjPuterrReader fails after handing out prefix bytes, standing in for a
// client that hangs up mid-body.
type ObjPuterrReader struct {
	prefix []byte
	off    int
	err    error
}

func (r *ObjPuterrReader) Read(p []byte) (int, error) {
	if r.off < len(r.prefix) {
		n := copy(p, r.prefix[r.off:])
		r.off += n
		return n, nil
	}
	return 0, r.err
}

// ---------------------------------------------------------------------------
// A small PUT: ciphertext at the backend, an exact metadata set, 200 + ETag.
// ---------------------------------------------------------------------------

func TestObjPutSmallObjectStoresCiphertextAndAnswers200(t *testing.T) {
	backend := new(MockS3Backend)
	h := ObjPutnewHandler(t, backend, ObjPutopts{})

	payload := ObjPutpayload(1024)
	stored := ObjPutcapturePut(backend, `"stored-etag"`, "version-9")

	req := httptest.NewRequest(http.MethodPut, "/b/small-key", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "text/plain")
	rr := ObjPutdo(h, req, "b", "small-key")

	require.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, `"stored-etag"`, rr.Header().Get("ETag"))
	assert.Equal(t, "version-9", rr.Header().Get("x-amz-version-id"))

	require.NotNil(t, stored.input)
	require.NoError(t, stored.readErr)
	assert.Equal(t, "b", aws.ToString(stored.input.Bucket))
	assert.Equal(t, "small-key", aws.ToString(stored.input.Key))
	assert.Equal(t, "text/plain", aws.ToString(stored.input.ContentType))

	// The whole point of the proxy: the plaintext must not be what is stored.
	assert.NotEqual(t, ObjPutdigest(payload), ObjPutdigest(stored.body),
		"the backend was handed the plaintext")
	assert.False(t, bytes.Contains(stored.body, payload[:64]),
		"a plaintext prefix survived into the stored object")

	// And it has to read back as exactly what the client sent.
	assert.Equal(t, ObjPutdigest(payload),
		ObjPutdigest(ObjPutreadBack(t, h, "small-key", stored.body, stored.input.Metadata)))

	// The declared Content-Length must match the bytes actually streamed, or the
	// backend either rejects the request or truncates the object.
	assert.Equal(t, int64(len(stored.body)), aws.ToInt64(stored.input.ContentLength))

	// Only the documented encryption metadata keys may be written.
	for _, k := range ObjPutencryptionMetadata(stored.input.Metadata, "s3ep-") {
		assert.Truef(t, ObjPutallowedMetadata[strings.TrimPrefix(k, "s3ep-")],
			"undocumented encryption metadata key %q", k)
	}
	assert.Subset(t,
		ObjPutencryptionMetadata(stored.input.Metadata, "s3ep-"),
		[]string{"s3ep-dek-algorithm", "s3ep-encrypted-dek", "s3ep-kek-algorithm", "s3ep-kek-fingerprint"},
		"an object without these cannot be decrypted again")
}

// The metadata prefix is configurable; nothing may be written under the default
// prefix once it is changed, or the object becomes undecryptable.
func TestObjPutCustomMetadataPrefixIsUsedEverywhere(t *testing.T) {
	backend := new(MockS3Backend)
	h := ObjPutnewHandler(t, backend, ObjPutopts{prefix: "enc-"})

	payload := ObjPutpayload(300)
	stored := ObjPutcapturePut(backend, `"e"`, "")

	rr := ObjPutdo(h, httptest.NewRequest(http.MethodPut, "/b/k", bytes.NewReader(payload)), "b", "k")
	require.Equal(t, http.StatusOK, rr.Code)

	require.NotNil(t, stored.input)
	assert.Empty(t, ObjPutencryptionMetadata(stored.input.Metadata, "s3ep-"))
	for _, k := range ObjPutencryptionMetadata(stored.input.Metadata, "enc-") {
		assert.Truef(t, ObjPutallowedMetadata[strings.TrimPrefix(k, "enc-")],
			"undocumented encryption metadata key %q", k)
	}
	assert.Equal(t, ObjPutdigest(payload),
		ObjPutdigest(ObjPutreadBack(t, h, "k", stored.body, stored.input.Metadata)))
}

// The none provider is configured pass-through: the backend receives the
// plaintext and no encryption metadata at all. Nothing in the proxy prevents
// this, which is the documented behaviour of the provider.
func TestObjPutNoneProviderPassesPlaintextThrough(t *testing.T) {
	for name, size := range map[string]int{"small_direct": 512, "streaming": 4096} {
		t.Run(name, func(t *testing.T) {
			backend := new(MockS3Backend)
			h := ObjPutnewHandler(t, backend, ObjPutopts{providerType: "none", threshold: 2048})

			payload := ObjPutpayload(size)
			stored := ObjPutcapturePut(backend, `"n"`, "")

			req := httptest.NewRequest(http.MethodPut, "/b/k", bytes.NewReader(payload))
			req.Header.Set("x-amz-meta-owner", "hans")
			rr := ObjPutdo(h, req, "b", "k")

			require.Equal(t, http.StatusOK, rr.Code)
			require.NotNil(t, stored.input)
			assert.Equal(t, ObjPutdigest(payload), ObjPutdigest(stored.body),
				"the none provider must store the bytes unchanged")
			assert.Equal(t, int64(len(payload)), aws.ToInt64(stored.input.ContentLength))
			assert.Empty(t, ObjPutencryptionMetadata(stored.input.Metadata, "s3ep-"))
			owner, ok := ObjPutlookupMeta(stored.input.Metadata, "owner")
			require.True(t, ok, "user metadata must survive the pass-through")
			assert.Equal(t, "hans", owner)
		})
	}
}

// ---------------------------------------------------------------------------
// Boundaries around the streaming threshold.
// ---------------------------------------------------------------------------

// Whatever branch a size takes, the object has to read back byte-identical and
// must not be stored as plaintext. This is the assertion that outlives the
// storage format.
func TestObjPutRoundTripAcrossTheStreamingThreshold(t *testing.T) {
	const threshold = 1024 * 1024 // the smallest streaming_threshold the config validator accepts

	sizes := map[string]int{
		"empty":           0,
		"one_byte":        1,
		"below_threshold": threshold - 1,
		"at_threshold":    threshold,
		"above_threshold": threshold + 1,
	}

	for name, size := range sizes {
		t.Run(name, func(t *testing.T) {
			backend := new(MockS3Backend)
			h := ObjPutnewHandler(t, backend, ObjPutopts{threshold: threshold})

			payload := ObjPutpayload(size)
			stored := ObjPutcapturePut(backend, `"etag"`, "")

			rr := ObjPutdo(h, httptest.NewRequest(http.MethodPut, "/b/k", bytes.NewReader(payload)), "b", "k")

			require.Equal(t, http.StatusOK, rr.Code)
			require.NotNil(t, stored.input)
			require.NoError(t, stored.readErr)

			if size > 0 {
				assert.NotEqual(t, ObjPutdigest(payload), ObjPutdigest(stored.body),
					"the backend was handed the plaintext")
			}
			assert.Equal(t, ObjPutdigest(payload),
				ObjPutdigest(ObjPutreadBack(t, h, "k", stored.body, stored.input.Metadata)))
			assert.Equal(t, int64(len(stored.body)), aws.ToInt64(stored.input.ContentLength),
				"a declared length that does not match the streamed body truncates the object")

			// Neither branch may reach for multipart below 5 MiB.
			backend.AssertNotCalled(t, "CreateMultipartUpload", mock.Anything, mock.Anything)
		})
	}
}

// Pins the current storage-format behaviour. The segmented-GCM format (ADR 0003)
// replaces this; update together.
// The threshold decides which cipher writes the object: below it AES-GCM (28
// bytes of overhead), at or above it AES-CTR (no overhead).
func TestObjPutThresholdSelectsTheStoredAlgorithm(t *testing.T) {
	const threshold = 1024 * 1024

	cases := map[string]struct {
		size          int
		wantAlgorithm string
		wantOverhead  int64
	}{
		"one_below": {threshold - 1, "aes-gcm", encryption.GCMOverhead},
		"exactly":   {threshold, "aes-ctr", 0},
		"one_above": {threshold + 1, "aes-ctr", 0},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			backend := new(MockS3Backend)
			h := ObjPutnewHandler(t, backend, ObjPutopts{threshold: threshold})
			stored := ObjPutcapturePut(backend, `"etag"`, "")

			payload := ObjPutpayload(tc.size)
			rr := ObjPutdo(h, httptest.NewRequest(http.MethodPut, "/b/k", bytes.NewReader(payload)), "b", "k")

			require.Equal(t, http.StatusOK, rr.Code)
			require.NotNil(t, stored.input)
			assert.Equal(t, tc.wantAlgorithm, stored.input.Metadata["s3ep-dek-algorithm"])
			assert.Equal(t, int64(tc.size)+tc.wantOverhead, aws.ToInt64(stored.input.ContentLength))
		})
	}
}

// Pins the current storage-format behaviour. The segmented-GCM format (ADR 0003)
// replaces this; update together.
// The magic content type forces AES-CTR. Below 1 KiB it still goes through the
// buffered path because S3 has no part smaller than 5 MiB; above it, streaming.
func TestObjPutForceCTRContentTypeSelectsCTRAtEverySize(t *testing.T) {
	for name, size := range map[string]int{"tiny_forced": 16, "over_1kib_forced": 4096} {
		t.Run(name, func(t *testing.T) {
			backend := new(MockS3Backend)
			h := ObjPutnewHandler(t, backend, ObjPutopts{})
			stored := ObjPutcapturePut(backend, `"etag"`, "")

			payload := ObjPutpayload(size)
			req := httptest.NewRequest(http.MethodPut, "/b/k", bytes.NewReader(payload))
			req.Header.Set("Content-Type", "application/x-s3ep-force-aes-ctr")
			rr := ObjPutdo(h, req, "b", "k")

			require.Equal(t, http.StatusOK, rr.Code)
			require.NotNil(t, stored.input)
			assert.Equal(t, "aes-ctr", stored.input.Metadata["s3ep-dek-algorithm"])
			assert.Equal(t, ObjPutdigest(payload),
				ObjPutdigest(ObjPutreadBack(t, h, "k", stored.body, stored.input.Metadata)))
		})
	}
}

func TestObjPutGetStreamingReason(t *testing.T) {
	assert.Equal(t, "content-type forced", getStreamingReason(true, 10, 20))
	assert.Equal(t, "content-type forced", getStreamingReason(true, -1, 0))
	assert.Equal(t, "size 4096 >= threshold 1024", getStreamingReason(false, 4096, 1024))
	assert.Equal(t, "size -1 >= threshold 5242880", getStreamingReason(false, -1, 5*1024*1024))
}

// ---------------------------------------------------------------------------
// Which request headers reach the backend.
// ---------------------------------------------------------------------------

// ObjPutstorageHeaders are the PUT headers a client can send that this proxy
// parses nowhere. ADR 0007 decides they are forwarded to the backend unchanged,
// never dropped behind a 200.
var ObjPutstorageHeaders = map[string]string{
	"x-amz-server-side-encryption":                "AES256",
	"x-amz-server-side-encryption-aws-kms-key-id": "arn:aws:kms:eu-central-1:1:key/abc",
	"x-amz-storage-class":                         "GLACIER",
	"x-amz-tagging":                               "team=platform",
	"x-amz-acl":                                   "public-read",
	"x-amz-grant-full-control":                    "id=someone",
	"x-amz-object-lock-mode":                      "COMPLIANCE",
	"x-amz-object-lock-retain-until-date":         "2099-01-01T00:00:00Z",
	"x-amz-object-lock-legal-hold":                "ON",
	"x-amz-website-redirect-location":             "/elsewhere",
}

func ObjPutsetAllHeaders(req *http.Request) {
	req.Header.Set("Cache-Control", "max-age=42")
	req.Header.Set("Content-Disposition", `attachment; filename="report.pdf"`)
	req.Header.Set("Content-Encoding", "aws-chunked, gzip")
	req.Header.Set("Content-Language", "en-GB")
	req.Header.Set("Expires", "Wed, 21 Oct 2099 07:28:00 GMT")
	req.Header.Set("x-amz-meta-project", "orion")
	for name, value := range ObjPutstorageHeaders {
		req.Header.Set(name, value)
	}
}

// The four entity headers plus Content-Type and x-amz-meta-* are all that
// reaches the backend on either single-part PUT path. Every storage header a
// client can send is dropped and the request still answers 200 - the "silent
// 200" class ADR 0007 forbids.
func TestObjPutForwardsOnlyTheEntityHeadersOnSinglePartPaths(t *testing.T) {
	const threshold = 1024 * 1024

	for name, size := range map[string]int{"direct_path": 256, "streaming_path": threshold} {
		t.Run(name, func(t *testing.T) {
			backend := new(MockS3Backend)
			h := ObjPutnewHandler(t, backend, ObjPutopts{threshold: threshold})
			stored := ObjPutcapturePut(backend, `"etag"`, "")

			req := httptest.NewRequest(http.MethodPut, "/b/k", bytes.NewReader(ObjPutpayload(size)))
			req.Header.Set("Content-Type", "application/pdf")
			ObjPutsetAllHeaders(req)
			req.Header.Set("Content-Length", fmt.Sprintf("%d", size))
			req.ContentLength = int64(size)

			rr := ObjPutdo(h, req, "b", "k")

			require.Equal(t, http.StatusOK, rr.Code,
				"a request asking for storage class, tagging, SSE and object lock answers 200")
			require.NotNil(t, stored.input)

			// Forwarded.
			assert.Equal(t, "max-age=42", aws.ToString(stored.input.CacheControl))
			assert.Equal(t, `attachment; filename="report.pdf"`, aws.ToString(stored.input.ContentDisposition))
			assert.Equal(t, "gzip", aws.ToString(stored.input.ContentEncoding),
				"aws-chunked describes the request framing and must be stripped")
			assert.Equal(t, "en-GB", aws.ToString(stored.input.ContentLanguage))
			assert.Equal(t, "application/pdf", aws.ToString(stored.input.ContentType))
			project, ok := ObjPutlookupMeta(stored.input.Metadata, "project")
			require.True(t, ok)
			assert.Equal(t, "orion", project)

			// Dropped, silently.
			assert.Empty(t, stored.input.ServerSideEncryption)
			assert.Nil(t, stored.input.SSEKMSKeyId)
			assert.Empty(t, stored.input.StorageClass)
			assert.Nil(t, stored.input.Tagging)
			assert.Empty(t, stored.input.ACL)
			assert.Nil(t, stored.input.GrantFullControl)
			assert.Empty(t, stored.input.ObjectLockMode)
			assert.Nil(t, stored.input.ObjectLockRetainUntilDate)
			assert.Empty(t, stored.input.ObjectLockLegalHoldStatus)
			assert.Nil(t, stored.input.WebsiteRedirectLocation)
			assert.Nil(t, stored.input.Expires, "the Expires header is deliberately not parsed")
			assert.Nil(t, stored.input.ContentMD5)
			assert.Empty(t, stored.input.ChecksumAlgorithm)
		})
	}
}

// The same on the auto-multipart path: CreateMultipartUpload carries the four
// entity headers and the user metadata, and nothing else.
func TestObjPutAutoMultipartForwardsOnlyTheEntityHeaders(t *testing.T) {
	backend := new(MockS3Backend)
	h := ObjPutnewHandler(t, backend, ObjPutopts{})

	var createInput *s3.CreateMultipartUploadInput
	backend.On("CreateMultipartUpload", mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) { createInput = args.Get(1).(*s3.CreateMultipartUploadInput) }).
		Return(&s3.CreateMultipartUploadOutput{UploadId: aws.String("u1")}, nil)
	backend.On("UploadPart", mock.Anything, mock.Anything).
		Return(&s3.UploadPartOutput{ETag: aws.String(`"p"`)}, nil)
	backend.On("CompleteMultipartUpload", mock.Anything, mock.Anything).
		Return(&s3.CompleteMultipartUploadOutput{ETag: aws.String(`"c"`)}, nil)
	backend.On("CopyObject", mock.Anything, mock.Anything).
		Return(&s3.CopyObjectOutput{CopyObjectResult: &types.CopyObjectResult{ETag: aws.String(`"cp"`)}}, nil)

	req := httptest.NewRequest(http.MethodPut, "/b/k", bytes.NewReader(ObjPutpayload(2048)))
	req.Header.Set("Content-Type", "application/pdf")
	ObjPutsetAllHeaders(req)
	req.ContentLength = -1 // unknown length routes to auto-multipart at any size

	rr := ObjPutdo(h, req, "b", "k")

	require.Equal(t, http.StatusOK, rr.Code)
	require.NotNil(t, createInput)
	assert.Equal(t, "max-age=42", aws.ToString(createInput.CacheControl))
	assert.Equal(t, `attachment; filename="report.pdf"`, aws.ToString(createInput.ContentDisposition))
	assert.Equal(t, "gzip", aws.ToString(createInput.ContentEncoding))
	assert.Equal(t, "en-GB", aws.ToString(createInput.ContentLanguage))
	assert.Equal(t, "application/pdf", aws.ToString(createInput.ContentType))
	assert.Equal(t, "orion", createInput.Metadata["project"])
	// Lowercased here, unlike on the two single-part paths.

	assert.Empty(t, createInput.ServerSideEncryption)
	assert.Empty(t, createInput.StorageClass)
	assert.Nil(t, createInput.Tagging)
	assert.Empty(t, createInput.ACL)
	assert.Empty(t, createInput.ObjectLockMode)
	assert.Nil(t, createInput.WebsiteRedirectLocation)
	assert.Nil(t, createInput.Expires)
}

func TestObjPutAddRequestHeaders(t *testing.T) {
	h := &Handler{metadataPrefix: "s3ep-"}

	t.Run("nothing set", func(t *testing.T) {
		input := &s3.PutObjectInput{}
		h.addRequestHeaders(httptest.NewRequest(http.MethodPut, "/b/k", nil), input)
		assert.Nil(t, input.CacheControl)
		assert.Nil(t, input.ContentDisposition)
		assert.Nil(t, input.ContentEncoding)
		assert.Nil(t, input.ContentLanguage)
	})

	t.Run("aws-chunked only leaves content-encoding unset", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPut, "/b/k", nil)
		req.Header.Set("Content-Encoding", "aws-chunked")
		input := &s3.PutObjectInput{}
		h.addRequestHeaders(req, input)
		assert.Nil(t, input.ContentEncoding,
			"storing aws-chunked would tell every later reader the object is framed")
	})

	t.Run("all four forwarded", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPut, "/b/k", nil)
		req.Header.Set("Cache-Control", "no-store")
		req.Header.Set("Content-Disposition", "inline")
		req.Header.Set("Content-Encoding", "br, aws-chunked")
		req.Header.Set("Content-Language", "fr")
		input := &s3.PutObjectInput{}
		h.addRequestHeaders(req, input)
		assert.Equal(t, "no-store", aws.ToString(input.CacheControl))
		assert.Equal(t, "inline", aws.ToString(input.ContentDisposition))
		assert.Equal(t, "br", aws.ToString(input.ContentEncoding))
		assert.Equal(t, "fr", aws.ToString(input.ContentLanguage))
	})
}

func TestObjPutPrepareEncryptionMetadata(t *testing.T) {
	h := &Handler{metadataPrefix: "s3ep-"}

	t.Run("user metadata and encryption metadata are merged", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPut, "/b/k", nil)
		req.Header.Set("x-amz-meta-owner", "hans")
		req.Header.Set("X-Amz-Meta-Team", "platform")
		req.Header.Set("Content-Type", "text/plain")
		req.Header.Set("x-amz-storage-class", "GLACIER")

		out := h.prepareEncryptionMetadata(req, &orchestration.EncryptionResult{
			Metadata: map[string]string{"s3ep-dek-algorithm": "aes-gcm"},
		})

		assert.Equal(t, "hans", out["owner"])
		assert.Equal(t, "platform", out["team"])
		assert.Equal(t, "aes-gcm", out["s3ep-dek-algorithm"])
		assert.Len(t, out, 3, "only x-amz-meta-* headers become object metadata")
	})

	t.Run("a header shorter than the prefix is not sliced", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPut, "/b/k", nil)
		req.Header.Set("X-Amz-Meta", "no-suffix")
		out := h.prepareEncryptionMetadata(req, &orchestration.EncryptionResult{Metadata: map[string]string{}})
		assert.Empty(t, out)
	})

	t.Run("an encryption-prefixed key is filtered in either spelling", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPut, "/b/k", nil)
		// The raw map entry is the uncanonicalised spelling, Header.Set the
		// canonical one. Both are refused.
		req.Header["x-amz-meta-s3ep-hmac"] = []string{"forged"}
		req.Header.Set("x-amz-meta-s3ep-encrypted-dek", "forged")
		out := h.prepareEncryptionMetadata(req, &orchestration.EncryptionResult{Metadata: map[string]string{}})
		assert.Empty(t, out)
	})
}

// A client cannot write encryption metadata on any single-part path.
//
// The guard used to compare the metadata key byte for byte against the
// lowercase configured prefix, while net/http canonicalises every request
// header name: a header sent as x-amz-meta-s3ep-hmac arrived as
// X-Amz-Meta-S3ep-Hmac, the key was "S3ep-Hmac", and the guard never fired.
// Both keys then reached the backend, S3 lowered one onto the other, and the
// client value won often enough to leave the object undecryptable. The
// none-provider streaming branch had no guard at all.
func TestObjPutClientCannotInjectEncryptionMetadataOnSinglePartPaths(t *testing.T) {
	// Three spellings a client can send. All canonicalise to one header, which
	// is exactly why comparing the case mattered.
	spellings := []string{
		"x-amz-meta-s3ep-encrypted-dek",
		"X-Amz-Meta-S3EP-Encrypted-Dek",
		"X-AMZ-META-S3EP-ENCRYPTED-DEK",
	}

	paths := map[string]ObjPutopts{
		"direct_path":    {threshold: 2048},
		"streaming_path": {threshold: 2048},
		"none_provider":  {providerType: "none", threshold: 2048},
	}
	sizes := map[string]int{"direct_path": 256, "streaming_path": 4096, "none_provider": 4096}

	for name, opts := range paths {
		for _, spelling := range spellings {
			t.Run(name+"/"+spelling, func(t *testing.T) {
				backend := new(MockS3Backend)
				h := ObjPutnewHandler(t, backend, opts)
				stored := ObjPutcapturePut(backend, `"etag"`, "")

				req := httptest.NewRequest(http.MethodPut, "/b/k", bytes.NewReader(ObjPutpayload(sizes[name])))
				req.Header.Set("x-amz-meta-s3ep-hmac", "forged-hmac")
				req.Header.Set(spelling, "forged-dek")
				req.Header.Set("x-amz-meta-project", "orion")

				rr := ObjPutdo(h, req, "b", "k")
				require.Equal(t, http.StatusOK, rr.Code)
				require.NotNil(t, stored.input)

				for k, v := range stored.input.Metadata {
					assert.NotEqual(t, "forged-dek", v, "forged value stored under key %q", k)
					assert.NotEqual(t, "forged-hmac", v, "forged value stored under key %q", k)
				}
				assert.Equal(t, "orion", stored.input.Metadata["project"],
					"metadata outside the namespace is untouched")
			})
		}
	}
}

// The auto-multipart path lowercases the key before the same check, so the
// guard has always worked there. Kept as the third path.
func TestObjPutAutoMultipartFiltersInjectedEncryptionMetadata(t *testing.T) {
	backend := new(MockS3Backend)
	h := ObjPutnewHandler(t, backend, ObjPutopts{})

	var createInput *s3.CreateMultipartUploadInput
	var copyInput *s3.CopyObjectInput
	backend.On("CreateMultipartUpload", mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) { createInput = args.Get(1).(*s3.CreateMultipartUploadInput) }).
		Return(&s3.CreateMultipartUploadOutput{UploadId: aws.String("u1")}, nil)
	backend.On("UploadPart", mock.Anything, mock.Anything).
		Return(&s3.UploadPartOutput{ETag: aws.String(`"p"`)}, nil)
	backend.On("CompleteMultipartUpload", mock.Anything, mock.Anything).
		Return(&s3.CompleteMultipartUploadOutput{ETag: aws.String(`"c"`)}, nil)
	backend.On("CopyObject", mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) { copyInput = args.Get(1).(*s3.CopyObjectInput) }).
		Return(&s3.CopyObjectOutput{CopyObjectResult: &types.CopyObjectResult{ETag: aws.String(`"cp"`)}}, nil)

	req := httptest.NewRequest(http.MethodPut, "/b/k", bytes.NewReader(ObjPutpayload(2048)))
	req.Header.Set("x-amz-meta-s3ep-hmac", "forged-hmac")
	req.Header.Set("x-amz-meta-keep", "value")
	req.ContentLength = -1

	rr := ObjPutdo(h, req, "b", "k")
	require.Equal(t, http.StatusOK, rr.Code)

	require.NotNil(t, createInput)
	assert.Equal(t, map[string]string{"keep": "value"}, createInput.Metadata)
	require.NotNil(t, copyInput)
	assert.NotEqual(t, "forged-hmac", copyInput.Metadata["s3ep-hmac"])
	assert.Equal(t, "value", copyInput.Metadata["keep"])
}

// ---------------------------------------------------------------------------
// Error paths on the single-part PUTs.
// ---------------------------------------------------------------------------

func TestObjPutBackendPutObjectErrorsAreMapped(t *testing.T) {
	cases := map[string]struct {
		err        error
		wantStatus int
		wantCode   string
	}{
		"no_such_bucket": {&types.NoSuchBucket{}, http.StatusNotFound, "NoSuchBucket"},
		"access_denied": {&smithy.GenericAPIError{Code: "AccessDenied", Message: "Access Denied"},
			http.StatusForbidden, "AccessDenied"},
		"entity_too_large": {&smithy.GenericAPIError{Code: "EntityTooLarge"},
			http.StatusBadRequest, "EntityTooLarge"},
		"network_error": {errors.New("dial tcp 10.0.0.1:9000: connect: connection refused"),
			http.StatusInternalServerError, "InternalError"},
	}

	const threshold = 1024 * 1024
	for _, path := range []struct {
		name string
		size int
	}{{"direct_path", 256}, {"streaming_path", threshold}} {
		for name, tc := range cases {
			t.Run(path.name+"/"+name, func(t *testing.T) {
				backend := new(MockS3Backend)
				h := ObjPutnewHandler(t, backend, ObjPutopts{threshold: threshold})
				backend.On("PutObject", mock.Anything, mock.Anything).Return(nil, tc.err)

				rr := ObjPutdo(h, httptest.NewRequest(http.MethodPut, "/b/k",
					bytes.NewReader(ObjPutpayload(path.size))), "b", "k")

				assert.Equal(t, tc.wantStatus, rr.Code)
				assert.Equal(t, "application/xml", rr.Header().Get("Content-Type"))
				doc := ObjPutparseError(t, rr.Body.Bytes())
				assert.Equal(t, tc.wantCode, doc.Code)
				assert.NotEmpty(t, doc.Message)
				assert.NotContains(t, rr.Body.String(), "10.0.0.1",
					"the backend endpoint must never reach the client")
				assert.Empty(t, rr.Header().Get("ETag"), "a failed PUT must not report an ETag")
			})
		}
	}
}

// A body that dies mid-read must not become a stored object.
func TestObjPutBodyReadErrorDoesNotStoreAnything(t *testing.T) {
	t.Run("direct path answers 500 ReadError", func(t *testing.T) {
		backend := new(MockS3Backend)
		h := ObjPutnewHandler(t, backend, ObjPutopts{})

		req := httptest.NewRequest(http.MethodPut, "/b/k", &ObjPuterrReader{
			prefix: ObjPutpayload(10),
			err:    errors.New("connection reset by peer"),
		})
		req.ContentLength = 4096

		rr := ObjPutdo(h, req, "b", "k")

		assert.Equal(t, http.StatusInternalServerError, rr.Code)
		assert.Equal(t, "ReadError", ObjPutparseError(t, rr.Body.Bytes()).Code)
		backend.AssertNotCalled(t, "PutObject", mock.Anything, mock.Anything)
	})

	// The forced-CTR small-file branch reports the same failure as a 400. AWS
	// answers a short or broken request body with 400 IncompleteBody, so the
	// two branches disagree with each other and one of them disagrees with S3.
	t.Run("forced ctr small file answers 400 ReadError", func(t *testing.T) {
		backend := new(MockS3Backend)
		h := ObjPutnewHandler(t, backend, ObjPutopts{})

		req := httptest.NewRequest(http.MethodPut, "/b/k", &ObjPuterrReader{
			prefix: ObjPutpayload(4),
			err:    errors.New("connection reset by peer"),
		})
		req.Header.Set("Content-Type", "application/x-s3ep-force-aes-ctr")
		req.ContentLength = 512

		rr := ObjPutdo(h, req, "b", "k")

		assert.Equal(t, http.StatusBadRequest, rr.Code)
		assert.Equal(t, "ReadError", ObjPutparseError(t, rr.Body.Bytes()).Code)
		backend.AssertNotCalled(t, "PutObject", mock.Anything, mock.Anything)
	})
}

// The streaming path cannot compute a ciphertext Content-Length without a
// declared plaintext length. handlePutObject routes such uploads to
// auto-multipart, so this is the safety net behind that decision.
func TestObjPutStreamingReaderWithoutLengthAnswers411(t *testing.T) {
	backend := new(MockS3Backend)
	h := ObjPutnewHandler(t, backend, ObjPutopts{})

	req := httptest.NewRequest(http.MethodPut, "/b/k", bytes.NewReader(ObjPutpayload(64)))
	req.ContentLength = -1

	rr := httptest.NewRecorder()
	h.putObjectStreamingReader(rr, req, "b", "k", nil, "application/octet-stream")

	assert.Equal(t, http.StatusLengthRequired, rr.Code)
	assert.Equal(t, "MissingContentLength", ObjPutparseError(t, rr.Body.Bytes()).Code)
	backend.AssertNotCalled(t, "PutObject", mock.Anything, mock.Anything)
}

// An unknown Content-Length is what a chunked client sends; it must not be
// refused, it must go to auto-multipart.
func TestObjPutUnknownContentLengthUsesAutoMultipart(t *testing.T) {
	backend := new(MockS3Backend)
	h := ObjPutnewHandler(t, backend, ObjPutopts{})

	backend.On("CreateMultipartUpload", mock.Anything, mock.Anything).
		Return(&s3.CreateMultipartUploadOutput{UploadId: aws.String("u1")}, nil)
	backend.On("UploadPart", mock.Anything, mock.Anything).
		Return(&s3.UploadPartOutput{ETag: aws.String(`"p"`)}, nil)
	backend.On("CompleteMultipartUpload", mock.Anything, mock.Anything).
		Return(&s3.CompleteMultipartUploadOutput{ETag: aws.String(`"c"`)}, nil)
	backend.On("CopyObject", mock.Anything, mock.Anything).
		Return(&s3.CopyObjectOutput{CopyObjectResult: &types.CopyObjectResult{ETag: aws.String(`"cp"`)}}, nil)

	req := httptest.NewRequest(http.MethodPut, "/b/k", bytes.NewReader(ObjPutpayload(512)))
	req.ContentLength = -1

	rr := ObjPutdo(h, req, "b", "k")

	require.Equal(t, http.StatusOK, rr.Code)
	backend.AssertCalled(t, "CreateMultipartUpload", mock.Anything, mock.Anything)
	backend.AssertNotCalled(t, "PutObject", mock.Anything, mock.Anything)
}

// With integrity verification off a large object stays on the single-part
// streaming path: there is no HMAC to compute incrementally.
func TestObjPutHMACOffKeepsLargeObjectsSinglePart(t *testing.T) {
	backend := new(MockS3Backend)
	h := ObjPutnewHandler(t, backend, ObjPutopts{integrity: config.HMACVerificationOff, threshold: 1024 * 1024})
	stored := ObjPutcapturePut(backend, `"etag"`, "")

	payload := ObjPutpayload(5*1024*1024 + 7)
	rr := ObjPutdo(h, httptest.NewRequest(http.MethodPut, "/b/k", bytes.NewReader(payload)), "b", "k")

	require.Equal(t, http.StatusOK, rr.Code)
	backend.AssertNotCalled(t, "CreateMultipartUpload", mock.Anything, mock.Anything)
	require.NotNil(t, stored.input)
	assert.NotContains(t, stored.input.Metadata, "s3ep-hmac",
		"integrity_verification: off must not write an HMAC")
	assert.Equal(t, ObjPutdigest(payload),
		ObjPutdigest(ObjPutreadBack(t, h, "k", stored.body, stored.input.Metadata)))
}

// ---------------------------------------------------------------------------
// aws-chunked framing: the framing bytes must never become object content.
// ---------------------------------------------------------------------------

func ObjPutchunked(payload []byte, chunkSize int) []byte {
	var buf bytes.Buffer
	for off := 0; off < len(payload); off += chunkSize {
		end := off + chunkSize
		if end > len(payload) {
			end = len(payload)
		}
		fmt.Fprintf(&buf, "%x;chunk-signature=%064x\r\n", end-off, 0)
		buf.Write(payload[off:end])
		buf.WriteString("\r\n")
	}
	fmt.Fprintf(&buf, "0;chunk-signature=%064x\r\n\r\n", 0)
	return buf.Bytes()
}

func TestObjPutAWSChunkedFramingIsDecodedBeforeEncryption(t *testing.T) {
	const threshold = 1024 * 1024

	for name, size := range map[string]int{"direct_path": 900, "streaming_path": threshold + 5} {
		t.Run(name, func(t *testing.T) {
			backend := new(MockS3Backend)
			h := ObjPutnewHandler(t, backend, ObjPutopts{threshold: threshold, awsChunked: true})
			stored := ObjPutcapturePut(backend, `"etag"`, "")

			payload := ObjPutpayload(size)
			framed := ObjPutchunked(payload, 300)

			req := httptest.NewRequest(http.MethodPut, "/b/k", bytes.NewReader(framed))
			req.Header.Set("Content-Encoding", "aws-chunked")
			req.Header.Set("X-Amz-Decoded-Content-Length", fmt.Sprintf("%d", size))
			req.ContentLength = int64(len(framed))

			rr := ObjPutdo(h, req, "b", "k")

			require.Equal(t, http.StatusOK, rr.Code)
			require.NotNil(t, stored.input)
			assert.Equal(t, ObjPutdigest(payload),
				ObjPutdigest(ObjPutreadBack(t, h, "k", stored.body, stored.input.Metadata)),
				"the chunk framing was stored as if it were payload")
			assert.Nil(t, stored.input.ContentEncoding,
				"aws-chunked must not be stored on the object")
		})
	}
}

// ---------------------------------------------------------------------------
// Auto-multipart: the whole lifecycle, and the abort that must happen.
// ---------------------------------------------------------------------------

// ObjPutmultipart records everything the auto-multipart pipeline sends.
type ObjPutmultipart struct {
	mu             sync.Mutex
	create         *s3.CreateMultipartUploadInput
	parts          map[int][]byte
	complete       *s3.CompleteMultipartUploadInput
	copy           *s3.CopyObjectInput
	abort          *s3.AbortMultipartUploadInput
	abortCtxErr    error
	partContentLen map[int]int64
}

func ObjPutwireMultipart(backend *MockS3Backend, uploadID string) *ObjPutmultipart {
	m := &ObjPutmultipart{parts: map[int][]byte{}, partContentLen: map[int]int64{}}

	backend.On("CreateMultipartUpload", mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			m.mu.Lock()
			defer m.mu.Unlock()
			m.create = args.Get(1).(*s3.CreateMultipartUploadInput)
		}).
		Return(&s3.CreateMultipartUploadOutput{UploadId: aws.String(uploadID)}, nil).Maybe()

	backend.On("UploadPart", mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			in := args.Get(1).(*s3.UploadPartInput)
			body, _ := io.ReadAll(in.Body)
			m.mu.Lock()
			defer m.mu.Unlock()
			m.parts[int(aws.ToInt32(in.PartNumber))] = body
			m.partContentLen[int(aws.ToInt32(in.PartNumber))] = aws.ToInt64(in.ContentLength)
		}).
		Return(&s3.UploadPartOutput{ETag: aws.String(`"part-etag"`)}, nil).Maybe()

	backend.On("CompleteMultipartUpload", mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			m.mu.Lock()
			defer m.mu.Unlock()
			m.complete = args.Get(1).(*s3.CompleteMultipartUploadInput)
		}).
		Return(&s3.CompleteMultipartUploadOutput{
			ETag:      aws.String(`"complete-etag"`),
			VersionId: aws.String("complete-version"),
		}, nil).Maybe()

	backend.On("CopyObject", mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			m.mu.Lock()
			defer m.mu.Unlock()
			m.copy = args.Get(1).(*s3.CopyObjectInput)
		}).
		Return(&s3.CopyObjectOutput{
			CopyObjectResult: &types.CopyObjectResult{ETag: aws.String(`"copy-etag"`)},
			VersionId:        aws.String("copy-version"),
		}, nil).Maybe()

	backend.On("AbortMultipartUpload", mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			m.mu.Lock()
			defer m.mu.Unlock()
			m.abort = args.Get(1).(*s3.AbortMultipartUploadInput)
			m.abortCtxErr = args.Get(0).(context.Context).Err()
		}).
		Return(&s3.AbortMultipartUploadOutput{}, nil).Maybe()

	return m
}

// ObjPutjoinParts concatenates the uploaded parts in PartNumber order.
func (m *ObjPutmultipart) ObjPutjoinParts() []byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	nums := make([]int, 0, len(m.parts))
	for n := range m.parts {
		nums = append(nums, n)
	}
	sort.Ints(nums)
	var out []byte
	for _, n := range nums {
		out = append(out, m.parts[n]...)
	}
	return out
}

// The full lifecycle: create, N parts, complete, and the self-copy that carries
// the encryption metadata. What the parts hold has to decrypt back to what the
// client sent.
func TestObjPutAutoMultipartRoundTripsThroughEveryStage(t *testing.T) {
	backend := new(MockS3Backend)
	h := ObjPutnewHandler(t, backend, ObjPutopts{segmentSize: 1024, concurrency: 2})
	rec := ObjPutwireMultipart(backend, "auto-id")

	payload := ObjPutpayload(3*1024 + 17) // four parts at a 1 KiB segment size
	req := httptest.NewRequest(http.MethodPut, "/b/big-key", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/zip")
	req.ContentLength = -1

	rr := ObjPutdo(h, req, "b", "big-key")

	require.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, `"copy-etag"`, rr.Header().Get("ETag"),
		"the self-copy rewrote the object, so the Complete ETag is stale")
	assert.Equal(t, "copy-version", rr.Header().Get("x-amz-version-id"))

	require.NotNil(t, rec.create)
	assert.Equal(t, "b", aws.ToString(rec.create.Bucket))
	assert.Equal(t, "big-key", aws.ToString(rec.create.Key))

	rec.mu.Lock()
	partCount := len(rec.parts)
	for n, body := range rec.parts {
		assert.Equal(t, int64(len(body)), rec.partContentLen[n],
			"part %d declared a length that does not match its body", n)
	}
	rec.mu.Unlock()
	assert.Equal(t, 4, partCount)

	require.NotNil(t, rec.complete)
	require.NotNil(t, rec.complete.MultipartUpload)
	parts := rec.complete.MultipartUpload.Parts
	require.Len(t, parts, 4)
	for i := range parts {
		assert.Equal(t, int32(i+1), aws.ToInt32(parts[i].PartNumber),
			"CompleteMultipartUpload requires ascending part numbers")
		assert.Equal(t, "part-etag", aws.ToString(parts[i].ETag),
			"the quotes S3 puts around an ETag must be stripped")
	}

	ciphertext := rec.ObjPutjoinParts()
	assert.NotEqual(t, ObjPutdigest(payload), ObjPutdigest(ciphertext),
		"the parts were handed to the backend as plaintext")

	require.NotNil(t, rec.copy)
	assert.Equal(t, types.MetadataDirectiveReplace, rec.copy.MetadataDirective)
	assert.Equal(t, "b/big-key", aws.ToString(rec.copy.CopySource))
	assert.Contains(t, rec.copy.Metadata, "s3ep-hmac",
		"strict integrity verification must store an HMAC")
	for _, k := range ObjPutencryptionMetadata(rec.copy.Metadata, "s3ep-") {
		assert.Truef(t, ObjPutallowedMetadata[strings.TrimPrefix(k, "s3ep-")],
			"undocumented encryption metadata key %q", k)
	}

	assert.Equal(t, ObjPutdigest(payload),
		ObjPutdigest(ObjPutreadBack(t, h, "big-key", ciphertext, rec.copy.Metadata)))

	rec.mu.Lock()
	defer rec.mu.Unlock()
	assert.Nil(t, rec.abort, "a successful upload must not abort")
}

// A leaked multipart upload costs the operator money for as long as the bucket
// lives, so every failure after Create has to abort.
func TestObjPutAutoMultipartAbortsOnEveryFailureAfterCreate(t *testing.T) {
	partErr := &smithy.GenericAPIError{Code: "AccessDenied", Message: "Access Denied"}

	cases := map[string]struct {
		wire       func(backend *MockS3Backend, rec *ObjPutmultipart)
		wantStatus int
		wantCode   string
	}{
		"upload_part_fails": {
			wire: func(backend *MockS3Backend, _ *ObjPutmultipart) {
				backend.ExpectedCalls = ObjPutdropCall(backend, "UploadPart")
				backend.On("UploadPart", mock.Anything, mock.Anything).Return(nil, partErr)
			},
			wantStatus: http.StatusForbidden,
			wantCode:   "AccessDenied",
		},
		"complete_fails": {
			wire: func(backend *MockS3Backend, _ *ObjPutmultipart) {
				backend.ExpectedCalls = ObjPutdropCall(backend, "CompleteMultipartUpload")
				backend.On("CompleteMultipartUpload", mock.Anything, mock.Anything).
					Return(nil, &types.NoSuchUpload{})
			},
			wantStatus: http.StatusNotFound,
			wantCode:   "NoSuchUpload",
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			backend := new(MockS3Backend)
			h := ObjPutnewHandler(t, backend, ObjPutopts{})
			rec := ObjPutwireMultipart(backend, "auto-id")
			tc.wire(backend, rec)

			req := httptest.NewRequest(http.MethodPut, "/b/k", bytes.NewReader(ObjPutpayload(2048)))
			req.ContentLength = -1

			rr := ObjPutdo(h, req, "b", "k")

			assert.Equal(t, tc.wantStatus, rr.Code)
			assert.Equal(t, tc.wantCode, ObjPutparseError(t, rr.Body.Bytes()).Code)
			assert.Empty(t, rr.Header().Get("ETag"))

			rec.mu.Lock()
			defer rec.mu.Unlock()
			require.NotNil(t, rec.abort, "a failed upload must not leak the multipart")
			assert.Equal(t, "auto-id", aws.ToString(rec.abort.UploadId))
			assert.Equal(t, "b", aws.ToString(rec.abort.Bucket))
			assert.Equal(t, "k", aws.ToString(rec.abort.Key))
			assert.NoError(t, rec.abortCtxErr)
		})
	}
}

// ObjPutdropCall removes a previously registered expectation so a test can
// replace one leg of the wired-up happy path.
func ObjPutdropCall(backend *MockS3Backend, method string) []*mock.Call {
	kept := backend.ExpectedCalls[:0]
	for _, c := range backend.ExpectedCalls {
		if c.Method != method {
			kept = append(kept, c)
		}
	}
	return kept
}

// CreateMultipartUpload failing is the one failure with nothing to abort.
func TestObjPutAutoMultipartCreateFailureDoesNotAbort(t *testing.T) {
	backend := new(MockS3Backend)
	h := ObjPutnewHandler(t, backend, ObjPutopts{})
	backend.On("CreateMultipartUpload", mock.Anything, mock.Anything).
		Return(nil, &types.NoSuchBucket{})

	req := httptest.NewRequest(http.MethodPut, "/b/k", bytes.NewReader(ObjPutpayload(512)))
	req.ContentLength = -1

	rr := ObjPutdo(h, req, "b", "k")

	assert.Equal(t, http.StatusNotFound, rr.Code)
	assert.Equal(t, "NoSuchBucket", ObjPutparseError(t, rr.Body.Bytes()).Code)
	backend.AssertNotCalled(t, "AbortMultipartUpload", mock.Anything, mock.Anything)
}

// The self-copy is what makes the object decryptable. If it fails the client
// must be told the upload failed, even though the bytes are committed.
func TestObjPutAutoMultipartSelfCopyFailureIsReportedAsAnError(t *testing.T) {
	backend := new(MockS3Backend)
	h := ObjPutnewHandler(t, backend, ObjPutopts{})
	rec := ObjPutwireMultipart(backend, "auto-id")
	backend.ExpectedCalls = ObjPutdropCall(backend, "CopyObject")
	backend.On("CopyObject", mock.Anything, mock.Anything).
		Return(nil, errors.New("backend refused the copy"))

	req := httptest.NewRequest(http.MethodPut, "/b/k", bytes.NewReader(ObjPutpayload(2048)))
	req.ContentLength = -1

	rr := ObjPutdo(h, req, "b", "k")

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
	assert.Equal(t, "InternalError", ObjPutparseError(t, rr.Body.Bytes()).Code)
	assert.Empty(t, rr.Header().Get("ETag"))
	rec.mu.Lock()
	defer rec.mu.Unlock()
	assert.NotNil(t, rec.complete, "the object is committed before the copy is attempted")
}

// The none provider produces no encryption metadata, so there is nothing to
// attach and the self-copy is skipped: the ETag the client sees is Complete's.
func TestObjPutAutoMultipartNoneProviderSkipsTheSelfCopy(t *testing.T) {
	backend := new(MockS3Backend)
	h := ObjPutnewHandler(t, backend, ObjPutopts{providerType: "none", segmentSize: 1024})
	rec := ObjPutwireMultipart(backend, "auto-id")

	payload := ObjPutpayload(2500)
	req := httptest.NewRequest(http.MethodPut, "/b/k", bytes.NewReader(payload))
	req.ContentLength = -1

	rr := ObjPutdo(h, req, "b", "k")

	require.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, `"complete-etag"`, rr.Header().Get("ETag"))
	assert.Equal(t, "complete-version", rr.Header().Get("x-amz-version-id"))
	backend.AssertNotCalled(t, "CopyObject", mock.Anything, mock.Anything)

	// Pass-through: the parts hold the plaintext, in order.
	assert.Equal(t, ObjPutdigest(payload), ObjPutdigest(rec.ObjPutjoinParts()))
}

// A body that errors mid-read must abort rather than commit what arrived.
func TestObjPutAutoMultipartBodyErrorAborts(t *testing.T) {
	backend := new(MockS3Backend)
	h := ObjPutnewHandler(t, backend, ObjPutopts{segmentSize: 1024})
	rec := ObjPutwireMultipart(backend, "auto-id")

	req := httptest.NewRequest(http.MethodPut, "/b/k", &ObjPuterrReader{
		prefix: ObjPutpayload(3000),
		err:    errors.New("connection reset by peer"),
	})
	req.ContentLength = -1

	rr := ObjPutdo(h, req, "b", "k")

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
	assert.Equal(t, "UploadError", ObjPutparseError(t, rr.Body.Bytes()).Code)
	backend.AssertNotCalled(t, "CompleteMultipartUpload", mock.Anything, mock.Anything)
	rec.mu.Lock()
	defer rec.mu.Unlock()
	assert.NotNil(t, rec.abort)
}

// An aws-chunked body declares its framed size in Content-Length, which is
// larger than the plaintext. The truncation guard must not fire on it.
func TestObjPutAutoMultipartAcceptsAWSChunkedWithoutDecodedLength(t *testing.T) {
	backend := new(MockS3Backend)
	h := ObjPutnewHandler(t, backend, ObjPutopts{segmentSize: 1024, awsChunked: true})
	rec := ObjPutwireMultipart(backend, "auto-id")

	payload := ObjPutpayload(2400)
	framed := ObjPutchunked(payload, 512)

	req := httptest.NewRequest(http.MethodPut, "/b/k", bytes.NewReader(framed))
	req.Header.Set("Content-Encoding", "aws-chunked")
	req.Header.Set("X-Amz-Content-Sha256", "STREAMING-AWS4-HMAC-SHA256-PAYLOAD")
	req.ContentLength = -1

	rr := ObjPutdo(h, req, "b", "k")

	require.Equal(t, http.StatusOK, rr.Code)
	require.NotNil(t, rec.copy)
	assert.Equal(t, ObjPutdigest(payload),
		ObjPutdigest(ObjPutreadBack(t, h, "k", rec.ObjPutjoinParts(), rec.copy.Metadata)),
		"the chunk framing was uploaded as if it were payload")
	rec.mu.Lock()
	defer rec.mu.Unlock()
	assert.Nil(t, rec.abort)
}

// ---------------------------------------------------------------------------
// Configuration accessors used by the PUT paths.
// ---------------------------------------------------------------------------

func TestObjPutSegmentSizeAndConcurrencyDefaults(t *testing.T) {
	cases := map[string]struct {
		cfg             *config.Config
		wantSegment     int64
		wantConcurrency int
	}{
		"nil config":  {nil, 12 * 1024 * 1024, 4},
		"zero values": {&config.Config{}, 12 * 1024 * 1024, 4},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			h := &Handler{config: tc.cfg}
			assert.Equal(t, tc.wantSegment, h.getSegmentSize())
			assert.Equal(t, tc.wantConcurrency, h.getMultipartUploadConcurrency())
		})
	}

	t.Run("configured values win", func(t *testing.T) {
		cfg := &config.Config{}
		cfg.Optimizations.StreamingSegmentSize = 7 * 1024 * 1024
		cfg.Optimizations.MultipartUploadConcurrency = 9
		h := &Handler{config: cfg}
		assert.Equal(t, int64(7*1024*1024), h.getSegmentSize())
		assert.Equal(t, 9, h.getMultipartUploadConcurrency())
	})

	t.Run("negative values fall back", func(t *testing.T) {
		cfg := &config.Config{}
		cfg.Optimizations.StreamingSegmentSize = -1
		cfg.Optimizations.MultipartUploadConcurrency = -1
		h := &Handler{config: cfg}
		assert.Equal(t, int64(12*1024*1024), h.getSegmentSize())
		assert.Equal(t, 4, h.getMultipartUploadConcurrency())
	})
}

// Every PUT path lowers a user metadata key, the way S3 lowers it in transit.
// The single-part paths used to keep the case net/http canonicalised the header
// to ("Project"), and that is what made the encryption-metadata guard in
// prepareEncryptionMetadata ineffective: it compared "S3ep-" against the
// lowercase configured prefix and never matched.
func TestObjPutUserMetadataKeyIsLoweredOnEveryPath(t *testing.T) {
	const threshold = 2048

	t.Run("direct path lowercases", func(t *testing.T) {
		backend := new(MockS3Backend)
		h := ObjPutnewHandler(t, backend, ObjPutopts{threshold: threshold})
		stored := ObjPutcapturePut(backend, `"e"`, "")

		req := httptest.NewRequest(http.MethodPut, "/b/k", bytes.NewReader(ObjPutpayload(64)))
		req.Header.Set("x-amz-meta-project", "orion")
		require.Equal(t, http.StatusOK, ObjPutdo(h, req, "b", "k").Code)

		require.NotNil(t, stored.input)
		assert.Equal(t, "orion", stored.input.Metadata["project"])
	})

	t.Run("none provider streaming lowercases", func(t *testing.T) {
		backend := new(MockS3Backend)
		h := ObjPutnewHandler(t, backend, ObjPutopts{providerType: "none", threshold: threshold})
		stored := ObjPutcapturePut(backend, `"e"`, "")

		req := httptest.NewRequest(http.MethodPut, "/b/k", bytes.NewReader(ObjPutpayload(threshold+1)))
		req.Header.Set("x-amz-meta-project", "orion")
		require.Equal(t, http.StatusOK, ObjPutdo(h, req, "b", "k").Code)

		require.NotNil(t, stored.input)
		assert.Equal(t, "orion", stored.input.Metadata["project"])
	})

	t.Run("auto-multipart lowercases", func(t *testing.T) {
		backend := new(MockS3Backend)
		h := ObjPutnewHandler(t, backend, ObjPutopts{})
		rec := ObjPutwireMultipart(backend, "auto-id")

		req := httptest.NewRequest(http.MethodPut, "/b/k", bytes.NewReader(ObjPutpayload(1500)))
		req.Header.Set("x-amz-meta-project", "orion")
		req.ContentLength = -1
		require.Equal(t, http.StatusOK, ObjPutdo(h, req, "b", "k").Code)

		require.NotNil(t, rec.create)
		assert.Equal(t, "orion", rec.create.Metadata["project"])
	})
}

// The streaming single-part path reports an encryption failure as an S3 error
// and stores nothing. A body that dies mid-read is what triggers it: the
// HMAC-enabled CTR encoder has to see the whole plaintext before it can emit
// ciphertext.
func TestObjPutStreamingEncryptionFailureStoresNothing(t *testing.T) {
	backend := new(MockS3Backend)
	h := ObjPutnewHandler(t, backend, ObjPutopts{})

	req := httptest.NewRequest(http.MethodPut, "/b/k", &ObjPuterrReader{
		prefix: ObjPutpayload(2000),
		err:    errors.New("connection reset by peer"),
	})
	req.Header.Set("Content-Type", "application/x-s3ep-force-aes-ctr")
	req.ContentLength = 8192

	rr := ObjPutdo(h, req, "b", "k")

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
	assert.Equal(t, "InternalError", ObjPutparseError(t, rr.Body.Bytes()).Code)
	assert.NotContains(t, rr.Body.String(), "connection reset",
		"internal error detail must stay in the log")
	backend.AssertNotCalled(t, "PutObject", mock.Anything, mock.Anything)
}

// Both halves of the cleanup can fail on their own. The request still has to
// answer the original failure rather than the cleanup's, and it must not
// pretend the upload succeeded.
func TestObjPutAutoMultipartReportsOriginalFailureWhenCleanupAlsoFails(t *testing.T) {
	backend := new(MockS3Backend)
	h := ObjPutnewHandler(t, backend, ObjPutopts{})
	rec := ObjPutwireMultipart(backend, "auto-id")

	backend.ExpectedCalls = ObjPutdropCall(backend, "CompleteMultipartUpload")
	backend.On("CompleteMultipartUpload", mock.Anything, mock.Anything).
		Return(nil, &smithy.GenericAPIError{Code: "SlowDown", Message: "Please reduce your request rate"})
	backend.ExpectedCalls = ObjPutdropCall(backend, "AbortMultipartUpload")
	backend.On("AbortMultipartUpload", mock.Anything, mock.Anything).
		Return(nil, errors.New("abort refused"))

	req := httptest.NewRequest(http.MethodPut, "/b/k", bytes.NewReader(ObjPutpayload(2048)))
	req.ContentLength = -1

	rr := ObjPutdo(h, req, "b", "k")

	assert.Equal(t, http.StatusServiceUnavailable, rr.Code)
	assert.Equal(t, "SlowDown", ObjPutparseError(t, rr.Body.Bytes()).Code)
	assert.Empty(t, rr.Header().Get("ETag"))
	backend.AssertNotCalled(t, "CopyObject", mock.Anything, mock.Anything)
	rec.mu.Lock()
	defer rec.mu.Unlock()
	assert.Nil(t, rec.copy)
}

// S3 allows at most 10000 parts. Past that the upload has to fail and clean up
// rather than send a part number the backend will reject.
// The segment size is set to one byte so the guard is reachable without a
// 120 GB body; the production minimum is 5 MiB.
func TestObjPutAutoMultipartRefusesMoreThan10000Parts(t *testing.T) {
	backend := new(MockS3Backend)
	h := ObjPutnewHandler(t, backend, ObjPutopts{segmentSize: 1})
	rec := ObjPutwireMultipart(backend, "auto-id")

	req := httptest.NewRequest(http.MethodPut, "/b/k", bytes.NewReader(ObjPutpayload(10001)))
	req.ContentLength = -1

	rr := ObjPutdo(h, req, "b", "k")

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
	doc := ObjPutparseError(t, rr.Body.Bytes())
	assert.Equal(t, "UploadError", doc.Code)
	assert.Contains(t, doc.Message, "10000")
	backend.AssertNotCalled(t, "CompleteMultipartUpload", mock.Anything, mock.Anything)
	rec.mu.Lock()
	defer rec.mu.Unlock()
	assert.NotNil(t, rec.abort, "the parts already uploaded must not be left behind")
}

// A backend that rejects every part must stop the producer instead of reading
// and encrypting the whole body first.
func TestObjPutAutoMultipartStopsFeedingAfterAPartFails(t *testing.T) {
	backend := new(MockS3Backend)
	h := ObjPutnewHandler(t, backend, ObjPutopts{segmentSize: 1024, concurrency: 2})
	rec := ObjPutwireMultipart(backend, "auto-id")
	backend.ExpectedCalls = ObjPutdropCall(backend, "UploadPart")

	var attempted int64
	var mu sync.Mutex
	backend.On("UploadPart", mock.Anything, mock.Anything).
		Run(func(mock.Arguments) {
			mu.Lock()
			attempted++
			mu.Unlock()
		}).
		Return(nil, &smithy.GenericAPIError{Code: "AccessDenied", Message: "Access Denied"})

	// 200 parts at a 1 KiB segment size; a pipeline that ignored the failure
	// would upload all of them.
	req := httptest.NewRequest(http.MethodPut, "/b/k", bytes.NewReader(ObjPutpayload(200*1024)))
	req.ContentLength = -1

	rr := ObjPutdo(h, req, "b", "k")

	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.Equal(t, "AccessDenied", ObjPutparseError(t, rr.Body.Bytes()).Code)
	mu.Lock()
	defer mu.Unlock()
	assert.Less(t, attempted, int64(200), "the producer kept feeding a failed pipeline")
	rec.mu.Lock()
	defer rec.mu.Unlock()
	assert.NotNil(t, rec.abort)
}

// The none provider has no encryption session to abort, so the cleanup's second
// half fails. That must not stop the S3 multipart from being aborted, and the
// client must still see the backend's error.
func TestObjPutAutoMultipartNoneProviderStillAbortsTheS3Upload(t *testing.T) {
	backend := new(MockS3Backend)
	h := ObjPutnewHandler(t, backend, ObjPutopts{providerType: "none", segmentSize: 1024})
	rec := ObjPutwireMultipart(backend, "auto-id")
	backend.ExpectedCalls = ObjPutdropCall(backend, "UploadPart")
	backend.On("UploadPart", mock.Anything, mock.Anything).
		Return(nil, &smithy.GenericAPIError{Code: "AccessDenied", Message: "Access Denied"})

	req := httptest.NewRequest(http.MethodPut, "/b/k", bytes.NewReader(ObjPutpayload(2048)))
	req.ContentLength = -1

	rr := ObjPutdo(h, req, "b", "k")

	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.Equal(t, "AccessDenied", ObjPutparseError(t, rr.Body.Bytes()).Code)
	rec.mu.Lock()
	defer rec.mu.Unlock()
	require.NotNil(t, rec.abort)
	assert.Equal(t, "auto-id", aws.ToString(rec.abort.UploadId))
}

// DEFECT (minor, reported): when the metadata self-copy fails the handler
// returns without calling CleanupMultipartUpload, so the encryption session -
// DEK, IV and HMAC calculator - stays in the manager until the background
// sweeper expires it. A second upload that lands on the same upload id then
// cannot initialise its session and is refused. The second half of this test
// is what makes the leak observable from outside.
func TestObjPutAutoMultipartSelfCopyFailureLeaksTheEncryptionSession(t *testing.T) {
	backend := new(MockS3Backend)
	h := ObjPutnewHandler(t, backend, ObjPutopts{})
	ObjPutwireMultipart(backend, "reused-id")
	backend.ExpectedCalls = ObjPutdropCall(backend, "CopyObject")
	backend.On("CopyObject", mock.Anything, mock.Anything).
		Return(nil, errors.New("backend refused the copy"))

	first := httptest.NewRequest(http.MethodPut, "/b/k", bytes.NewReader(ObjPutpayload(2048)))
	first.ContentLength = -1
	require.Equal(t, http.StatusInternalServerError, ObjPutdo(h, first, "b", "k").Code)

	// Same upload id again: the leaked session makes the encryption init fail.
	second := httptest.NewRequest(http.MethodPut, "/b/k", bytes.NewReader(ObjPutpayload(2048)))
	second.ContentLength = -1
	rr := ObjPutdo(h, second, "b", "k")

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
	assert.Equal(t, "EncryptionError", ObjPutparseError(t, rr.Body.Bytes()).Code)
	backend.AssertCalled(t, "AbortMultipartUpload", mock.Anything, mock.Anything)
}

// DEFECT (minor, reported): the single-part streaming path computes the
// ciphertext Content-Length from the declared plaintext length and then streams
// whatever the body yields. A client that declares more than it sends makes the
// proxy announce a length it does not deliver; nothing in the proxy notices.
// The auto-multipart path has an explicit guard for exactly this case
// (operations.go, "client sent %d bytes but declared %d") - the single-part
// path does not.
func TestObjPutStreamingShortBodyDeclaresMoreThanItSends(t *testing.T) {
	backend := new(MockS3Backend)
	h := ObjPutnewHandler(t, backend, ObjPutopts{threshold: 2048, integrity: config.HMACVerificationOff})
	stored := ObjPutcapturePut(backend, `"etag"`, "")

	body := ObjPutpayload(1000)
	req := httptest.NewRequest(http.MethodPut, "/b/k", bytes.NewReader(body))
	req.ContentLength = 4096 // four times what the body holds

	rr := ObjPutdo(h, req, "b", "k")

	require.Equal(t, http.StatusOK, rr.Code)
	require.NotNil(t, stored.input)
	assert.Equal(t, int64(4096), aws.ToInt64(stored.input.ContentLength))
	assert.Len(t, stored.body, 1000,
		"the proxy declared 4096 bytes of ciphertext and streamed 1000")
}

// DEFECT (minor, reported): a PUT without a Content-Type stores an empty one
// instead of leaving it unset. Real S3 defaults a missing Content-Type to
// binary/octet-stream; here the header is forwarded as an empty string on both
// single-part paths because the value is wrapped unconditionally.
func TestObjPutMissingContentTypeIsForwardedAsEmpty(t *testing.T) {
	const threshold = 2048
	for name, size := range map[string]int{"direct_path": 64, "streaming_path": threshold} {
		t.Run(name, func(t *testing.T) {
			backend := new(MockS3Backend)
			h := ObjPutnewHandler(t, backend, ObjPutopts{threshold: threshold})
			stored := ObjPutcapturePut(backend, `"etag"`, "")

			req := httptest.NewRequest(http.MethodPut, "/b/k", bytes.NewReader(ObjPutpayload(size)))
			req.Header.Del("Content-Type")
			require.Equal(t, http.StatusOK, ObjPutdo(h, req, "b", "k").Code)

			require.NotNil(t, stored.input)
			require.NotNil(t, stored.input.ContentType,
				"an unset Content-Type is forwarded as an empty header, not omitted")
			assert.Equal(t, "", aws.ToString(stored.input.ContentType))
		})
	}
}

// DEFECT (major, reported): a conditional PUT is answered unconditionally.
// S3 supports "If-None-Match: *" on PutObject to make a write fail with 412
// PreconditionFailed when the key already exists, which is how clients
// implement optimistic concurrency. The GET path forwards both conditional
// headers (operations.go, handleGetObject); the PUT path reads neither, so
// both writers of a race believe they won and one write is lost silently.
func TestObjPutConditionalHeadersAreSilentlyIgnored(t *testing.T) {
	const threshold = 2048

	for name, size := range map[string]int{"direct_path": 64, "streaming_path": threshold} {
		t.Run(name, func(t *testing.T) {
			backend := new(MockS3Backend)
			h := ObjPutnewHandler(t, backend, ObjPutopts{threshold: threshold})
			stored := ObjPutcapturePut(backend, `"etag"`, "")

			req := httptest.NewRequest(http.MethodPut, "/b/k", bytes.NewReader(ObjPutpayload(size)))
			req.Header.Set("If-None-Match", "*")
			req.Header.Set("If-Match", `"some-etag"`)

			rr := ObjPutdo(h, req, "b", "k")

			assert.Equal(t, http.StatusOK, rr.Code,
				"a conditional write is accepted as an unconditional one")
			require.NotNil(t, stored.input)
			assert.Nil(t, stored.input.IfNoneMatch, "the condition never reaches the backend")
			assert.Nil(t, stored.input.IfMatch)
		})
	}
}

// DEFECT (major, reported; the fix is the checksum verification of ADR 0012):
// a client checksum on PUT is accepted and dropped. AWS verifies Content-MD5
// and x-amz-checksum-* against the uploaded bytes and answers 400 BadDigest on
// a mismatch; here the upload is never checked against what the client said it
// was sending, and the client is told 200. The proxy cannot forward the values
// as they are - they describe the plaintext while the body is ciphertext - but
// it can verify them itself.
func TestObjPutClientChecksumsAreAcceptedAndDropped(t *testing.T) {
	const threshold = 2048

	for name, size := range map[string]int{"direct_path": 64, "streaming_path": threshold} {
		t.Run(name, func(t *testing.T) {
			backend := new(MockS3Backend)
			h := ObjPutnewHandler(t, backend, ObjPutopts{threshold: threshold})
			stored := ObjPutcapturePut(backend, `"etag"`, "")

			req := httptest.NewRequest(http.MethodPut, "/b/k", bytes.NewReader(ObjPutpayload(size)))
			// A digest of something else entirely.
			req.Header.Set("Content-MD5", "1B2M2Y8AsgTpgAmY7PhCfg==")
			req.Header.Set("x-amz-sdk-checksum-algorithm", "CRC32")
			req.Header.Set("x-amz-checksum-crc32", "AAAAAA==")
			req.Header.Set("x-amz-expected-bucket-owner", "123456789012")

			rr := ObjPutdo(h, req, "b", "k")

			assert.Equal(t, http.StatusOK, rr.Code,
				"a wrong client digest is not detected")
			require.NotNil(t, stored.input)
			assert.Nil(t, stored.input.ContentMD5)
			assert.Empty(t, stored.input.ChecksumAlgorithm)
			assert.Nil(t, stored.input.ChecksumCRC32)
			assert.Nil(t, stored.input.ExpectedBucketOwner,
				"the bucket-owner guard the client asked for is dropped too")
		})
	}
}
