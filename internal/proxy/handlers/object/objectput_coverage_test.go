package object

import (
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
	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption/dataencryption"
)

// ---------------------------------------------------------------------------
// PUT: the client contract.
//
// Everything here drives a real HTTP request through the handler and then looks
// at two things only: what the client got back, and what the backend was asked
// to store. The bytes handed to the backend are checked by opening them again
// with the object's own metadata and comparing sha256 against what the client
// sent, so the assertions survive a change of storage format: whatever the
// pipeline does in between, a PUT has to store something that is not the
// plaintext and that reads back as the plaintext.
// ---------------------------------------------------------------------------

const ObjPutaesKey = "ZEsubBlmU+Pr61y+JOwO09c0LOrHs5LITaO0D4JzSZE="

// ObjPutopts describes the handler configuration a test needs. The zero value
// is an AES provider, the default metadata prefix, one segment of plaintext per
// producer part and a single upload worker.
type ObjPutopts struct {
	providerType string // "aes" (default) or "exit"
	prefix       string // default: "s3ep-"
	segmentSize  int64  // plaintext per part; also the single-request/producer boundary
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
	if o.prefix == "" {
		o.prefix = "s3ep-"
	}
	// A part that does not end the object has to cover whole segments, so the
	// default is the smallest part size the codec accepts: exactly one segment.
	if o.segmentSize == 0 {
		o.segmentSize = dataencryption.SegmentSize
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
			Providers:             []config.EncryptionProvider{provider},
		},
	}
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

// ObjPutstoredLen is what a plaintext of n bytes occupies once sealed: framing
// per segment plus the trailer that closes the object.
func ObjPutstoredLen(t *testing.T, n int) int64 {
	t.Helper()
	size, err := dataencryption.CiphertextSize(int64(n))
	require.NoError(t, err)
	return size
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
// mock because the production code seals it lazily, as the backend pulls.
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

// ObjPutreadBack opens what the backend was handed, using the metadata the
// backend was handed, and returns the plaintext a later GET would produce. The
// reader authenticates every segment and the trailer, so anything it returns
// without an error is what the object really holds.
func ObjPutreadBack(t *testing.T, h *Handler, key string, ciphertext []byte, metadata map[string]string) []byte {
	t.Helper()
	reader, err := h.encryptionMgr.OpenSegmented(key, metadata, bytes.NewReader(ciphertext))
	require.NoError(t, err)
	defer reader.Close()
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

// ObjPutlookupMeta reads object metadata case-insensitively.
func ObjPutlookupMeta(metadata map[string]string, key string) (string, bool) {
	for k, v := range metadata {
		if strings.EqualFold(k, key) {
			return v, true
		}
	}
	return "", false
}

// ObjPutmetadataKeys is the whole encryption metadata set of the segmented
// format: four keys and no more. There is no per-object IV, because every
// segment carries its own nonce, and no separate integrity value, because
// integrity is not separable from decryption.
func ObjPutmetadataKeys(prefix string) []string {
	return []string{
		prefix + "dek-algorithm",
		prefix + "encrypted-dek",
		prefix + "kek-algorithm",
		prefix + "kek-fingerprint",
	}
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

// ObjPutbulkReader yields n bytes without a test ever holding them, so the
// producer can be driven past a part count no in-memory payload would reach.
type ObjPutbulkReader struct{ left int }

func (r *ObjPutbulkReader) Read(p []byte) (int, error) {
	if r.left <= 0 {
		return 0, io.EOF
	}
	if len(p) > r.left {
		p = p[:r.left]
	}
	for i := range p {
		p[i] = byte(i)
	}
	r.left -= len(p)
	return len(p), nil
}

// ---------------------------------------------------------------------------
// A small PUT: a sealed chain at the backend, an exact metadata set, 200 + ETag.
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
	assert.Equal(t, ObjPutstoredLen(t, len(payload)), aws.ToInt64(stored.input.ContentLength))

	assert.Equal(t, ObjPutmetadataKeys("s3ep-"),
		ObjPutencryptionMetadata(stored.input.Metadata, "s3ep-"),
		"the format carries exactly these four keys: fewer cannot be read, more is not written")
	assert.Equal(t, dataencryption.FormatID, stored.input.Metadata["s3ep-dek-algorithm"])
}

// The metadata prefix is configurable; nothing may be written under the default
// prefix once it is changed, or the object becomes unreadable.
func TestObjPutCustomMetadataPrefixIsUsedEverywhere(t *testing.T) {
	backend := new(MockS3Backend)
	h := ObjPutnewHandler(t, backend, ObjPutopts{prefix: "enc-"})

	payload := ObjPutpayload(300)
	stored := ObjPutcapturePut(backend, `"e"`, "")

	rr := ObjPutdo(h, httptest.NewRequest(http.MethodPut, "/b/k", bytes.NewReader(payload)), "b", "k")
	require.Equal(t, http.StatusOK, rr.Code)

	require.NotNil(t, stored.input)
	assert.Empty(t, ObjPutencryptionMetadata(stored.input.Metadata, "s3ep-"))
	assert.Equal(t, ObjPutmetadataKeys("enc-"), ObjPutencryptionMetadata(stored.input.Metadata, "enc-"))
	assert.Equal(t, ObjPutdigest(payload),
		ObjPutdigest(ObjPutreadBack(t, h, "k", stored.body, stored.input.Metadata)))
}

// Under the exit provider a write stores the bytes as the client sent them and
// writes no proxy metadata at all: no data key is created, so there is nothing
// to record.
func TestObjPutExitProviderPassesPlaintextThrough(t *testing.T) {
	for name, size := range map[string]int{
		"empty":       0,
		"small":       512,
		"one_segment": dataencryption.SegmentSize,
	} {
		t.Run(name, func(t *testing.T) {
			backend := new(MockS3Backend)
			h := ObjPutnewHandler(t, backend, ObjPutopts{providerType: "exit"})

			payload := ObjPutpayload(size)
			stored := ObjPutcapturePut(backend, `"n"`, "")

			req := httptest.NewRequest(http.MethodPut, "/b/k", bytes.NewReader(payload))
			req.Header.Set("x-amz-meta-owner", "hans")
			rr := ObjPutdo(h, req, "b", "k")

			require.Equal(t, http.StatusOK, rr.Code)
			require.NotNil(t, stored.input)
			assert.Equal(t, ObjPutdigest(payload), ObjPutdigest(stored.body),
				"the exit provider must store the bytes unchanged")
			assert.Equal(t, int64(len(payload)), aws.ToInt64(stored.input.ContentLength))
			assert.Empty(t, ObjPutencryptionMetadata(stored.input.Metadata, "s3ep-"))
			owner, ok := ObjPutlookupMeta(stored.input.Metadata, "owner")
			require.True(t, ok, "user metadata must survive the pass-through")
			assert.Equal(t, "hans", owner)
		})
	}
}

// All three write paths pass through, so the producer does too: an object one
// byte larger than a part is still stored as the client sent it. It used to be
// sealed here while the read path served it verbatim, which handed the client
// the stored chain instead of its file.
func TestObjPutExitProviderPassesThroughTheProducerToo(t *testing.T) {
	backend := new(MockS3Backend)
	h := ObjPutnewHandler(t, backend, ObjPutopts{providerType: "exit"})
	rec := ObjPutwireMultipart(backend, "auto-id")

	payload := ObjPutpayload(dataencryption.SegmentSize + 1)
	req := httptest.NewRequest(http.MethodPut, "/b/k", bytes.NewReader(payload))
	req.Header.Set("x-amz-meta-owner", "hans")
	rr := ObjPutdo(h, req, "b", "k")

	require.Equal(t, http.StatusOK, rr.Code)
	require.NotNil(t, rec.create)
	assert.Empty(t, ObjPutencryptionMetadata(rec.create.Metadata, "s3ep-"),
		"the exit provider must announce no encryption metadata")
	assert.Equal(t, "hans", rec.create.Metadata["owner"], "user metadata still travels")
	assert.Equal(t, ObjPutdigest(payload), ObjPutdigest(rec.ObjPutjoinParts()),
		"the producer must store the bytes unchanged")
}

// ---------------------------------------------------------------------------
// The one routing boundary that is left: what fits a single request, and what
// does not.
// ---------------------------------------------------------------------------

// Whatever branch a size takes, the object has to read back byte-identical and
// must not be stored as plaintext. This is the assertion that outlives the
// storage format.
func TestObjPutRoundTripAcrossThePartBoundary(t *testing.T) {
	sizes := map[string]int{
		"empty":          0,
		"one_byte":       1,
		"below_boundary": dataencryption.SegmentSize - 1,
		"at_boundary":    dataencryption.SegmentSize,
	}

	for name, size := range sizes {
		t.Run(name, func(t *testing.T) {
			backend := new(MockS3Backend)
			h := ObjPutnewHandler(t, backend, ObjPutopts{})

			payload := ObjPutpayload(size)
			stored := ObjPutcapturePut(backend, `"etag"`, "")

			rr := ObjPutdo(h, httptest.NewRequest(http.MethodPut, "/b/k", bytes.NewReader(payload)), "b", "k")

			require.Equal(t, http.StatusOK, rr.Code)
			require.NotNil(t, stored.input)
			require.NoError(t, stored.readErr)

			assert.NotEqual(t, ObjPutdigest(payload), ObjPutdigest(stored.body),
				"even an empty object is stored as a sealed trailer, never as nothing")
			assert.Equal(t, ObjPutdigest(payload),
				ObjPutdigest(ObjPutreadBack(t, h, "k", stored.body, stored.input.Metadata)))
			assert.Equal(t, int64(len(stored.body)), aws.ToInt64(stored.input.ContentLength),
				"a declared length that does not match the streamed body truncates the object")

			// Everything up to one part is one PutObject.
			backend.AssertNotCalled(t, "CreateMultipartUpload", mock.Anything, mock.Anything)
		})
	}
}

// One byte past what a single request carries is the whole difference between
// the two write paths, and both have to produce the same readable object.
func TestObjPutOneBytePastThePartBoundaryUsesTheProducer(t *testing.T) {
	backend := new(MockS3Backend)
	h := ObjPutnewHandler(t, backend, ObjPutopts{})
	rec := ObjPutwireMultipart(backend, "auto-id")

	payload := ObjPutpayload(dataencryption.SegmentSize + 1)
	rr := ObjPutdo(h, httptest.NewRequest(http.MethodPut, "/b/k", bytes.NewReader(payload)), "b", "k")

	require.Equal(t, http.StatusOK, rr.Code)
	backend.AssertNotCalled(t, "PutObject", mock.Anything, mock.Anything)
	require.NotNil(t, rec.create)
	assert.Equal(t, ObjPutdigest(payload),
		ObjPutdigest(ObjPutreadBack(t, h, "k", rec.ObjPutjoinParts(), rec.create.Metadata)))
}

// The stored length is a pure function of the plaintext length: one framing per
// segment plus the trailer. HEAD reports the plaintext size by inverting it, so
// a writer that stores a different number makes every later HEAD lie.
func TestObjPutStoredLengthIsThePlaintextPlusItsFraming(t *testing.T) {
	const overhead = dataencryption.SegmentOverhead
	const trailer = dataencryption.TrailerSize

	cases := map[string]struct {
		size int
		want int64
	}{
		"empty":                {0, trailer},
		"one_byte":             {1, 1 + overhead + trailer},
		"one_segment_less_one": {dataencryption.SegmentSize - 1, dataencryption.SegmentSize - 1 + overhead + trailer},
		"one_whole_segment":    {dataencryption.SegmentSize, dataencryption.SegmentSize + overhead + trailer},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			backend := new(MockS3Backend)
			h := ObjPutnewHandler(t, backend, ObjPutopts{})
			stored := ObjPutcapturePut(backend, `"etag"`, "")

			rr := ObjPutdo(h, httptest.NewRequest(http.MethodPut, "/b/k",
				bytes.NewReader(ObjPutpayload(tc.size))), "b", "k")

			require.Equal(t, http.StatusOK, rr.Code)
			require.NotNil(t, stored.input)
			assert.Equal(t, tc.want, aws.ToInt64(stored.input.ContentLength))
			assert.Equal(t, tc.want, int64(len(stored.body)))
			assert.Equal(t, dataencryption.FormatID, stored.input.Metadata["s3ep-dek-algorithm"])
		})
	}
}

// The content type that used to force the streaming cipher went with the second
// cipher. It must now be routed and stored like any other content type, not
// special-cased into a different path.
func TestObjPutForceCTRContentTypeIsNowAnOrdinaryContentType(t *testing.T) {
	for name, size := range map[string]int{"tiny": 16, "over_1kib": 4096} {
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
			assert.Equal(t, "application/x-s3ep-force-aes-ctr", aws.ToString(stored.input.ContentType))
			assert.Equal(t, dataencryption.FormatID, stored.input.Metadata["s3ep-dek-algorithm"])
			assert.Equal(t, ObjPutdigest(payload),
				ObjPutdigest(ObjPutreadBack(t, h, "k", stored.body, stored.input.Metadata)))
			backend.AssertNotCalled(t, "CreateMultipartUpload", mock.Anything, mock.Anything)
		})
	}
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
// reaches the backend on the single-request path. Every storage header a client
// can send is dropped and the request still answers 200 - the "silent 200" class
// ADR 0007 forbids.
func TestObjPutForwardsOnlyTheEntityHeadersOnTheSingleRequestPath(t *testing.T) {
	const size = 4096

	backend := new(MockS3Backend)
	h := ObjPutnewHandler(t, backend, ObjPutopts{})
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
}

// The same on the producer path: CreateMultipartUpload carries the four entity
// headers, the user metadata and the encryption metadata, and nothing else.
func TestObjPutAutoMultipartForwardsOnlyTheEntityHeaders(t *testing.T) {
	backend := new(MockS3Backend)
	h := ObjPutnewHandler(t, backend, ObjPutopts{})
	rec := ObjPutwireMultipart(backend, "u1")

	req := httptest.NewRequest(http.MethodPut, "/b/k", bytes.NewReader(ObjPutpayload(2048)))
	req.Header.Set("Content-Type", "application/pdf")
	ObjPutsetAllHeaders(req)
	req.ContentLength = -1 // unknown length routes to the producer at any size

	rr := ObjPutdo(h, req, "b", "k")

	require.Equal(t, http.StatusOK, rr.Code)
	require.NotNil(t, rec.create)
	createInput := rec.create
	assert.Equal(t, "max-age=42", aws.ToString(createInput.CacheControl))
	assert.Equal(t, `attachment; filename="report.pdf"`, aws.ToString(createInput.ContentDisposition))
	assert.Equal(t, "gzip", aws.ToString(createInput.ContentEncoding))
	assert.Equal(t, "en-GB", aws.ToString(createInput.ContentLanguage))
	assert.Equal(t, "application/pdf", aws.ToString(createInput.ContentType))
	assert.Equal(t, "orion", createInput.Metadata["project"])

	// The object is readable the moment Complete returns, so the metadata has to
	// be here rather than in a rewrite afterwards.
	assert.Equal(t, ObjPutmetadataKeys("s3ep-"),
		ObjPutencryptionMetadata(createInput.Metadata, "s3ep-"))

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

// Both write paths take their user metadata from here, so the namespace guard
// lives here too.
func TestObjPutUserMetadataFromRequest(t *testing.T) {
	h := &Handler{metadataPrefix: "s3ep-"}

	t.Run("only x-amz-meta headers are collected, lowered", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPut, "/b/k", nil)
		req.Header.Set("x-amz-meta-owner", "hans")
		req.Header.Set("X-Amz-Meta-Team", "platform")
		req.Header.Set("Content-Type", "text/plain")
		req.Header.Set("x-amz-storage-class", "GLACIER")

		out := h.userMetadataFromRequest(req)

		assert.Equal(t, map[string]string{"owner": "hans", "team": "platform"}, out)
	})

	t.Run("a header shorter than the prefix is not sliced", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPut, "/b/k", nil)
		req.Header.Set("X-Amz-Meta", "no-suffix")
		assert.Empty(t, h.userMetadataFromRequest(req))
	})

	t.Run("an encryption-prefixed key is filtered in either spelling", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPut, "/b/k", nil)
		// The raw map entry is the uncanonicalised spelling, Header.Set the
		// canonical one. Both are refused.
		req.Header["x-amz-meta-s3ep-kek-fingerprint"] = []string{"forged"}
		req.Header.Set("x-amz-meta-s3ep-encrypted-dek", "forged")
		assert.Empty(t, h.userMetadataFromRequest(req))
	})
}

// A client cannot write encryption metadata on the single-request path.
//
// The guard used to compare the metadata key byte for byte against the
// lowercase configured prefix, while net/http canonicalises every request
// header name: a header sent as x-amz-meta-s3ep-encrypted-dek arrived as
// X-Amz-Meta-S3ep-Encrypted-Dek, the key was "S3ep-Encrypted-Dek", and the
// guard never fired. Both keys then reached the backend, S3 lowered one onto
// the other, and the client value won often enough to leave the object
// unreadable. The pass-through branch had no guard at all.
func TestObjPutClientCannotInjectEncryptionMetadataOnTheSingleRequestPath(t *testing.T) {
	// Three spellings a client can send. All canonicalise to one header, which
	// is exactly why comparing the case mattered.
	spellings := []string{
		"x-amz-meta-s3ep-encrypted-dek",
		"X-Amz-Meta-S3EP-Encrypted-Dek",
		"X-AMZ-META-S3EP-ENCRYPTED-DEK",
	}

	paths := map[string]ObjPutopts{
		"aes_provider":  {},
		"exit_provider": {providerType: "exit"},
	}

	for name, opts := range paths {
		for _, spelling := range spellings {
			t.Run(name+"/"+spelling, func(t *testing.T) {
				backend := new(MockS3Backend)
				h := ObjPutnewHandler(t, backend, opts)
				stored := ObjPutcapturePut(backend, `"etag"`, "")

				req := httptest.NewRequest(http.MethodPut, "/b/k", bytes.NewReader(ObjPutpayload(256)))
				req.Header.Set("x-amz-meta-s3ep-kek-fingerprint", "forged-fingerprint")
				req.Header.Set(spelling, "forged-dek")
				req.Header.Set("x-amz-meta-project", "orion")

				rr := ObjPutdo(h, req, "b", "k")
				require.Equal(t, http.StatusOK, rr.Code)
				require.NotNil(t, stored.input)

				for k, v := range stored.input.Metadata {
					assert.NotEqual(t, "forged-dek", v, "forged value stored under key %q", k)
					assert.NotEqual(t, "forged-fingerprint", v, "forged value stored under key %q", k)
				}
				assert.Equal(t, "orion", stored.input.Metadata["project"],
					"metadata outside the namespace is untouched")
			})
		}
	}
}

// The same guard on the producer path, where the injected key would land in
// CreateMultipartUpload and travel with the object from its first byte.
func TestObjPutAutoMultipartFiltersInjectedEncryptionMetadata(t *testing.T) {
	backend := new(MockS3Backend)
	h := ObjPutnewHandler(t, backend, ObjPutopts{})
	rec := ObjPutwireMultipart(backend, "u1")

	req := httptest.NewRequest(http.MethodPut, "/b/k", bytes.NewReader(ObjPutpayload(2048)))
	req.Header.Set("x-amz-meta-s3ep-kek-fingerprint", "forged-fingerprint")
	req.Header.Set("x-amz-meta-keep", "value")
	req.ContentLength = -1

	rr := ObjPutdo(h, req, "b", "k")
	require.Equal(t, http.StatusOK, rr.Code)

	require.NotNil(t, rec.create)
	assert.Equal(t, "value", rec.create.Metadata["keep"])
	assert.NotEqual(t, "forged-fingerprint", rec.create.Metadata["s3ep-kek-fingerprint"])
	assert.Equal(t, ObjPutmetadataKeys("s3ep-"),
		ObjPutencryptionMetadata(rec.create.Metadata, "s3ep-"))
}

// ---------------------------------------------------------------------------
// Error paths on the single-request PUT.
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

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			backend := new(MockS3Backend)
			h := ObjPutnewHandler(t, backend, ObjPutopts{})
			backend.On("PutObject", mock.Anything, mock.Anything).Return(nil, tc.err)

			rr := ObjPutdo(h, httptest.NewRequest(http.MethodPut, "/b/k",
				bytes.NewReader(ObjPutpayload(256))), "b", "k")

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

// A body that dies mid-read is no longer read by the handler: the sealing reader
// is pulled by the backend call, so the client's failure surfaces as a failed
// PutObject. What must not happen either way is a 200 over a half-written object.
func TestObjPutBodyReadErrorDoesNotStoreAnything(t *testing.T) {
	backend := new(MockS3Backend)
	h := ObjPutnewHandler(t, backend, ObjPutopts{})

	var sealErr error
	backend.On("PutObject", mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			_, sealErr = io.ReadAll(args.Get(1).(*s3.PutObjectInput).Body)
		}).
		Return(nil, errors.New("upload aborted: connection reset by peer"))

	req := httptest.NewRequest(http.MethodPut, "/b/k", &ObjPuterrReader{
		prefix: ObjPutpayload(10),
		err:    errors.New("connection reset by peer"),
	})
	req.ContentLength = 4096

	rr := ObjPutdo(h, req, "b", "k")

	require.Error(t, sealErr, "the sealing reader must hand the client's failure to the backend")
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
	assert.Equal(t, "InternalError", ObjPutparseError(t, rr.Body.Bytes()).Code)
	assert.Empty(t, rr.Header().Get("ETag"))
	assert.NotContains(t, rr.Body.String(), "connection reset",
		"internal error detail must stay in the log")
}

// An unknown Content-Length is what a chunked client sends; it must not be
// refused, it must go to the producer.
func TestObjPutUnknownContentLengthUsesAutoMultipart(t *testing.T) {
	backend := new(MockS3Backend)
	h := ObjPutnewHandler(t, backend, ObjPutopts{})
	ObjPutwireMultipart(backend, "u1")

	req := httptest.NewRequest(http.MethodPut, "/b/k", bytes.NewReader(ObjPutpayload(512)))
	req.ContentLength = -1

	rr := ObjPutdo(h, req, "b", "k")

	require.Equal(t, http.StatusOK, rr.Code)
	backend.AssertCalled(t, "CreateMultipartUpload", mock.Anything, mock.Anything)
	backend.AssertNotCalled(t, "PutObject", mock.Anything, mock.Anything)
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
	for name, size := range map[string]int{
		"below_boundary": 900,
		"at_boundary":    dataencryption.SegmentSize,
	} {
		t.Run(name, func(t *testing.T) {
			backend := new(MockS3Backend)
			h := ObjPutnewHandler(t, backend, ObjPutopts{awsChunked: true})
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
			// The declared length is computed from the decoded size, not the wire size.
			assert.Equal(t, ObjPutstoredLen(t, size), aws.ToInt64(stored.input.ContentLength))
			assert.Nil(t, stored.input.ContentEncoding,
				"aws-chunked must not be stored on the object")
		})
	}
}

// ---------------------------------------------------------------------------
// The multipart producer: the whole lifecycle, and the abort that must happen.
// ---------------------------------------------------------------------------

// ObjPutmultipart records everything the producer sends.
type ObjPutmultipart struct {
	mu             sync.Mutex
	create         *s3.CreateMultipartUploadInput
	parts          map[int][]byte
	complete       *s3.CompleteMultipartUploadInput
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

// ObjPutjoinParts concatenates the uploaded parts in PartNumber order. That is
// the object as the backend holds it, trailer included: the producer lays the
// parts out itself and lets the trailer ride on the last one.
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

// The full lifecycle: create with the object's metadata already on it, N parts,
// complete. What the parts hold has to open back to what the client sent, and
// no rewrite may follow: the metadata is complete before the first byte moves.
func TestObjPutAutoMultipartRoundTripsThroughEveryStage(t *testing.T) {
	backend := new(MockS3Backend)
	h := ObjPutnewHandler(t, backend, ObjPutopts{concurrency: 2})
	rec := ObjPutwireMultipart(backend, "auto-id")

	payload := ObjPutpayload(3*dataencryption.SegmentSize + 17) // four parts at one segment each
	req := httptest.NewRequest(http.MethodPut, "/b/big-key", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/zip")
	req.ContentLength = -1

	rr := ObjPutdo(h, req, "b", "big-key")

	require.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, `"complete-etag"`, rr.Header().Get("ETag"),
		"nothing rewrites the object after Complete, so its ETag is the one the client gets")
	assert.Equal(t, "complete-version", rr.Header().Get("x-amz-version-id"))
	backend.AssertNotCalled(t, "CopyObject", mock.Anything, mock.Anything)

	require.NotNil(t, rec.create)
	assert.Equal(t, "b", aws.ToString(rec.create.Bucket))
	assert.Equal(t, "big-key", aws.ToString(rec.create.Key))
	assert.Equal(t, ObjPutmetadataKeys("s3ep-"),
		ObjPutencryptionMetadata(rec.create.Metadata, "s3ep-"))

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
	assert.Equal(t, ObjPutstoredLen(t, len(payload)), int64(len(ciphertext)),
		"the producer's layout has to occupy exactly what a single request would")

	assert.Equal(t, ObjPutdigest(payload),
		ObjPutdigest(ObjPutreadBack(t, h, "big-key", ciphertext, rec.create.Metadata)))

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

// A body that errors mid-read must abort rather than commit what arrived.
func TestObjPutAutoMultipartBodyErrorAborts(t *testing.T) {
	backend := new(MockS3Backend)
	h := ObjPutnewHandler(t, backend, ObjPutopts{})
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
	h := ObjPutnewHandler(t, backend, ObjPutopts{awsChunked: true})
	rec := ObjPutwireMultipart(backend, "auto-id")

	payload := ObjPutpayload(2400)
	framed := ObjPutchunked(payload, 512)

	req := httptest.NewRequest(http.MethodPut, "/b/k", bytes.NewReader(framed))
	req.Header.Set("Content-Encoding", "aws-chunked")
	req.Header.Set("X-Amz-Content-Sha256", "STREAMING-AWS4-HMAC-SHA256-PAYLOAD")
	req.ContentLength = -1

	rr := ObjPutdo(h, req, "b", "k")

	require.Equal(t, http.StatusOK, rr.Code)
	require.NotNil(t, rec.create)
	assert.Equal(t, ObjPutdigest(payload),
		ObjPutdigest(ObjPutreadBack(t, h, "k", rec.ObjPutjoinParts(), rec.create.Metadata)),
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
// Keeping the case net/http canonicalised the header to is what made the
// encryption-metadata guard ineffective: it compared "S3ep-" against the
// lowercase configured prefix and never matched.
func TestObjPutUserMetadataKeyIsLoweredOnEveryPath(t *testing.T) {
	t.Run("single request lowercases", func(t *testing.T) {
		backend := new(MockS3Backend)
		h := ObjPutnewHandler(t, backend, ObjPutopts{})
		stored := ObjPutcapturePut(backend, `"e"`, "")

		req := httptest.NewRequest(http.MethodPut, "/b/k", bytes.NewReader(ObjPutpayload(64)))
		req.Header.Set("x-amz-meta-project", "orion")
		require.Equal(t, http.StatusOK, ObjPutdo(h, req, "b", "k").Code)

		require.NotNil(t, stored.input)
		assert.Equal(t, "orion", stored.input.Metadata["project"])
	})

	t.Run("exit provider lowercases", func(t *testing.T) {
		backend := new(MockS3Backend)
		h := ObjPutnewHandler(t, backend, ObjPutopts{providerType: "exit"})
		stored := ObjPutcapturePut(backend, `"e"`, "")

		req := httptest.NewRequest(http.MethodPut, "/b/k", bytes.NewReader(ObjPutpayload(64)))
		req.Header.Set("x-amz-meta-project", "orion")
		require.Equal(t, http.StatusOK, ObjPutdo(h, req, "b", "k").Code)

		require.NotNil(t, stored.input)
		assert.Equal(t, "orion", stored.input.Metadata["project"])
	})

	t.Run("producer lowercases", func(t *testing.T) {
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
	rec.mu.Lock()
	defer rec.mu.Unlock()
	assert.Nil(t, rec.complete, "the failed Complete stored nothing")
}

// S3 allows at most 10000 parts. Past that the upload has to fail and clean up
// rather than send a part number the backend will reject. The body is generated
// as it is read: at one segment per part the guard sits 640 MiB in.
func TestObjPutAutoMultipartRefusesMoreThan10000Parts(t *testing.T) {
	backend := new(MockS3Backend)
	h := ObjPutnewHandler(t, backend, ObjPutopts{})
	rec := ObjPutwireMultipart(backend, "auto-id")

	// The parts are never read here, so nothing is sealed: the guard is what is
	// under test, not the cipher.
	backend.ExpectedCalls = ObjPutdropCall(backend, "UploadPart")
	backend.On("UploadPart", mock.Anything, mock.Anything).
		Return(&s3.UploadPartOutput{ETag: aws.String(`"p"`)}, nil)

	req := httptest.NewRequest(http.MethodPut, "/b/k",
		&ObjPutbulkReader{left: 10001 * dataencryption.SegmentSize})
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

// A part that is neither whole segments nor the end of the object cannot be
// stored as a chain. The configured part size is validated to at least 5 MiB,
// which is a whole number of segments, so the producer refuses rather than
// writing an object no reader can open.
func TestObjPutAutoMultipartRefusesAPartThatIsNotWholeSegments(t *testing.T) {
	backend := new(MockS3Backend)
	h := ObjPutnewHandler(t, backend, ObjPutopts{segmentSize: 1024})
	rec := ObjPutwireMultipart(backend, "auto-id")

	req := httptest.NewRequest(http.MethodPut, "/b/k", bytes.NewReader(ObjPutpayload(4096)))
	req.ContentLength = -1

	rr := ObjPutdo(h, req, "b", "k")

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
	doc := ObjPutparseError(t, rr.Body.Bytes())
	assert.Equal(t, "UploadError", doc.Code)
	assert.Contains(t, doc.Message, "segment boundary")
	backend.AssertNotCalled(t, "CompleteMultipartUpload", mock.Anything, mock.Anything)
	rec.mu.Lock()
	defer rec.mu.Unlock()
	assert.NotNil(t, rec.abort)
}

// A backend that rejects every part must stop the producer instead of reading
// and sealing the whole body first.
func TestObjPutAutoMultipartStopsFeedingAfterAPartFails(t *testing.T) {
	backend := new(MockS3Backend)
	h := ObjPutnewHandler(t, backend, ObjPutopts{concurrency: 2})
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

	// 200 parts at one segment each; a pipeline that ignored the failure would
	// upload all of them.
	req := httptest.NewRequest(http.MethodPut, "/b/k",
		&ObjPutbulkReader{left: 200 * dataencryption.SegmentSize})
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

// The exit provider has nothing of its own to clean up - it registers no upload
// at all - which must not stop the S3 multipart from being aborted, and the
// client must still see the backend's error.
func TestObjPutAutoMultipartExitProviderStillAbortsTheS3Upload(t *testing.T) {
	backend := new(MockS3Backend)
	h := ObjPutnewHandler(t, backend, ObjPutopts{providerType: "exit"})
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

// DEFECT (minor, reported): the single-request path computes the stored length
// from the declared plaintext length and then seals whatever the body yields. A
// client that declares more than it sends makes the proxy announce a length it
// does not deliver; nothing in the proxy notices. The producer has an explicit
// guard for exactly this case ("client sent %d bytes but declared %d") - the
// single-request path does not.
func TestObjPutSingleRequestShortBodyDeclaresMoreThanItSends(t *testing.T) {
	backend := new(MockS3Backend)
	h := ObjPutnewHandler(t, backend, ObjPutopts{})
	stored := ObjPutcapturePut(backend, `"etag"`, "")

	body := ObjPutpayload(1000)
	req := httptest.NewRequest(http.MethodPut, "/b/k", bytes.NewReader(body))
	req.ContentLength = 4096 // four times what the body holds

	rr := ObjPutdo(h, req, "b", "k")

	require.Equal(t, http.StatusOK, rr.Code)
	require.NotNil(t, stored.input)
	assert.Equal(t, ObjPutstoredLen(t, 4096), aws.ToInt64(stored.input.ContentLength))
	assert.Equal(t, ObjPutstoredLen(t, 1000), int64(len(stored.body)),
		"the proxy declared the length of a 4096-byte object and streamed a 1000-byte one")
}

// DEFECT (minor, reported): a PUT without a Content-Type stores an empty one
// instead of leaving it unset. Real S3 defaults a missing Content-Type to
// binary/octet-stream; here the header is forwarded as an empty string on both
// write paths because the value is wrapped unconditionally.
func TestObjPutMissingContentTypeIsForwardedAsEmpty(t *testing.T) {
	t.Run("single request", func(t *testing.T) {
		backend := new(MockS3Backend)
		h := ObjPutnewHandler(t, backend, ObjPutopts{})
		stored := ObjPutcapturePut(backend, `"etag"`, "")

		req := httptest.NewRequest(http.MethodPut, "/b/k", bytes.NewReader(ObjPutpayload(64)))
		req.Header.Del("Content-Type")
		require.Equal(t, http.StatusOK, ObjPutdo(h, req, "b", "k").Code)

		require.NotNil(t, stored.input)
		require.NotNil(t, stored.input.ContentType,
			"an unset Content-Type is forwarded as an empty header, not omitted")
		assert.Equal(t, "", aws.ToString(stored.input.ContentType))
	})

	t.Run("producer", func(t *testing.T) {
		backend := new(MockS3Backend)
		h := ObjPutnewHandler(t, backend, ObjPutopts{})
		rec := ObjPutwireMultipart(backend, "auto-id")

		req := httptest.NewRequest(http.MethodPut, "/b/k", bytes.NewReader(ObjPutpayload(64)))
		req.Header.Del("Content-Type")
		req.ContentLength = -1
		require.Equal(t, http.StatusOK, ObjPutdo(h, req, "b", "k").Code)

		require.NotNil(t, rec.create)
		require.NotNil(t, rec.create.ContentType)
		assert.Equal(t, "", aws.ToString(rec.create.ContentType))
	})
}

// DEFECT (major, reported): a conditional PUT is answered unconditionally.
// S3 supports "If-None-Match: *" on PutObject to make a write fail with 412
// PreconditionFailed when the key already exists, which is how clients
// implement optimistic concurrency. The GET path forwards both conditional
// headers; the PUT path reads neither, so both writers of a race believe they
// won and one write is lost silently.
func TestObjPutConditionalHeadersAreSilentlyIgnored(t *testing.T) {
	backend := new(MockS3Backend)
	h := ObjPutnewHandler(t, backend, ObjPutopts{})
	stored := ObjPutcapturePut(backend, `"etag"`, "")

	req := httptest.NewRequest(http.MethodPut, "/b/k", bytes.NewReader(ObjPutpayload(64)))
	req.Header.Set("If-None-Match", "*")
	req.Header.Set("If-Match", `"some-etag"`)

	rr := ObjPutdo(h, req, "b", "k")

	assert.Equal(t, http.StatusOK, rr.Code,
		"a conditional write is accepted as an unconditional one")
	require.NotNil(t, stored.input)
	assert.Nil(t, stored.input.IfNoneMatch, "the condition never reaches the backend")
	assert.Nil(t, stored.input.IfMatch)
}

// DEFECT (major, reported; the fix is the checksum verification of ADR 0012):
// a client checksum on PUT is accepted and dropped. AWS verifies Content-MD5
// and x-amz-checksum-* against the uploaded bytes and answers 400 BadDigest on
// a mismatch; here the upload is never checked against what the client said it
// was sending, and the client is told 200. The proxy cannot forward the values
// as they are - they describe the plaintext while the body is a sealed chain -
// but it can verify them itself.
func TestObjPutClientChecksumsAreAcceptedAndDropped(t *testing.T) {
	backend := new(MockS3Backend)
	h := ObjPutnewHandler(t, backend, ObjPutopts{})
	stored := ObjPutcapturePut(backend, `"etag"`, "")

	req := httptest.NewRequest(http.MethodPut, "/b/k", bytes.NewReader(ObjPutpayload(64)))
	// A digest of something else entirely.
	req.Header.Set("Content-MD5", "1B2M2Y8AsgTpgAmY7PhCfg==")
	req.Header.Set("x-amz-sdk-checksum-algorithm", "CRC32")
	req.Header.Set("x-amz-checksum-crc32", "AAAAAA==")
	req.Header.Set("x-amz-expected-bucket-owner", "123456789012")

	rr := ObjPutdo(h, req, "b", "k")

	assert.Equal(t, http.StatusOK, rr.Code, "a wrong client digest is not detected")
	require.NotNil(t, stored.input)
	assert.Nil(t, stored.input.ContentMD5)
	assert.Empty(t, stored.input.ChecksumAlgorithm)
	assert.Nil(t, stored.input.ChecksumCRC32)
	assert.Nil(t, stored.input.ExpectedBucketOwner,
		"the bucket-owner guard the client asked for is dropped too")
}
