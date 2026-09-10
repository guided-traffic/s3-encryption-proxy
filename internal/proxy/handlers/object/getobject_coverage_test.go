package object

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

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
// Fixtures. Everything here builds a *stored object* the way the proxy stores
// one and then exercises the read path through the public HTTP surface, so the
// assertions survive a change of storage format: what a client PUT has to come
// back out byte-identical, whatever the bytes did in between.
// ---------------------------------------------------------------------------

const ObjGetaesKey = "ZEsubBlmU+Pr61y+JOwO09c0LOrHs5LITaO0D4JzSZE="

// ObjGetnewHandler wires a handler with a real AES provider and the requested
// integrity mode ("off", "lax", "strict", "hybrid").
func ObjGetnewHandler(t *testing.T, backend *MockS3Backend, integrity string) *Handler {
	t.Helper()
	prefix := "s3ep-"
	cfg := &config.Config{
		Encryption: config.EncryptionConfig{
			EncryptionMethodAlias: "test-aes",
			MetadataKeyPrefix:     &prefix,
			IntegrityVerification: integrity,
			Providers: []config.EncryptionProvider{{
				Alias:  "test-aes",
				Type:   "aes",
				Config: map[string]interface{}{"aes_key": ObjGetaesKey},
			}},
		},
	}
	cfg.Optimizations.StreamingSegmentSize = 1024
	cfg.Optimizations.MultipartUploadConcurrency = 1
	cfg.Optimizations.StreamingThreshold = 5 * 1024 * 1024

	encMgr, err := orchestration.NewManager(cfg)
	require.NoError(t, err)
	return NewHandler(backend, encMgr, cfg, testLogEntry())
}

// ObjGetstore encrypts plaintext exactly like the write path does and returns
// what the backend would hold: the ciphertext and the stored metadata.
func ObjGetstore(t *testing.T, h *Handler, algorithm, objectKey string, plaintext []byte) ([]byte, map[string]string) {
	t.Helper()
	reader := bufio.NewReader(bytes.NewReader(plaintext))

	var res *orchestration.StreamingEncryptionResult
	var err error
	switch algorithm {
	case "aes-gcm":
		res, err = h.encryptionMgr.EncryptGCM(t.Context(), reader, objectKey)
	case "aes-ctr":
		res, err = h.encryptionMgr.EncryptCTR(t.Context(), reader, objectKey)
	default:
		t.Fatalf("unknown algorithm %q", algorithm)
	}
	require.NoError(t, err)

	ciphertext, err := io.ReadAll(res.EncryptedDataReader)
	require.NoError(t, err)
	require.Equal(t, algorithm, res.Metadata["s3ep-dek-algorithm"])

	// The stored bytes must never be the plaintext. This is the whole point of
	// the proxy, and it makes the fixture self-checking.
	if len(plaintext) > 0 {
		require.NotEqual(t, plaintext, ciphertext, "fixture stored plaintext at the backend")
	}
	return ciphertext, res.Metadata
}

// ObjGetdigest keeps large-payload comparisons out of the failure output.
func ObjGetdigest(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// ObjGetpayload builds a deterministic, incompressible-looking payload of n bytes.
func ObjGetpayload(n int) []byte {
	out := make([]byte, n)
	state := uint32(0x9e3779b9)
	for i := range out {
		state ^= state << 13
		state ^= state >> 17
		state ^= state << 5
		out[i] = byte(state)
	}
	return out
}

// ObjGetgetOutput assembles the backend answer for a stored object.
func ObjGetgetOutput(body []byte, metadata map[string]string) *s3.GetObjectOutput {
	return &s3.GetObjectOutput{
		Body:          io.NopCloser(bytes.NewReader(body)),
		ContentLength: aws.Int64(int64(len(body))),
		ContentType:   aws.String("application/octet-stream"),
		ETag:          aws.String(`"stored-etag"`),
		LastModified:  aws.Time(time.Unix(1700000000, 0).UTC()),
		Metadata:      metadata,
	}
}

// ObjGetdo drives a request through the public entry point, so routing and the
// method switch are part of what is under test.
func ObjGetdo(h *Handler, req *http.Request, bucket, key string) *httptest.ResponseRecorder {
	req = mux.SetURLVars(req, map[string]string{"bucket": bucket, "key": key})
	rr := httptest.NewRecorder()
	h.Handle(rr, req)
	return rr
}

// ObjGeterrorDoc parses the S3 <Error> document out of a response body.
type ObjGeterrorDoc struct {
	XMLName xml.Name `xml:"Error"`
	Code    string   `xml:"Code"`
	Message string   `xml:"Message"`
}

func ObjGetparseError(t *testing.T, body []byte) ObjGeterrorDoc {
	t.Helper()
	var doc ObjGeterrorDoc
	require.NoError(t, xml.Unmarshal(body, &doc), "error response must be a parseable S3 error document")
	return doc
}

// ---------------------------------------------------------------------------
// GET: the client contract.
// ---------------------------------------------------------------------------

// An object the proxy never encrypted is handed through untouched. Note what
// this also means: the proxy has no "encryption required" mode, so anything the
// backend serves without s3ep- metadata reaches the client as a clean 200.
func TestObjGetGetObjectPassthroughWithoutEncryptionMetadata(t *testing.T) {
	backend := new(MockS3Backend)
	h := ObjGetnewHandler(t, backend, config.HMACVerificationStrict)

	payload := ObjGetpayload(4096)
	var captured *s3.GetObjectInput
	backend.On("GetObject", mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) { captured = args.Get(1).(*s3.GetObjectInput) }).
		Return(ObjGetgetOutput(payload, map[string]string{"user": "value"}), nil)

	rr := ObjGetdo(h, httptest.NewRequest(http.MethodGet, "/b/plain-key", nil), "b", "plain-key")

	require.Equal(t, http.StatusOK, rr.Code)
	require.NotNil(t, captured)
	assert.Equal(t, "b", aws.ToString(captured.Bucket))
	assert.Equal(t, "plain-key", aws.ToString(captured.Key))
	assert.Equal(t, ObjGetdigest(payload), ObjGetdigest(rr.Body.Bytes()))
	assert.Equal(t, strconv.Itoa(len(payload)), rr.Header().Get("Content-Length"))
	assert.Equal(t, "bytes", rr.Header().Get("Accept-Ranges"))
	assert.Equal(t, "value", rr.Header().Get("x-amz-meta-user"))
}

// The core contract: what went in comes back out, whatever the storage format
// did with it, and the bytes at the backend are not the plaintext.
func TestObjGetGetObjectReturnsPlaintext(t *testing.T) {
	sizes := []int{0, 1, 15, 28, 4096, 65537}
	for _, algorithm := range []string{"aes-gcm", "aes-ctr"} {
		for _, size := range sizes {
			t.Run(algorithm+"/"+strconv.Itoa(size), func(t *testing.T) {
				backend := new(MockS3Backend)
				h := ObjGetnewHandler(t, backend, config.HMACVerificationStrict)

				key := algorithm + "-" + strconv.Itoa(size)
				plaintext := ObjGetpayload(size)
				ciphertext, metadata := ObjGetstore(t, h, algorithm, key, plaintext)

				var captured *s3.GetObjectInput
				backend.On("GetObject", mock.Anything, mock.Anything).
					Run(func(args mock.Arguments) { captured = args.Get(1).(*s3.GetObjectInput) }).
					Return(ObjGetgetOutput(ciphertext, metadata), nil)

				rr := ObjGetdo(h, httptest.NewRequest(http.MethodGet, "/b/"+key, nil), "b", key)

				require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
				require.NotNil(t, captured)
				assert.Equal(t, key, aws.ToString(captured.Key), "the backend must be asked for the requested key")
				assert.Equal(t, ObjGetdigest(plaintext), ObjGetdigest(rr.Body.Bytes()))
				assert.Equal(t, strconv.Itoa(size), rr.Header().Get("Content-Length"),
					"Content-Length must describe the plaintext the client receives")
				// No s3ep- metadata may leak to the client.
				for name := range rr.Result().Header {
					assert.NotContains(t, strings.ToLower(name), "s3ep-")
				}
			})
		}
	}
}

// A GET that reaches the backend and fails there must answer with the S3 error
// document for that failure, not with a generic 500.
func TestObjGetGetObjectBackendErrors(t *testing.T) {
	cases := map[string]struct {
		err        error
		wantStatus int
		wantCode   string
	}{
		"no_such_key":    {&types.NoSuchKey{}, http.StatusNotFound, "NoSuchKey"},
		"no_such_bucket": {&types.NoSuchBucket{}, http.StatusNotFound, "NoSuchBucket"},
		"access_denied": {&smithy.GenericAPIError{Code: "AccessDenied", Message: "Access Denied"},
			http.StatusForbidden, "AccessDenied"},
		"precondition_failed": {&smithy.GenericAPIError{Code: "PreconditionFailed"},
			http.StatusPreconditionFailed, "PreconditionFailed"},
		"network_error": {errors.New("dial tcp 10.0.0.1:9000: connect: connection refused"),
			http.StatusInternalServerError, "InternalError"},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			backend := new(MockS3Backend)
			h := ObjGetnewHandler(t, backend, config.HMACVerificationStrict)
			backend.On("GetObject", mock.Anything, mock.Anything).Return(nil, tc.err)

			rr := ObjGetdo(h, httptest.NewRequest(http.MethodGet, "/b/k", nil), "b", "k")

			assert.Equal(t, tc.wantStatus, rr.Code)
			assert.Equal(t, "application/xml", rr.Header().Get("Content-Type"))
			doc := ObjGetparseError(t, rr.Body.Bytes())
			assert.Equal(t, tc.wantCode, doc.Code)
			assert.NotEmpty(t, doc.Message)
			// The backend endpoint must never reach the client.
			assert.NotContains(t, rr.Body.String(), "10.0.0.1")
		})
	}
}

// Stored metadata that cannot be decoded is a server fault, and the client must
// see it as one - with no object bytes attached.
func TestObjGetGetObjectMalformedEncryptedDEKMetadata(t *testing.T) {
	backend := new(MockS3Backend)
	h := ObjGetnewHandler(t, backend, config.HMACVerificationStrict)

	ciphertext := ObjGetpayload(256)
	backend.On("GetObject", mock.Anything, mock.Anything).Return(ObjGetgetOutput(ciphertext, map[string]string{
		"s3ep-encrypted-dek": "this is not base64!!",
		"s3ep-dek-algorithm": "aes-gcm",
	}), nil)

	rr := ObjGetdo(h, httptest.NewRequest(http.MethodGet, "/b/k", nil), "b", "k")

	require.Equal(t, http.StatusInternalServerError, rr.Code)
	doc := ObjGetparseError(t, rr.Body.Bytes())
	assert.Equal(t, "DecryptionError", doc.Code)
	assert.NotContains(t, rr.Body.String(), string(ciphertext[:8]), "no object bytes may be written")
}

// Encryption metadata that names no key material fails before a single byte is
// written, on both algorithm branches.
func TestObjGetGetObjectUndecryptableMetadata(t *testing.T) {
	cases := map[string]map[string]string{
		"ctr_without_fingerprint": {
			"s3ep-encrypted-dek": "ZW5jcnlwdGVkLWRlaw==",
			"s3ep-dek-algorithm": "aes-ctr",
		},
		"gcm_without_fingerprint": {
			"s3ep-encrypted-dek": "ZW5jcnlwdGVkLWRlaw==",
			"s3ep-dek-algorithm": "aes-gcm",
		},
		"unknown_algorithm": {
			"s3ep-encrypted-dek":   "ZW5jcnlwdGVkLWRlaw==",
			"s3ep-dek-algorithm":   "aes-xyz",
			"s3ep-kek-fingerprint": "deadbeef",
		},
	}

	for name, metadata := range cases {
		t.Run(name, func(t *testing.T) {
			backend := new(MockS3Backend)
			h := ObjGetnewHandler(t, backend, config.HMACVerificationStrict)
			backend.On("GetObject", mock.Anything, mock.Anything).
				Return(ObjGetgetOutput(ObjGetpayload(512), metadata), nil)

			rr := ObjGetdo(h, httptest.NewRequest(http.MethodGet, "/b/k", nil), "b", "k")

			require.Equal(t, http.StatusInternalServerError, rr.Code)
			doc := ObjGetparseError(t, rr.Body.Bytes())
			assert.Equal(t, "DecryptionError", doc.Code)
			assert.Empty(t, rr.Header().Get("ETag"), "no object response headers may be committed")
		})
	}
}

// Ciphertext that does not authenticate must never be served as plaintext.
func TestObjGetGetObjectCorruptGCMCiphertextIsNotServed(t *testing.T) {
	backend := new(MockS3Backend)
	h := ObjGetnewHandler(t, backend, config.HMACVerificationStrict)

	plaintext := ObjGetpayload(2048)
	ciphertext, metadata := ObjGetstore(t, h, "aes-gcm", "corrupt-gcm", plaintext)
	ciphertext[100] ^= 0xff

	backend.On("GetObject", mock.Anything, mock.Anything).Return(ObjGetgetOutput(ciphertext, metadata), nil)

	rr := ObjGetdo(h, httptest.NewRequest(http.MethodGet, "/b/corrupt-gcm", nil), "b", "corrupt-gcm")

	assert.NotEqual(t, ObjGetdigest(plaintext), ObjGetdigest(rr.Body.Bytes()),
		"a tampered object must not decrypt to the original plaintext")
	if rr.Code == http.StatusOK {
		assert.Less(t, rr.Body.Len(), len(plaintext),
			"a 200 for tampered ciphertext is only tolerable if the body is withheld")
	} else {
		assert.Equal(t, http.StatusInternalServerError, rr.Code)
		assert.Equal(t, "DecryptionError", ObjGetparseError(t, rr.Body.Bytes()).Code)
	}
}

// Ranged reads leave through their own path; this pins that a Range request is
// answered as a partial response and never as a silent full 200.
func TestObjGetGetObjectWithRangeTakesTheRangePath(t *testing.T) {
	backend := new(MockS3Backend)
	h := ObjGetnewHandler(t, backend, config.HMACVerificationStrict)

	payload := ObjGetpayload(1000)
	var captured *s3.GetObjectInput
	backend.On("GetObject", mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) { captured = args.Get(1).(*s3.GetObjectInput) }).
		Return(&s3.GetObjectOutput{
			Body:          io.NopCloser(bytes.NewReader(payload[10:20])),
			ContentLength: aws.Int64(10),
			ContentRange:  aws.String("bytes 10-19/1000"),
		}, nil)

	req := httptest.NewRequest(http.MethodGet, "/b/k", nil)
	req.Header.Set("Range", "bytes=10-19")
	rr := ObjGetdo(h, req, "b", "k")

	require.Equal(t, http.StatusPartialContent, rr.Code)
	require.NotNil(t, captured)
	assert.Equal(t, "bytes=10-19", aws.ToString(captured.Range), "the Range must reach the backend")
	assert.Equal(t, "bytes 10-19/1000", rr.Header().Get("Content-Range"))
	assert.Equal(t, payload[10:20], rr.Body.Bytes())
}

// ---------------------------------------------------------------------------
// Conditional GET. Two of the four RFC 7232 preconditions are forwarded and two
// are dropped, which is a client-visible defect: the request that should be
// answered 304 or 412 is answered 200 with the whole body.
// ---------------------------------------------------------------------------

func TestObjGetGetObjectForwardsOnlyETagPreconditions(t *testing.T) {
	backend := new(MockS3Backend)
	h := ObjGetnewHandler(t, backend, config.HMACVerificationStrict)

	payload := ObjGetpayload(64)
	var captured *s3.GetObjectInput
	backend.On("GetObject", mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) { captured = args.Get(1).(*s3.GetObjectInput) }).
		Return(ObjGetgetOutput(payload, nil), nil)

	req := httptest.NewRequest(http.MethodGet, "/b/k", nil)
	req.Header.Set("If-Match", `"etag-1"`)
	req.Header.Set("If-None-Match", `"etag-2"`)
	req.Header.Set("If-Modified-Since", "Wed, 21 Oct 2015 07:28:00 GMT")
	req.Header.Set("If-Unmodified-Since", "Wed, 21 Oct 2015 07:28:00 GMT")

	rr := ObjGetdo(h, req, "b", "k")

	require.Equal(t, http.StatusOK, rr.Code)
	require.NotNil(t, captured)
	assert.Equal(t, `"etag-1"`, aws.ToString(captured.IfMatch))
	assert.Equal(t, `"etag-2"`, aws.ToString(captured.IfNoneMatch))

	// DEFECT (pinned, not endorsed): the date preconditions are dropped, so a
	// client revalidating a cache entry gets 200 and the whole body where S3
	// answers 304, and If-Unmodified-Since never produces the 412 it exists for.
	assert.Nil(t, captured.IfModifiedSince, "known defect: If-Modified-Since is dropped")
	assert.Nil(t, captured.IfUnmodifiedSince, "known defect: If-Unmodified-Since is dropped")
	assert.Equal(t, len(payload), rr.Body.Len(), "the full body is served instead of a 304")
}

// ---------------------------------------------------------------------------
// Silent 200: request parameters S3 acts on that this proxy neither honours nor
// rejects. The client cannot tell that it got something else than it asked for.
// ---------------------------------------------------------------------------

func TestObjGetGetObjectRefusesPartNumberAndDropsResponseOverrides(t *testing.T) {
	// partNumber selects one part of a multipart object at S3 and answers 206
	// with x-amz-mp-parts-count. This proxy does not implement it. It used to
	// drop the parameter and serve the WHOLE object with a 200, which is the
	// silent-200 class: a client asking for part 2 got the entire object and no
	// way to tell. It is now refused instead.
	t.Run("partNumber is refused rather than silently ignored", func(t *testing.T) {
		backend := new(MockS3Backend)
		h := ObjGetnewHandler(t, backend, config.HMACVerificationStrict)

		rr := ObjGetdo(h, httptest.NewRequest(http.MethodGet, "/b/k?partNumber=2", nil), "b", "k")

		assert.Equal(t, http.StatusNotImplemented, rr.Code)
		backend.AssertNotCalled(t, "GetObject", mock.Anything, mock.Anything)
	})

	// DEFECT (pinned): the response-* overrides are what presigned download URLs
	// use to name a file and set its type. All six are accepted and dropped.
	t.Run("the six response overrides are accepted and dropped", func(t *testing.T) {
		backend := new(MockS3Backend)
		h := ObjGetnewHandler(t, backend, config.HMACVerificationStrict)

		payload := ObjGetpayload(2048)
		var captured *s3.GetObjectInput
		backend.On("GetObject", mock.Anything, mock.Anything).
			Run(func(args mock.Arguments) { captured = args.Get(1).(*s3.GetObjectInput) }).
			Return(ObjGetgetOutput(payload, nil), nil)

		url := "/b/k?response-content-type=text%2Fplain" +
			"&response-content-disposition=attachment%3B+filename%3D%22a.txt%22" +
			"&response-cache-control=no-store&response-content-encoding=identity" +
			"&response-content-language=en-GB&response-expires=Wed%2C+21+Oct+2015+07%3A28%3A00+GMT"
		rr := ObjGetdo(h, httptest.NewRequest(http.MethodGet, url, nil), "b", "k")

		require.Equal(t, http.StatusOK, rr.Code)
		require.NotNil(t, captured)

		assert.Nil(t, captured.ResponseContentType, "known defect: response-content-type is dropped")
		assert.Nil(t, captured.ResponseContentDisposition)
		assert.Nil(t, captured.ResponseCacheControl)
		assert.Nil(t, captured.ResponseContentEncoding)
		assert.Nil(t, captured.ResponseContentLanguage)
		assert.Nil(t, captured.ResponseExpires)
		assert.Equal(t, "application/octet-stream", rr.Header().Get("Content-Type"),
			"the stored type is served, not the requested override")
		assert.Empty(t, rr.Header().Get("Content-Disposition"))
	})
}

// ---------------------------------------------------------------------------
// Integrity: where the HMAC check fires, and where it silently does not.
// Pins the current storage-format behaviour. The segmented-GCM format (ADR 0003)
// replaces this; update together.
// ---------------------------------------------------------------------------

// DEFECT (pinned, not endorsed): a tampered AES-CTR object is served in full,
// with 200 OK and a matching Content-Length, in strict integrity mode. The
// verifying reader is documented to withhold the tail until the HMAC checks out,
// but its "near end of stream" branch
// (internal/orchestration/streaming_io.go:200) returns the bytes to the caller
// instead of buffering them, so by the time VerifyIntegrity runs on the EOF read
// the whole plaintext has already been written to the client. The failure exists
// only as a log line.
//
// The two cases fail for two different reasons and are pinned separately:
// with a Content-Length the check runs and is too late, without one the check is
// never wired in at all (the wrapper needs expectedSize > 0).
func TestObjGetGetObjectTamperedCTRIsServedDespiteStrictMode(t *testing.T) {
	for _, withLength := range []bool{true, false} {
		name := "content_length_known"
		if !withLength {
			name = "content_length_absent"
		}
		t.Run(name, func(t *testing.T) {
			backend := new(MockS3Backend)
			h := ObjGetnewHandler(t, backend, config.HMACVerificationStrict)

			key := "tampered-ctr-" + name
			plaintext := ObjGetpayload(8192)
			ciphertext, metadata := ObjGetstore(t, h, "aes-ctr", key, plaintext)
			require.NotEmpty(t, metadata["s3ep-hmac"], "strict mode must store an HMAC")
			ciphertext[42] ^= 0xff

			out := ObjGetgetOutput(ciphertext, metadata)
			if !withLength {
				out.ContentLength = nil
			}
			backend.On("GetObject", mock.Anything, mock.Anything).Return(out, nil)

			rr := ObjGetdo(h, httptest.NewRequest(http.MethodGet, "/b/"+key, nil), "b", key)

			require.Equal(t, http.StatusOK, rr.Code)
			assert.Equal(t, len(plaintext), rr.Body.Len(),
				"known defect: the tampered plaintext is delivered in full")
			assert.NotEqual(t, ObjGetdigest(plaintext), ObjGetdigest(rr.Body.Bytes()),
				"the delivered bytes are the tampered ones, not the original")
			if withLength {
				assert.Equal(t, strconv.Itoa(len(plaintext)), rr.Header().Get("Content-Length"),
					"the response is complete and well-formed, so the client cannot notice")
			}
		})
	}
}

// The counterpart that does hold: AES-GCM authenticates with its own tag inside
// the cipher, so a tampered object never decrypts and nothing is served.
func TestObjGetGetObjectTamperedGCMNeverReachesTheClient(t *testing.T) {
	backend := new(MockS3Backend)
	h := ObjGetnewHandler(t, backend, config.HMACVerificationStrict)

	plaintext := ObjGetpayload(4096)
	ciphertext, metadata := ObjGetstore(t, h, "aes-gcm", "tampered-gcm", plaintext)
	ciphertext[len(ciphertext)/2] ^= 0xff

	backend.On("GetObject", mock.Anything, mock.Anything).Return(ObjGetgetOutput(ciphertext, metadata), nil)

	rr := ObjGetdo(h, httptest.NewRequest(http.MethodGet, "/b/tampered-gcm", nil), "b", "tampered-gcm")

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
	assert.Equal(t, "DecryptionError", ObjGetparseError(t, rr.Body.Bytes()).Code)
	assert.NotContains(t, rr.Body.String(), string(plaintext[:4]))
}

// ---------------------------------------------------------------------------
// HEAD.
// ---------------------------------------------------------------------------

// The length HEAD reports has to be the length GET delivers. For AES-GCM the
// stored object is 28 bytes longer than the plaintext (12-byte nonce, 16-byte
// tag), and the arithmetic is cross-checked against encryption.ComputePlaintextSize.
func TestObjGetHeadObjectReportsPlaintextContentLength(t *testing.T) {
	for _, algorithm := range []string{"aes-gcm", "aes-ctr"} {
		for _, size := range []int{0, 1, 4096} {
			t.Run(algorithm+"/"+strconv.Itoa(size), func(t *testing.T) {
				backend := new(MockS3Backend)
				h := ObjGetnewHandler(t, backend, config.HMACVerificationStrict)

				key := "head-" + algorithm + "-" + strconv.Itoa(size)
				plaintext := ObjGetpayload(size)
				ciphertext, metadata := ObjGetstore(t, h, algorithm, key, plaintext)

				expected := encryption.ComputePlaintextSize(int64(len(ciphertext)), algorithm)
				require.Equal(t, int64(size), expected, "ComputePlaintextSize disagrees with the stored object")

				backend.On("HeadObject", mock.Anything, mock.Anything).Return(&s3.HeadObjectOutput{
					ContentLength: aws.Int64(int64(len(ciphertext))),
					Metadata:      metadata,
				}, nil)
				backend.On("GetObject", mock.Anything, mock.Anything).
					Return(ObjGetgetOutput(ciphertext, metadata), nil)

				head := ObjGetdo(h, httptest.NewRequest(http.MethodHead, "/b/"+key, nil), "b", key)
				require.Equal(t, http.StatusOK, head.Code)
				assert.Equal(t, strconv.Itoa(size), head.Header().Get("Content-Length"))

				get := ObjGetdo(h, httptest.NewRequest(http.MethodGet, "/b/"+key, nil), "b", key)
				require.Equal(t, http.StatusOK, get.Code)
				assert.Equal(t, head.Header().Get("Content-Length"), get.Header().Get("Content-Length"),
					"HEAD and GET must agree on the length")
				assert.Equal(t, size, get.Body.Len())
			})
		}
	}
}

// An object with no encryption metadata and one whose recorded algorithm cannot
// be sized both keep the stored length.
func TestObjGetHeadObjectContentLengthFallbacks(t *testing.T) {
	cases := map[string]struct {
		metadata map[string]string
		stored   int64
		want     string
	}{
		"unencrypted":       {nil, 1234, "1234"},
		"unknown_algorithm": {map[string]string{"s3ep-dek-algorithm": "aes-xyz"}, 1234, "1234"},
		"gcm_short_object":  {map[string]string{"s3ep-dek-algorithm": "aes-gcm"}, 10, "10"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			backend := new(MockS3Backend)
			h := ObjGetnewHandler(t, backend, config.HMACVerificationStrict)
			backend.On("HeadObject", mock.Anything, mock.Anything).Return(&s3.HeadObjectOutput{
				ContentLength: aws.Int64(tc.stored),
				Metadata:      tc.metadata,
			}, nil)

			rr := ObjGetdo(h, httptest.NewRequest(http.MethodHead, "/b/k", nil), "b", "k")
			require.Equal(t, http.StatusOK, rr.Code)
			assert.Equal(t, tc.want, rr.Header().Get("Content-Length"))
		})
	}
}

func TestObjGetHeadObjectPassesThroughEntityHeadersAndMetadata(t *testing.T) {
	backend := new(MockS3Backend)
	h := ObjGetnewHandler(t, backend, config.HMACVerificationStrict)

	modified := time.Date(2023, 11, 14, 22, 13, 20, 0, time.UTC)
	backend.On("HeadObject", mock.Anything, mock.Anything).Return(&s3.HeadObjectOutput{
		ContentType:        aws.String("image/png"),
		ETag:               aws.String(`"stored-etag"`),
		LastModified:       aws.Time(modified),
		VersionId:          aws.String("version-7"),
		ContentEncoding:    aws.String("gzip"),
		ContentDisposition: aws.String(`attachment; filename="x.png"`),
		ContentLanguage:    aws.String("de-DE"),
		CacheControl:       aws.String("max-age=99"),
		ChecksumSHA256:     aws.String("AAAAAA=="),
		Metadata: map[string]string{
			"user":                 "value",
			"s3ep-encrypted-dek":   "ZW5jcnlwdGVkLWRlaw==",
			"s3ep-dek-algorithm":   "aes-gcm",
			"s3ep-kek-fingerprint": "deadbeef",
			"s3ep-hmac":            "AAAA",
		},
	}, nil)

	rr := ObjGetdo(h, httptest.NewRequest(http.MethodHead, "/b/k", nil), "b", "k")

	require.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "image/png", rr.Header().Get("Content-Type"))
	assert.Equal(t, `"stored-etag"`, rr.Header().Get("ETag"))
	assert.Equal(t, modified.Format(http.TimeFormat), rr.Header().Get("Last-Modified"))
	assert.Equal(t, "bytes", rr.Header().Get("Accept-Ranges"))
	assert.Equal(t, "version-7", rr.Header().Get("x-amz-version-id"))
	assert.Equal(t, "gzip", rr.Header().Get("Content-Encoding"))
	assert.Equal(t, `attachment; filename="x.png"`, rr.Header().Get("Content-Disposition"))
	assert.Equal(t, "de-DE", rr.Header().Get("Content-Language"))
	assert.Equal(t, "max-age=99", rr.Header().Get("Cache-Control"))
	assert.Equal(t, "value", rr.Header().Get("x-amz-meta-user"))
	assertNoChecksumHeaders(t, rr.Result().Header)

	for name := range rr.Result().Header {
		assert.NotContains(t, strings.ToLower(name), "s3ep-", "encryption metadata must not reach the client")
	}
}

func TestObjGetHeadObjectBackendErrors(t *testing.T) {
	cases := map[string]struct {
		err        error
		wantStatus int
		wantCode   string
	}{
		"not_found":     {&types.NotFound{}, http.StatusNotFound, "NotFound"},
		"access_denied": {&smithy.GenericAPIError{Code: "AccessDenied"}, http.StatusForbidden, "AccessDenied"},
		"network":       {errors.New("connection reset by peer"), http.StatusInternalServerError, "InternalError"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			backend := new(MockS3Backend)
			h := ObjGetnewHandler(t, backend, config.HMACVerificationStrict)
			backend.On("HeadObject", mock.Anything, mock.Anything).Return(nil, tc.err)

			rr := ObjGetdo(h, httptest.NewRequest(http.MethodHead, "/b/k", nil), "b", "k")

			assert.Equal(t, tc.wantStatus, rr.Code)
			assert.Equal(t, tc.wantCode, ObjGetparseError(t, rr.Body.Bytes()).Code)
			assert.Empty(t, rr.Header().Get("Content-Length"))
		})
	}
}

// DEFECT (pinned): HEAD forwards no conditional header at all and no Range.
// A client revalidating with If-None-Match gets 200 instead of 304, a client
// guarding a write with If-Match never sees the 412, and a HEAD with a Range
// header - which S3 answers 206 with a Content-Range - is answered 200.
func TestObjGetHeadObjectDropsEveryConditionalHeader(t *testing.T) {
	backend := new(MockS3Backend)
	h := ObjGetnewHandler(t, backend, config.HMACVerificationStrict)

	var captured *s3.HeadObjectInput
	backend.On("HeadObject", mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) { captured = args.Get(1).(*s3.HeadObjectInput) }).
		Return(&s3.HeadObjectOutput{
			ContentLength: aws.Int64(1000),
			ETag:          aws.String(`"stored-etag"`),
		}, nil)

	req := httptest.NewRequest(http.MethodHead, "/b/k", nil)
	req.Header.Set("If-None-Match", `"stored-etag"`)
	req.Header.Set("If-Match", `"other-etag"`)
	req.Header.Set("If-Modified-Since", "Wed, 21 Oct 2015 07:28:00 GMT")
	req.Header.Set("If-Unmodified-Since", "Wed, 21 Oct 2015 07:28:00 GMT")
	req.Header.Set("Range", "bytes=0-9")

	rr := ObjGetdo(h, req, "b", "k")

	require.Equal(t, http.StatusOK, rr.Code, "known defect: every precondition is dropped, so nothing can fail")
	require.NotNil(t, captured)
	assert.Nil(t, captured.IfNoneMatch, "known defect: HEAD drops If-None-Match")
	assert.Nil(t, captured.IfMatch, "known defect: HEAD drops If-Match")
	assert.Nil(t, captured.IfModifiedSince)
	assert.Nil(t, captured.IfUnmodifiedSince)
	assert.Nil(t, captured.Range, "known defect: HEAD drops the Range header")
	assert.Empty(t, rr.Header().Get("Content-Range"))
	assert.Equal(t, "1000", rr.Header().Get("Content-Length"))
}

// ---------------------------------------------------------------------------
// Units below the handlers.
// ---------------------------------------------------------------------------


// ObjGeterrReader fails on Read.
type ObjGeterrReader struct{ err error }

func (r ObjGeterrReader) Read([]byte) (int, error) { return 0, r.err }
func (r ObjGeterrReader) Close() error             { return nil }

// ObjGetcloseErrReader delivers its payload and then fails on Close, the way a
// reader that verifies integrity at the end of the stream does.
type ObjGetcloseErrReader struct {
	io.Reader
	err error
}

func (r ObjGetcloseErrReader) Close() error { return r.err }

// ObjGetkeyedReader carries the GetObjectKey marker the HMAC path looks for.
type ObjGetkeyedReader struct{ io.Reader }

func (ObjGetkeyedReader) Close() error         { return nil }
func (ObjGetkeyedReader) GetObjectKey() string { return "keyed-object" }




// writeGetObjectResponse is the single funnel every GET branch ends in. With a
// bare output it must still produce a valid, empty 200 and emit nothing it was
// not given.
func TestObjGetWriteGetObjectResponseMinimalOutput(t *testing.T) {
	h := newResponseTestHandler(nil)

	rr := httptest.NewRecorder()
	h.writeGetObjectResponse(rr, &s3.GetObjectOutput{Body: io.NopCloser(bytes.NewReader(nil))}, false)

	require.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, []string{"accept-ranges"}, headerNames(rr.Result().Header))
	assert.Empty(t, rr.Body.Bytes())
}

// A body that fails mid-stream cannot change a status that is already sent; all
// the handler can do is stop writing. Pinned so a future "return 500 here"
// regression, which would panic on a committed response, is visible.
func TestObjGetWriteGetObjectResponseBodyFailure(t *testing.T) {
	h := newResponseTestHandler(nil)

	rr := httptest.NewRecorder()
	h.writeGetObjectResponse(rr, &s3.GetObjectOutput{
		Body:          io.NopCloser(io.MultiReader(bytes.NewReader([]byte("head")), ObjGeterrReader{err: errors.New("broken")})),
		ContentLength: aws.Int64(1000),
	}, true)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "head", rr.Body.String())
	assert.Equal(t, "1000", rr.Header().Get("Content-Length"), "the declared length outlives the failure")
}

// A Close failure on the response body is reported by the reader after the last
// byte is written; it must not corrupt the response.
func TestObjGetWriteGetObjectResponseCloseFailureIsSwallowed(t *testing.T) {
	h := newResponseTestHandler(nil)
	payload := ObjGetpayload(512)

	rr := httptest.NewRecorder()
	h.writeGetObjectResponse(rr, &s3.GetObjectOutput{
		Body:          ObjGetcloseErrReader{Reader: bytes.NewReader(payload), err: errors.New("hmac mismatch")},
		ContentLength: aws.Int64(int64(len(payload))),
	}, true)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, ObjGetdigest(payload), ObjGetdigest(rr.Body.Bytes()))
}

func TestObjGetDecodeEncryptedDEK(t *testing.T) {
	h := newResponseTestHandler(nil)

	decoded, err := h.decodeEncryptedDEK("ZW5jcnlwdGVkLWRlaw==")
	require.NoError(t, err)
	assert.Equal(t, []byte("encrypted-dek"), decoded)

	_, err = h.decodeEncryptedDEK("not base64 %%%")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode encrypted DEK")
}

// A backend body whose Close fails after the object was delivered must not
// damage the response: the bytes are already correct and the status is out.
func TestObjGetGetObjectBackendBodyCloseFailureStillDelivers(t *testing.T) {
	backend := new(MockS3Backend)
	h := ObjGetnewHandler(t, backend, config.HMACVerificationStrict)

	plaintext := ObjGetpayload(4096)
	ciphertext, metadata := ObjGetstore(t, h, "aes-ctr", "ctr-close-error", plaintext)

	out := ObjGetgetOutput(ciphertext, metadata)
	out.Body = ObjGetcloseErrReader{Reader: bytes.NewReader(ciphertext), err: errors.New("connection reset on close")}
	backend.On("GetObject", mock.Anything, mock.Anything).Return(out, nil)

	rr := ObjGetdo(h, httptest.NewRequest(http.MethodGet, "/b/ctr-close-error", nil), "b", "ctr-close-error")

	require.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, ObjGetdigest(plaintext), ObjGetdigest(rr.Body.Bytes()))
}

// Pins the current storage-format behaviour. The segmented-GCM format (ADR 0003)
// replaces this; update together.
// ObjGetstreamingDecryptionReaderStub exists to reach writeGetObjectResponse's
// second branch, which is selected by matching the Go type name of the body
// against the literal "streamingDecryptionReader". No type of that name exists
// in the repository any more, so no request can take that branch - this stub is
// the only way in, and that is the point being recorded.
type ObjGetstreamingDecryptionReaderStub struct {
	io.Reader
	closeErr error
}

func (s ObjGetstreamingDecryptionReaderStub) Close() error { return s.closeErr }

func TestObjGetWriteGetObjectResponseHMACBranchIsSelectedByTypeName(t *testing.T) {
	h := newResponseTestHandler(nil)
	payload := ObjGetpayload(4096)

	t.Run("delivers_the_body", func(t *testing.T) {
		rr := httptest.NewRecorder()
		body := ObjGetstreamingDecryptionReaderStub{Reader: bytes.NewReader(payload)}
		require.Contains(t, fmt.Sprintf("%T", body), "streamingDecryptionReader",
			"the branch is selected by this substring alone")

		h.writeGetObjectResponse(rr, &s3.GetObjectOutput{
			Body:          body,
			ContentLength: aws.Int64(int64(len(payload))),
		}, true)

		require.Equal(t, http.StatusOK, rr.Code)
		assert.Equal(t, ObjGetdigest(payload), ObjGetdigest(rr.Body.Bytes()))
	})

	t.Run("copy_failure_stops_writing", func(t *testing.T) {
		rr := httptest.NewRecorder()
		body := ObjGetstreamingDecryptionReaderStub{
			Reader: io.MultiReader(bytes.NewReader([]byte("head")), ObjGeterrReader{err: errors.New("broken")}),
		}
		h.writeGetObjectResponse(rr, &s3.GetObjectOutput{Body: body, ContentLength: aws.Int64(999)}, true)

		assert.Equal(t, http.StatusOK, rr.Code)
		assert.Equal(t, "head", rr.Body.String())
	})

	// An integrity failure reported by Close arrives after the last byte is on
	// the wire. All the handler can do is log it - the client already has the data.
	t.Run("close_failure_after_the_body_is_sent", func(t *testing.T) {
		rr := httptest.NewRecorder()
		body := ObjGetstreamingDecryptionReaderStub{
			Reader:   bytes.NewReader(payload),
			closeErr: errors.New("HMAC integrity verification failed"),
		}
		h.writeGetObjectResponse(rr, &s3.GetObjectOutput{
			Body:          body,
			ContentLength: aws.Int64(int64(len(payload))),
		}, true)

		assert.Equal(t, http.StatusOK, rr.Code)
		assert.Equal(t, len(payload), rr.Body.Len(),
			"the plaintext is already delivered when the integrity check reports")
	})
}

// DEFECT (pinned, not endorsed): the GET path subtracts the 28 bytes of AES-GCM
// framing from Content-Length for every algorithm that is not aes-ctr, while the
// decryption layer accepts "none" as a valid stored algorithm and returns the
// bytes verbatim. The response then declares 28 bytes less than it writes. A
// real net/http server truncates the body to the declared length, so a client
// stores a corrupt object without any error - and the metadata that triggers it
// sits at the backend, which this proxy does not trust.
func TestObjGetGetObjectNoneAlgorithmDeclaresTooShortAContentLength(t *testing.T) {
	backend := new(MockS3Backend)
	h := ObjGetnewHandler(t, backend, config.HMACVerificationStrict)

	stored := ObjGetpayload(1000)
	backend.On("GetObject", mock.Anything, mock.Anything).Return(ObjGetgetOutput(stored, map[string]string{
		"s3ep-encrypted-dek":   "ZW5jcnlwdGVkLWRlaw==",
		"s3ep-dek-algorithm":   "none",
		"s3ep-kek-fingerprint": "none-provider-fingerprint",
	}), nil)

	rr := ObjGetdo(h, httptest.NewRequest(http.MethodGet, "/b/none-algo", nil), "b", "none-algo")

	require.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, 1000, rr.Body.Len())
	assert.Equal(t, "972", rr.Header().Get("Content-Length"),
		"known defect: the declared length is 28 bytes short of the body")
}
