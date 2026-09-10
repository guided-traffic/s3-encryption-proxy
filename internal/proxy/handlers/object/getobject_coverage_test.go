package object

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"errors"
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
	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption/dataencryption"
)

// ---------------------------------------------------------------------------
// Fixtures. Everything here builds a *stored object* the way the proxy stores
// one and then exercises the read path through the public HTTP surface, so the
// assertions survive a change of storage format: what a client PUT has to come
// back out byte-identical, whatever the bytes did in between.
// ---------------------------------------------------------------------------

const ObjGetaesKey = "ZEsubBlmU+Pr61y+JOwO09c0LOrHs5LITaO0D4JzSZE="

// ObjGetnewHandler wires a handler with a real AES provider. Every object it
// writes is a segment chain and every object it reads has to be one; there is
// no setting that relaxes that.
func ObjGetnewHandler(t *testing.T, backend *MockS3Backend) *Handler {
	t.Helper()
	return ObjGetnewProviderHandler(t, backend, config.EncryptionProvider{
		Alias:  "test-aes",
		Type:   "aes",
		Config: map[string]interface{}{"aes_key": ObjGetaesKey},
	})
}

// ObjGetnewPassThroughHandler wires the one provider under which stored bytes
// and plaintext are the same bytes.
func ObjGetnewPassThroughHandler(t *testing.T, backend *MockS3Backend) *Handler {
	t.Helper()
	return ObjGetnewProviderHandler(t, backend, config.EncryptionProvider{
		Alias: "test-none",
		Type:  "none",
	})
}

func ObjGetnewProviderHandler(t *testing.T, backend *MockS3Backend, provider config.EncryptionProvider) *Handler {
	t.Helper()
	prefix := "s3ep-"
	cfg := &config.Config{
		Encryption: config.EncryptionConfig{
			EncryptionMethodAlias: provider.Alias,
			MetadataKeyPrefix:     &prefix,
			Providers:             []config.EncryptionProvider{provider},
		},
	}
	cfg.Optimizations.StreamingSegmentSize = 1024
	cfg.Optimizations.MultipartUploadConcurrency = 1

	encMgr, err := orchestration.NewManager(cfg)
	require.NoError(t, err)
	return NewHandler(backend, encMgr, cfg, testLogEntry())
}

// ObjGetstore seals plaintext exactly like the write path does and returns what
// the backend would hold: the sealed chain and the metadata that makes it
// readable. The object key is part of what every seal authenticates, so a
// fixture is only readable under the key it was sealed for.
func ObjGetstore(t *testing.T, h *Handler, objectKey string, plaintext []byte) ([]byte, map[string]string) {
	t.Helper()

	write, err := h.encryptionMgr.NewSegmentedWrite(objectKey, bytes.NewReader(plaintext), int64(len(plaintext)), nil)
	require.NoError(t, err)

	ciphertext, err := io.ReadAll(write.Body)
	require.NoError(t, err)
	require.Equal(t, write.ContentLength, int64(len(ciphertext)),
		"the stored length is declared before the first byte moves, so it has to match what was sealed")
	require.Equal(t, dataencryption.FormatID, write.Metadata["s3ep-dek-algorithm"])

	// The stored bytes must never be the plaintext. This is the whole point of
	// the proxy, and it makes the fixture self-checking. The empty object is not
	// empty either: it is the sealed trailer on its own.
	require.NotEqual(t, plaintext, ciphertext, "fixture stored plaintext at the backend")
	return ciphertext, write.Metadata
}

// ObjGetmutateMetadata copies stored metadata with single keys overridden, so a
// case describes one deviation from a readable object. An empty value removes
// the key.
func ObjGetmutateMetadata(metadata, overrides map[string]string) map[string]string {
	out := make(map[string]string, len(metadata))
	for key, value := range metadata {
		out[key] = value
	}
	for key, value := range overrides {
		if value == "" {
			delete(out, key)
			continue
		}
		out[key] = value
	}
	return out
}

// ObjGettamperedWrap returns the metadata with the wrapped data key modified.
// The wrap is authenticated, so this is what a backend that edited the metadata
// looks like from the read side.
func ObjGettamperedWrap(t *testing.T, metadata map[string]string) map[string]string {
	t.Helper()
	wrapped, err := base64.StdEncoding.DecodeString(metadata["s3ep-encrypted-dek"])
	require.NoError(t, err)
	wrapped[len(wrapped)-1] ^= 0xff
	return ObjGetmutateMetadata(metadata, map[string]string{
		"s3ep-encrypted-dek": base64.StdEncoding.EncodeToString(wrapped),
	})
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

// An object without the proxy's metadata is an object the proxy did not write.
// Under an encrypting provider it is refused rather than handed over: there is
// no mode in which a client receives bytes this proxy cannot authenticate, and
// the object exists and the client may read it, so InvalidObjectState is the
// only honest answer (ADR 0003).
func TestObjGetGetObjectWithoutEncryptionMetadataIsRefused(t *testing.T) {
	backend := new(MockS3Backend)
	h := ObjGetnewHandler(t, backend)

	payload := ObjGetpayload(4096)
	backend.On("GetObject", mock.Anything, mock.Anything).
		Return(ObjGetgetOutput(payload, map[string]string{"user": "value"}), nil)

	rr := ObjGetdo(h, httptest.NewRequest(http.MethodGet, "/b/plain-key", nil), "b", "plain-key")

	require.Equal(t, http.StatusForbidden, rr.Code)
	assert.Equal(t, "InvalidObjectState", ObjGetparseError(t, rr.Body.Bytes()).Code)
	assert.NotContains(t, rr.Body.String(), string(payload[:8]), "no stored bytes may reach the client")
	assert.Empty(t, rr.Header().Get("x-amz-meta-user"), "no object headers may be committed")
}

// The pass-through provider is the one place where the stored bytes are the
// plaintext, so there the same request is still a clean 200.
func TestObjGetGetObjectPassThroughProviderServesStoredBytes(t *testing.T) {
	backend := new(MockS3Backend)
	h := ObjGetnewPassThroughHandler(t, backend)

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
// did with it, and the bytes at the backend are not the plaintext. The sizes
// bracket the segment boundary, which is where the chain arithmetic can go
// wrong: nothing at all, a partial segment, exactly one, and one byte over.
func TestObjGetGetObjectReturnsPlaintext(t *testing.T) {
	for _, size := range []int{0, 1, 15, 4096, dataencryption.SegmentSize, dataencryption.SegmentSize + 1} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			backend := new(MockS3Backend)
			h := ObjGetnewHandler(t, backend)

			key := "object-" + strconv.Itoa(size)
			plaintext := ObjGetpayload(size)
			ciphertext, metadata := ObjGetstore(t, h, key, plaintext)

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
			h := ObjGetnewHandler(t, backend)
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

// Metadata that names the format but carries a wrapped key that is not even
// base64 describes nothing this proxy can open, so the object counts as one it
// did not write and the read is refused before a byte is served.
func TestObjGetGetObjectMalformedEncryptedDEKMetadata(t *testing.T) {
	backend := new(MockS3Backend)
	h := ObjGetnewHandler(t, backend)

	ciphertext := ObjGetpayload(256)
	backend.On("GetObject", mock.Anything, mock.Anything).Return(ObjGetgetOutput(ciphertext, map[string]string{
		"s3ep-encrypted-dek":   "this is not base64!!",
		"s3ep-dek-algorithm":   dataencryption.FormatID,
		"s3ep-kek-fingerprint": "deadbeef",
	}), nil)

	rr := ObjGetdo(h, httptest.NewRequest(http.MethodGet, "/b/k", nil), "b", "k")

	require.Equal(t, http.StatusForbidden, rr.Code)
	assert.Equal(t, "InvalidObjectState", ObjGetparseError(t, rr.Body.Bytes()).Code)
	assert.NotContains(t, rr.Body.String(), string(ciphertext[:8]), "no object bytes may be written")
}

// The two ways a read fails on the metadata alone, told apart on purpose. An
// object in a format this proxy does not read is the client's answer to give up
// on (403); a key this proxy should be able to unwrap and cannot is the proxy's
// own failure (500). Neither writes a byte of the object.
func TestObjGetGetObjectUndecryptableMetadata(t *testing.T) {
	reference := new(MockS3Backend)
	_, stored := ObjGetstore(t, ObjGetnewHandler(t, reference), "k", ObjGetpayload(512))

	cases := map[string]struct {
		metadata   map[string]string
		wantStatus int
		wantCode   string
	}{
		"previous_format_ctr": {
			ObjGetmutateMetadata(stored, map[string]string{"s3ep-dek-algorithm": "aes-ctr"}),
			http.StatusForbidden, "InvalidObjectState",
		},
		"previous_format_gcm": {
			ObjGetmutateMetadata(stored, map[string]string{"s3ep-dek-algorithm": "aes-gcm"}),
			http.StatusForbidden, "InvalidObjectState",
		},
		"no_algorithm": {
			ObjGetmutateMetadata(stored, map[string]string{"s3ep-dek-algorithm": ""}),
			http.StatusForbidden, "InvalidObjectState",
		},
		"no_wrapped_key": {
			ObjGetmutateMetadata(stored, map[string]string{"s3ep-encrypted-dek": ""}),
			http.StatusForbidden, "InvalidObjectState",
		},
		"no_fingerprint": {
			ObjGetmutateMetadata(stored, map[string]string{"s3ep-kek-fingerprint": ""}),
			http.StatusForbidden, "InvalidObjectState",
		},
		"fingerprint_of_a_key_this_proxy_does_not_hold": {
			ObjGetmutateMetadata(stored, map[string]string{"s3ep-kek-fingerprint": "deadbeef"}),
			http.StatusInternalServerError, "DecryptionError",
		},
		// Permanent, like every case above it: the wrap will not authenticate on a
		// later attempt either, so the client is told the object cannot be served
		// rather than handed a 5xx its SDK will retry to the end of its budget.
		"wrapped_key_does_not_authenticate": {
			ObjGettamperedWrap(t, stored),
			http.StatusForbidden, "InvalidObjectState",
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			backend := new(MockS3Backend)
			h := ObjGetnewHandler(t, backend)
			backend.On("GetObject", mock.Anything, mock.Anything).
				Return(ObjGetgetOutput(ObjGetpayload(512), tc.metadata), nil)

			rr := ObjGetdo(h, httptest.NewRequest(http.MethodGet, "/b/k", nil), "b", "k")

			require.Equal(t, tc.wantStatus, rr.Code, rr.Body.String())
			assert.Equal(t, tc.wantCode, ObjGetparseError(t, rr.Body.Bytes()).Code)
			assert.Empty(t, rr.Header().Get("ETag"), "no object response headers may be committed")
		})
	}
}

// What the previous format could not do. A segment is opened before any of its
// bytes are handed out, and the trailer states the length and checksum the whole
// chain has to add up to, so an object that was modified, truncated or had its
// trailer replaced cannot be served as if it were whole. The response is already
// committed with 200 when the damage is found, so what the client sees is a body
// that stops early - never the tampered plaintext in full.
func TestObjGetGetObjectTamperedObjectIsNotDelivered(t *testing.T) {
	mutations := map[string]func([]byte) []byte{
		"first_segment_flipped": func(c []byte) []byte { c[42] ^= 0xff; return c },
		"last_segment_flipped": func(c []byte) []byte {
			c[len(c)-dataencryption.TrailerSize-1] ^= 0xff
			return c
		},
		"trailer_flipped": func(c []byte) []byte { c[len(c)-1] ^= 0xff; return c },
		"trailer_removed": func(c []byte) []byte { return c[:len(c)-dataencryption.TrailerSize] },
	}

	// Two segments, so a mutation in the second one can only be caught after the
	// first has already been served.
	plaintext := ObjGetpayload(dataencryption.SegmentSize + 4096)

	for _, withLength := range []bool{true, false} {
		suffix := "/content_length_known"
		if !withLength {
			// The previous format wired no verification at all without a
			// Content-Length. The chain does not depend on one.
			suffix = "/content_length_absent"
		}
		for name, mutate := range mutations {
			t.Run(name+suffix, func(t *testing.T) {
				backend := new(MockS3Backend)
				h := ObjGetnewHandler(t, backend)

				key := "tampered-" + name
				ciphertext, metadata := ObjGetstore(t, h, key, plaintext)

				out := ObjGetgetOutput(mutate(ciphertext), metadata)
				if !withLength {
					out.ContentLength = nil
				}
				backend.On("GetObject", mock.Anything, mock.Anything).Return(out, nil)

				rr := ObjGetdo(h, httptest.NewRequest(http.MethodGet, "/b/"+key, nil), "b", key)

				require.Equal(t, http.StatusOK, rr.Code)
				assert.NotEqual(t, ObjGetdigest(plaintext), ObjGetdigest(rr.Body.Bytes()),
					"a tampered object must not decrypt to the original plaintext")
				assert.Less(t, rr.Body.Len(), len(plaintext),
					"the body has to stop where the chain stops authenticating")
			})
		}
	}
}

// Ranged reads leave through their own path. Under the segment chain the range
// the client asks for and the range the backend is asked for are different
// things: the client addresses plaintext, the backend stored bytes.
func TestObjGetGetObjectWithRangeTakesTheRangePath(t *testing.T) {
	backend := new(MockS3Backend)
	h := ObjGetnewHandler(t, backend)

	plaintext := ObjGetpayload(1000)
	ciphertext, metadata := ObjGetstore(t, h, "ranged", plaintext)

	var captured *s3.GetObjectInput
	backend.On("GetObject", mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) { captured = args.Get(1).(*s3.GetObjectInput) }).
		Return(&s3.GetObjectOutput{
			Body:          io.NopCloser(bytes.NewReader(ciphertext)),
			ContentLength: aws.Int64(int64(len(ciphertext))),
			ContentRange:  aws.String("bytes 0-" + strconv.Itoa(len(ciphertext)-1) + "/" + strconv.Itoa(len(ciphertext))),
			Metadata:      metadata,
		}, nil)

	req := httptest.NewRequest(http.MethodGet, "/b/ranged", nil)
	req.Header.Set("Range", "bytes=10-19")
	rr := ObjGetdo(h, req, "b", "ranged")

	require.Equal(t, http.StatusPartialContent, rr.Code, rr.Body.String())
	require.NotNil(t, captured)
	// One segment stride plus the trailer: the window an explicit range needs if
	// the object is large enough to hold it, planned without the key and without
	// a round trip.
	assert.Equal(t, "bytes=0-65603", aws.ToString(captured.Range),
		"the backend is asked for stored bytes, not for the client's plaintext range")
	assert.Equal(t, "bytes 10-19/1000", rr.Header().Get("Content-Range"))
	assert.Equal(t, ObjGetdigest(plaintext[10:20]), ObjGetdigest(rr.Body.Bytes()))
}

// ---------------------------------------------------------------------------
// Conditional GET. Two of the four RFC 7232 preconditions are forwarded and two
// are dropped, which is a client-visible defect: the request that should be
// answered 304 or 412 is answered 200 with the whole body.
// ---------------------------------------------------------------------------

func TestObjGetGetObjectForwardsOnlyETagPreconditions(t *testing.T) {
	backend := new(MockS3Backend)
	h := ObjGetnewHandler(t, backend)

	plaintext := ObjGetpayload(64)
	ciphertext, metadata := ObjGetstore(t, h, "conditional", plaintext)

	var captured *s3.GetObjectInput
	backend.On("GetObject", mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) { captured = args.Get(1).(*s3.GetObjectInput) }).
		Return(ObjGetgetOutput(ciphertext, metadata), nil)

	req := httptest.NewRequest(http.MethodGet, "/b/conditional", nil)
	req.Header.Set("If-Match", `"etag-1"`)
	req.Header.Set("If-None-Match", `"etag-2"`)
	req.Header.Set("If-Modified-Since", "Wed, 21 Oct 2015 07:28:00 GMT")
	req.Header.Set("If-Unmodified-Since", "Wed, 21 Oct 2015 07:28:00 GMT")

	rr := ObjGetdo(h, req, "b", "conditional")

	require.Equal(t, http.StatusOK, rr.Code)
	require.NotNil(t, captured)
	assert.Equal(t, `"etag-1"`, aws.ToString(captured.IfMatch))
	assert.Equal(t, `"etag-2"`, aws.ToString(captured.IfNoneMatch))

	// DEFECT (pinned, not endorsed): the date preconditions are dropped, so a
	// client revalidating a cache entry gets 200 and the whole body where S3
	// answers 304, and If-Unmodified-Since never produces the 412 it exists for.
	assert.Nil(t, captured.IfModifiedSince, "known defect: If-Modified-Since is dropped")
	assert.Nil(t, captured.IfUnmodifiedSince, "known defect: If-Unmodified-Since is dropped")
	assert.Equal(t, len(plaintext), rr.Body.Len(), "the full body is served instead of a 304")
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
		h := ObjGetnewHandler(t, backend)

		rr := ObjGetdo(h, httptest.NewRequest(http.MethodGet, "/b/k?partNumber=2", nil), "b", "k")

		assert.Equal(t, http.StatusNotImplemented, rr.Code)
		backend.AssertNotCalled(t, "GetObject", mock.Anything, mock.Anything)
	})

	// DEFECT (pinned): the response-* overrides are what presigned download URLs
	// use to name a file and set its type. All six are accepted and dropped.
	t.Run("the six response overrides are accepted and dropped", func(t *testing.T) {
		backend := new(MockS3Backend)
		h := ObjGetnewHandler(t, backend)

		plaintext := ObjGetpayload(2048)
		ciphertext, metadata := ObjGetstore(t, h, "k", plaintext)

		var captured *s3.GetObjectInput
		backend.On("GetObject", mock.Anything, mock.Anything).
			Run(func(args mock.Arguments) { captured = args.Get(1).(*s3.GetObjectInput) }).
			Return(ObjGetgetOutput(ciphertext, metadata), nil)

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
// HEAD.
// ---------------------------------------------------------------------------

// The length HEAD reports has to be the length GET delivers. The stored object
// carries 28 bytes of framing per segment and a 40-byte trailer, and the
// conversion back is a pure function of the stored length - no key, no round
// trip - which is what lets HEAD answer in plaintext terms at all.
func TestObjGetHeadObjectReportsPlaintextContentLength(t *testing.T) {
	for _, size := range []int{0, 1, 4096, dataencryption.SegmentSize + 1} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			backend := new(MockS3Backend)
			h := ObjGetnewHandler(t, backend)

			key := "head-" + strconv.Itoa(size)
			plaintext := ObjGetpayload(size)
			ciphertext, metadata := ObjGetstore(t, h, key, plaintext)

			expected, err := orchestration.PlaintextSize(int64(len(ciphertext)))
			require.NoError(t, err)
			require.Equal(t, int64(size), expected, "PlaintextSize disagrees with the stored object")

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

// HEAD does not describe an object it cannot read. There is no fallback that
// reports the stored length as if it were the plaintext length: a client that
// sizes a buffer from a HEAD would get a number the GET never delivers.
func TestObjGetHeadObjectRefusesWhatItCannotSize(t *testing.T) {
	reference := new(MockS3Backend)
	_, stored := ObjGetstore(t, ObjGetnewHandler(t, reference), "k", ObjGetpayload(4096))

	cases := map[string]struct {
		metadata map[string]string
		stored   int64
	}{
		"unencrypted":              {nil, 1234},
		"previous_format":          {ObjGetmutateMetadata(stored, map[string]string{"s3ep-dek-algorithm": "aes-gcm"}), 1234},
		"shorter_than_the_trailer": {stored, dataencryption.TrailerSize - 1},
		// Room for a second segment's framing but not for a byte inside it: no
		// writer of this format produces that length.
		"no_chain_lands_on_that_length": {
			stored,
			dataencryption.SegmentSize + 2*dataencryption.SegmentOverhead + dataencryption.TrailerSize,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			backend := new(MockS3Backend)
			h := ObjGetnewHandler(t, backend)
			backend.On("HeadObject", mock.Anything, mock.Anything).Return(&s3.HeadObjectOutput{
				ContentLength: aws.Int64(tc.stored),
				Metadata:      tc.metadata,
			}, nil)

			rr := ObjGetdo(h, httptest.NewRequest(http.MethodHead, "/b/k", nil), "b", "k")

			require.Equal(t, http.StatusForbidden, rr.Code)
			assert.Equal(t, "InvalidObjectState", ObjGetparseError(t, rr.Body.Bytes()).Code)
			assert.Empty(t, rr.Header().Get("Content-Length"), "no length may be stated for an unreadable object")
		})
	}

	// Under the pass-through provider the stored length is the plaintext length,
	// so the same answer is served unchanged.
	t.Run("pass_through_provider_reports_the_stored_length", func(t *testing.T) {
		backend := new(MockS3Backend)
		h := ObjGetnewPassThroughHandler(t, backend)
		backend.On("HeadObject", mock.Anything, mock.Anything).Return(&s3.HeadObjectOutput{
			ContentLength: aws.Int64(1234),
		}, nil)

		rr := ObjGetdo(h, httptest.NewRequest(http.MethodHead, "/b/k", nil), "b", "k")

		require.Equal(t, http.StatusOK, rr.Code)
		assert.Equal(t, "1234", rr.Header().Get("Content-Length"))
	})
}

func TestObjGetHeadObjectPassesThroughEntityHeadersAndMetadata(t *testing.T) {
	backend := new(MockS3Backend)
	h := ObjGetnewHandler(t, backend)

	ciphertext, metadata := ObjGetstore(t, h, "k", ObjGetpayload(1000))
	metadata["user"] = "value"

	modified := time.Date(2023, 11, 14, 22, 13, 20, 0, time.UTC)
	backend.On("HeadObject", mock.Anything, mock.Anything).Return(&s3.HeadObjectOutput{
		ContentLength:      aws.Int64(int64(len(ciphertext))),
		ContentType:        aws.String("image/png"),
		ETag:               aws.String(`"stored-etag"`),
		LastModified:       aws.Time(modified),
		VersionId:          aws.String("version-7"),
		ContentEncoding:    aws.String("gzip"),
		ContentDisposition: aws.String(`attachment; filename="x.png"`),
		ContentLanguage:    aws.String("de-DE"),
		CacheControl:       aws.String("max-age=99"),
		ChecksumSHA256:     aws.String("AAAAAA=="),
		Metadata:           metadata,
	}, nil)

	rr := ObjGetdo(h, httptest.NewRequest(http.MethodHead, "/b/k", nil), "b", "k")

	require.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "1000", rr.Header().Get("Content-Length"))
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
			h := ObjGetnewHandler(t, backend)
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
	h := ObjGetnewHandler(t, backend)

	ciphertext, metadata := ObjGetstore(t, h, "k", ObjGetpayload(1000))

	var captured *s3.HeadObjectInput
	backend.On("HeadObject", mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) { captured = args.Get(1).(*s3.HeadObjectInput) }).
		Return(&s3.HeadObjectOutput{
			ContentLength: aws.Int64(int64(len(ciphertext))),
			ETag:          aws.String(`"stored-etag"`),
			Metadata:      metadata,
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

// ObjGetcloseErrReader delivers its payload and then fails on Close, the way the
// decrypting reader reports a chain that did not authenticate.
type ObjGetcloseErrReader struct {
	io.Reader
	err error
}

func (r ObjGetcloseErrReader) Close() error { return r.err }

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

// The decrypting reader reports a chain that did not add up from Close, which
// runs after the last byte is on the wire. All the handler can do is log it.
func TestObjGetWriteGetObjectResponseCloseFailureIsSwallowed(t *testing.T) {
	h := newResponseTestHandler(nil)
	payload := ObjGetpayload(512)

	rr := httptest.NewRecorder()
	h.writeGetObjectResponse(rr, &s3.GetObjectOutput{
		Body:          ObjGetcloseErrReader{Reader: bytes.NewReader(payload), err: errors.New("object failed authentication")},
		ContentLength: aws.Int64(int64(len(payload))),
	}, true)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, ObjGetdigest(payload), ObjGetdigest(rr.Body.Bytes()))
}

// A backend body whose Close fails after the object was delivered must not
// damage the response: the bytes are already correct and the status is out.
func TestObjGetGetObjectBackendBodyCloseFailureStillDelivers(t *testing.T) {
	backend := new(MockS3Backend)
	h := ObjGetnewHandler(t, backend)

	plaintext := ObjGetpayload(4096)
	ciphertext, metadata := ObjGetstore(t, h, "close-error", plaintext)

	out := ObjGetgetOutput(ciphertext, metadata)
	out.Body = ObjGetcloseErrReader{Reader: bytes.NewReader(ciphertext), err: errors.New("connection reset on close")}
	backend.On("GetObject", mock.Anything, mock.Anything).Return(out, nil)

	rr := ObjGetdo(h, httptest.NewRequest(http.MethodGet, "/b/close-error", nil), "b", "close-error")

	require.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, ObjGetdigest(plaintext), ObjGetdigest(rr.Body.Bytes()))
}

// An object recorded as stored by the pass-through provider is still an object
// this proxy did not seal, so an encrypting provider refuses it instead of
// serving the stored bytes and declaring a length it made up for them.
func TestObjGetGetObjectNoneAlgorithmIsRefused(t *testing.T) {
	backend := new(MockS3Backend)
	h := ObjGetnewHandler(t, backend)

	stored := ObjGetpayload(1000)
	backend.On("GetObject", mock.Anything, mock.Anything).Return(ObjGetgetOutput(stored, map[string]string{
		"s3ep-encrypted-dek":   "ZW5jcnlwdGVkLWRlaw==",
		"s3ep-dek-algorithm":   "none",
		"s3ep-kek-fingerprint": "none-provider-fingerprint",
	}), nil)

	rr := ObjGetdo(h, httptest.NewRequest(http.MethodGet, "/b/none-algo", nil), "b", "none-algo")

	require.Equal(t, http.StatusForbidden, rr.Code)
	assert.Equal(t, "InvalidObjectState", ObjGetparseError(t, rr.Body.Bytes()).Code)
	assert.Empty(t, rr.Header().Get("Content-Length"))
	assert.NotContains(t, rr.Body.String(), string(stored[:8]))
}
