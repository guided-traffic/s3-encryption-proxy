package object

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption/dataencryption"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// The entity-tag marker, with fixtures that have the shape the marker keys on.
//
// Every other entity-tag fixture in this package is a name — "stored-etag",
// "mpu-etag" — so the forward map never fires against them and the whole marker
// could be missing, or applied where it must not be, without one of them
// failing. These carry a real thirty-two-hex digest instead (ADR 0032).
// ---------------------------------------------------------------------------

// ObjTagStoredDigest is what a backend answers for an object it stored in one
// request: the MD5 of the stored bytes, which for an encrypted object is the
// ciphertext and not anything the client can compute.
const ObjTagStoredDigest = `"2c52a8e3b689c5ea7f55444e2000b35a"`

// ObjTagMarked is the same tag as this proxy answers it.
const ObjTagMarked = `"2c52a8e3b689c5ea7f55444e2000b35a-0"`

// ObjTagserve wires a whole-object read whose backend entity tag is a digest.
func ObjTagserve(backend *MockS3Backend, stored []byte, metadata map[string]string) {
	ObjServeStored(backend, stored, s3.GetObjectOutput{
		ContentType:  aws.String("application/octet-stream"),
		ETag:         aws.String(ObjTagStoredDigest),
		LastModified: aws.Time(time.Unix(1700000000, 0).UTC()),
		Metadata:     metadata,
	})
}

// Every verb that states an object's entity tag states the marked one. A client
// reads the bare shape as a promise that the value is the MD5 of its own
// content, and under encryption it never is (ADR 0032 D2, D3).
func TestObjTagEveryObjectVerbAnswersTheMarker(t *testing.T) {
	t.Run("single-request PUT", func(t *testing.T) {
		backend := new(MockS3Backend)
		h := ObjPutnewHandler(t, backend, ObjPutopts{})
		ObjPutcapturePut(backend, ObjTagStoredDigest, "")

		rr := ObjPutdo(h, httptest.NewRequest(http.MethodPut, "/b/k", bytes.NewReader(ObjPutpayload(1024))), "b", "k")

		require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
		assert.Equal(t, ObjTagMarked, rr.Header().Get("ETag"))
	})

	// One segment is one backend read, more than one segment is the tail-first
	// pair: both halves answer the same tag and both go through the marker.
	for name, size := range map[string]int{
		"whole-object GET, one backend read":  dataencryption.SegmentSize,
		"whole-object GET, tail-first pair":   3*dataencryption.SegmentSize + 17,
		"whole-object GET of an empty object": 0,
	} {
		t.Run(name, func(t *testing.T) {
			backend := new(MockS3Backend)
			h := ObjGetnewHandler(t, backend)
			ciphertext, metadata := ObjGetstore(t, h, "k", ObjGetpayload(size))
			ObjTagserve(backend, ciphertext, metadata)

			rr := ObjGetdo(h, httptest.NewRequest(http.MethodGet, "/b/k", nil), "b", "k")

			require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
			assert.Equal(t, ObjTagMarked, rr.Header().Get("ETag"))
		})
	}

	t.Run("HEAD", func(t *testing.T) {
		backend := new(MockS3Backend)
		h := ObjGetnewHandler(t, backend)
		ciphertext, metadata := ObjGetstore(t, h, "k", ObjGetpayload(2*dataencryption.SegmentSize))
		ObjTagserve(backend, ciphertext, metadata)

		rr := ObjGetdo(h, httptest.NewRequest(http.MethodHead, "/b/k", nil), "b", "k")

		require.Equal(t, http.StatusOK, rr.Code)
		assert.Equal(t, ObjTagMarked, rr.Header().Get("ETag"))
	})

	t.Run("ranged GET", func(t *testing.T) {
		backend := new(MockS3Backend)
		h := ObjGetnewHandler(t, backend)
		stored, metadata := ObjGetrangeStore(t, h, "k", ObjGetpayload(1<<20))

		// One segment plus the trailer: the window the planner asks for at
		// offset 0, whatever the client's range.
		answer := ObjGetrangeAnswer(t, stored, metadata, "bytes=0-65603")
		answer.ETag = aws.String(ObjTagStoredDigest)
		backend.On("GetObject", mock.Anything, mock.Anything).Return(answer, nil)

		rr := ObjGetdo(h, ObjGetrangeRequest("k", "bytes=0-99"), "b", "k")

		require.Equal(t, http.StatusPartialContent, rr.Code, rr.Body.String())
		assert.Equal(t, ObjTagMarked, rr.Header().Get("ETag"))
	})
}

// The load-bearing negative. A whole-object read above one segment pins its
// second request to the entity tag its first answer carried, and that pin is the
// backend's own value going back to the backend. Marking it would answer 412 to
// every whole-object GET of an object larger than one segment.
func TestObjTagTheInternalPinIsNeverMarked(t *testing.T) {
	backend := new(MockS3Backend)
	h := ObjGetnewHandler(t, backend)
	plaintext := ObjGetpayload(3*dataencryption.SegmentSize + 17)
	ciphertext, metadata := ObjGetstore(t, h, "k", plaintext)
	ObjTagserve(backend, ciphertext, metadata)

	rr := ObjGetdo(h, httptest.NewRequest(http.MethodGet, "/b/k", nil), "b", "k")

	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	assert.Equal(t, ObjGetdigest(plaintext), ObjGetdigest(rr.Body.Bytes()))

	var reads []*s3.GetObjectInput
	for _, call := range backend.Calls {
		if call.Method == "GetObject" {
			reads = append(reads, call.Arguments.Get(1).(*s3.GetObjectInput))
		}
	}
	require.Len(t, reads, 2)
	assert.Equal(t, ObjTagStoredDigest, aws.ToString(reads[1].IfMatch),
		"the pin is the backend's own tag, unmarked: the backend has never heard of the marker")
	assert.Equal(t, ObjTagMarked, rr.Header().Get("ETag"),
		"and the client still gets the marked one")
}

// The same negative one level down: any precondition the proxy sets on a read of
// its own carries the backend's tag, never the marked one. The backend has never
// heard of the marker and would answer 412 to it.
func TestObjTagAProxyPinNeverCarriesTheMarker(t *testing.T) {
	backend := new(MockS3Backend)
	h := ObjGetnewHandler(t, backend)
	stored, metadata := ObjGetrangeStore(t, h, "k", ObjGetpayload(1<<20))

	answer := ObjGetrangeAnswer(t, stored, metadata, "bytes=0-65603")
	answer.ETag = aws.String(ObjTagStoredDigest)
	backend.On("GetObject", mock.Anything, mock.Anything).Return(answer, nil)

	rr := ObjGetdo(h, ObjGetrangeRequest("k", "bytes=0-99"), "b", "k")
	require.Equal(t, http.StatusPartialContent, rr.Code, rr.Body.String())

	for _, call := range backend.Calls {
		if call.Method != "GetObject" {
			continue
		}
		in := call.Arguments.Get(1).(*s3.GetObjectInput)
		if in.IfMatch != nil {
			assert.Equal(t, ObjTagStoredDigest, aws.ToString(in.IfMatch),
				"a pin the proxy sets itself carries the backend's tag")
		}
	}
}

// A tag the client sends back is unmarked before it reaches the backend, so a
// client that returns what it was given revalidates against the object it was
// given it for (ADR 0032 D4).
func TestObjTagPreconditionsAreUnmarkedOnTheWayOut(t *testing.T) {
	cases := map[string]struct{ sent, want string }{
		"a marked tag":           {ObjTagMarked, ObjTagStoredDigest},
		"an unmarked tag passes": {ObjTagStoredDigest, ObjTagStoredDigest},
		"a multipart tag passes": {`"2c52a8e3b689c5ea7f55444e2000b35a-3"`, `"2c52a8e3b689c5ea7f55444e2000b35a-3"`},
		"the wildcard passes":    {"*", "*"},
		"a list is unmarked entrywise": {
			`"2c52a8e3b689c5ea7f55444e2000b35a-0", "58d6a6131ee4337c8877716b2af05a6d-0"`,
			`"2c52a8e3b689c5ea7f55444e2000b35a", "58d6a6131ee4337c8877716b2af05a6d"`,
		},
	}

	for _, header := range []string{"If-Match", "If-None-Match"} {
		for name, tc := range cases {
			t.Run(header+"/"+name, func(t *testing.T) {
				backend := new(MockS3Backend)
				h := ObjGetnewHandler(t, backend)
				ciphertext, metadata := ObjGetstore(t, h, "k", ObjGetpayload(1024))

				var captured *s3.GetObjectInput
				backend.On("GetObject", mock.Anything, mock.Anything).
					Run(func(args mock.Arguments) { captured = args.Get(1).(*s3.GetObjectInput) }).
					Return(ObjGetgetOutput(ciphertext, metadata), nil)

				req := httptest.NewRequest(http.MethodGet, "/b/k", nil)
				req.Header.Set(header, tc.sent)
				ObjGetdo(h, req, "b", "k")

				require.NotNil(t, captured)
				got := aws.ToString(captured.IfMatch)
				if header == "If-None-Match" {
					got = aws.ToString(captured.IfNoneMatch)
				}
				assert.Equal(t, tc.want, got)
			})
		}
	}
}

// Under the exit provider the stored bytes are the plaintext, so the backend's
// entity tag is the truth about them and nothing is marked - the same reason its
// sizes pass through unmarked (ADR 0032 D7, ADR 0025).
func TestObjTagExitProviderAnswersTheBackendTag(t *testing.T) {
	t.Run("PUT", func(t *testing.T) {
		backend := new(MockS3Backend)
		h := ObjPutnewHandler(t, backend, ObjPutopts{providerType: "exit"})
		ObjPutcapturePut(backend, ObjTagStoredDigest, "")

		rr := ObjPutdo(h, httptest.NewRequest(http.MethodPut, "/b/k", bytes.NewReader(ObjPutpayload(1024))), "b", "k")

		require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
		assert.Equal(t, ObjTagStoredDigest, rr.Header().Get("ETag"))
	})

	t.Run("GET of a plain object", func(t *testing.T) {
		backend := new(MockS3Backend)
		h := ObjPutnewHandler(t, backend, ObjPutopts{providerType: "exit"})
		payload := ObjPutpayload(1024)
		backend.On("GetObject", mock.Anything, mock.Anything).Return(&s3.GetObjectOutput{
			Body:          io.NopCloser(bytes.NewReader(payload)),
			ContentLength: aws.Int64(int64(len(payload))),
			ETag:          aws.String(ObjTagStoredDigest),
		}, nil)

		rr := ObjPutdo(h, httptest.NewRequest(http.MethodGet, "/b/k", nil), "b", "k")

		require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
		assert.Equal(t, ObjTagStoredDigest, rr.Header().Get("ETag"))
	})
}

// The marker is a shape correction, not a value: the digits are the backend's,
// and only the suffix is the proxy's.
func TestObjTagTheMarkedValueIsTheBackendsOwn(t *testing.T) {
	backend := new(MockS3Backend)
	h := ObjPutnewHandler(t, backend, ObjPutopts{})
	ObjPutcapturePut(backend, ObjTagStoredDigest, "")

	rr := ObjPutdo(h, httptest.NewRequest(http.MethodPut, "/b/k", bytes.NewReader(ObjPutpayload(1024))), "b", "k")

	require.Equal(t, http.StatusOK, rr.Code)
	answered := rr.Header().Get("ETag")
	assert.Equal(t, fmt.Sprintf(`"%s-0"`, "2c52a8e3b689c5ea7f55444e2000b35a"), answered)
	assert.Contains(t, answered, "2c52a8e3b689c5ea7f55444e2000b35a",
		"the value is not replaced, only its shape is corrected")
}
