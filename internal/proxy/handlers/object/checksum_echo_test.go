package object

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"hash/crc32"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption/dataencryption"
)

// ---------------------------------------------------------------------------
// x-amz-checksum-crc32c on a write (ADR 0003 D16).
//
// The seal computes this value for the trailer whatever happens, so answering it
// costs a header. What it buys is the other half of the upload leg: the proxy
// verifies what a client declares, and this lets the client confirm what the
// proxy received.
//
// Every expectation here is computed from the payload with the standard library,
// not with the codec's own helper: a test that asks the implementation what the
// answer should be proves only that it is consistent with itself.
// ---------------------------------------------------------------------------

// ObjCrcwant is what S3 states for a CRC32C: base64 of the four raw bytes, big
// endian, over the plaintext.
func ObjCrcwant(plaintext []byte) string {
	sum := crc32.Checksum(plaintext, crc32.MakeTable(crc32.Castagnoli))
	var raw [4]byte
	binary.BigEndian.PutUint32(raw[:], sum)
	return base64.StdEncoding.EncodeToString(raw[:])
}

// A single-request PUT answers the checksum of the plaintext it received, and a
// read of the same object answers the same value. The round trip is the property
// that matters: two answers about one object that disagree are worse than one
// answer.
func TestObjCrcSingleRequestPutAnswersThePlaintextChecksum(t *testing.T) {
	for name, size := range map[string]int{
		"a few bytes":           5,
		"exactly one segment":   dataencryption.SegmentSize,
		"one segment plus one":  dataencryption.SegmentSize + 1,
		"several whole buffers": 3 * dataencryption.SegmentSize,
	} {
		t.Run(name, func(t *testing.T) {
			backend := new(MockS3Backend)
			h := ObjPutnewHandler(t, backend, ObjPutopts{segmentSize: 8 * dataencryption.SegmentSize})
			ObjPutcapturePut(backend, `"stored-etag"`, "")

			payload := ObjPutpayload(size)
			rr := ObjPutdo(h, httptest.NewRequest(http.MethodPut, "/b/k", bytes.NewReader(payload)), "b", "k")

			require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
			assert.Equal(t, ObjCrcwant(payload), rr.Header().Get("x-amz-checksum-crc32c"))
		})
	}
}

// The empty object has a checksum like any other, and it is not the absence of
// one: CRC32C of nothing is a defined value and a client comparing against it
// must not be told nothing.
func TestObjCrcAnEmptyObjectStillAnswersAChecksum(t *testing.T) {
	backend := new(MockS3Backend)
	h := ObjPutnewHandler(t, backend, ObjPutopts{})
	ObjPutcapturePut(backend, `"stored-etag"`, "")

	rr := ObjPutdo(h, httptest.NewRequest(http.MethodPut, "/b/k", bytes.NewReader(nil)), "b", "k")

	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	assert.Equal(t, ObjCrcwant(nil), rr.Header().Get("x-amz-checksum-crc32c"))
	assert.Equal(t, "AAAAAA==", rr.Header().Get("x-amz-checksum-crc32c"),
		"the CRC32C of an empty plaintext is zero, and zero is a value")
}

// Above the single-request ceiling the object is written by the internal
// producer, which accumulates the same value part by part. A client must not be
// able to tell which path wrote its object from the checksum it gets back.
func TestObjCrcTheProducerAnswersTheSameChecksumAsAPut(t *testing.T) {
	payload := ObjPutpayload(3*dataencryption.SegmentSize + 17)

	backend := new(MockS3Backend)
	h := ObjPutnewHandler(t, backend, ObjPutopts{segmentSize: dataencryption.SegmentSize})
	ObjPutwireMultipart(backend, "auto-id")

	rr := ObjPutdo(h, httptest.NewRequest(http.MethodPut, "/b/k", bytes.NewReader(payload)), "b", "k")

	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	backend.AssertNotCalled(t, "PutObject", mock.Anything, mock.Anything)
	assert.Equal(t, ObjCrcwant(payload), rr.Header().Get("x-amz-checksum-crc32c"),
		"the producer path and the single-request path describe the same plaintext")
}

// What a write answered, a read answers again. This is the assertion that would
// catch a value taken from the wrong place - the ciphertext, a part, the
// backend's own idea of the object.
func TestObjCrcAWriteAndAReadAgreeOnTheChecksum(t *testing.T) {
	payload := ObjGetpayload(2*dataencryption.SegmentSize + 9)

	backend := new(MockS3Backend)
	h := ObjGetnewHandler(t, backend)
	ciphertext, metadata := ObjGetstore(t, h, "k", payload)
	ObjGetserve(backend, ciphertext, metadata)

	rr := ObjGetdo(h, httptest.NewRequest(http.MethodGet, "/b/k", nil), "b", "k")

	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	assert.Equal(t, ObjCrcwant(payload), rr.Header().Get("x-amz-checksum-crc32c"))
	assert.Equal(t, ObjGetdigest(payload), ObjGetdigest(rr.Body.Bytes()))
}

// The checksum describes the plaintext, never the bytes the backend holds. Worth
// its own assertion because both values are available at the moment the header
// is written, and the wrong one would look perfectly plausible.
func TestObjCrcIsNotTheChecksumOfTheStoredBytes(t *testing.T) {
	backend := new(MockS3Backend)
	h := ObjPutnewHandler(t, backend, ObjPutopts{})
	stored := ObjPutcapturePut(backend, `"stored-etag"`, "")

	payload := ObjPutpayload(4096)
	rr := ObjPutdo(h, httptest.NewRequest(http.MethodPut, "/b/k", bytes.NewReader(payload)), "b", "k")

	require.Equal(t, http.StatusOK, rr.Code)
	answered := rr.Header().Get("x-amz-checksum-crc32c")
	assert.Equal(t, ObjCrcwant(payload), answered)
	assert.NotEqual(t, ObjCrcwant(stored.body), answered,
		"the stored bytes are the ciphertext and describe nothing the client sent")
}

// Under the exit provider the proxy seals nothing, so it has nothing of its own
// to state. An absent header is the honest answer; a value copied from somewhere
// else would not be.
func TestObjCrcTheExitProviderStatesNoChecksum(t *testing.T) {
	backend := new(MockS3Backend)
	h := ObjPutnewHandler(t, backend, ObjPutopts{providerType: "exit"})
	ObjPutcapturePut(backend, `"stored-etag"`, "")

	rr := ObjPutdo(h, httptest.NewRequest(http.MethodPut, "/b/k", bytes.NewReader(ObjPutpayload(1024))), "b", "k")

	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	assert.Empty(t, rr.Header().Get("x-amz-checksum-crc32c"))
}

// A refused upload states no checksum, because there is no object to describe.
func TestObjCrcARefusedUploadStatesNoChecksum(t *testing.T) {
	backend := new(MockS3Backend)
	h := ObjPutnewHandler(t, backend, ObjPutopts{})
	ObjPutcapturePut(backend, `"stored-etag"`, "")

	payload := ObjPutpayload(2048)
	req := httptest.NewRequest(http.MethodPut, "/b/k", bytes.NewReader(payload))
	req.Header.Set("x-amz-checksum-crc32c", ObjCrcwant(ObjPutpayload(1024)))

	rr := ObjPutdo(h, req, "b", "k")

	require.Equal(t, http.StatusBadRequest, rr.Code, rr.Body.String())
	assert.Equal(t, "BadDigest", ObjPutparseError(t, rr.Body.Bytes()).Code)
	assert.Empty(t, rr.Header().Get("x-amz-checksum-crc32c"))
}

// A client that declares the right CRC32C is told the same value back. The two
// are computed by different code over the same bytes - the verifier's hash and
// the seal's running sum - so agreeing is a real cross-check.
func TestObjCrcADeclaredChecksumAndTheAnsweredOneAgree(t *testing.T) {
	backend := new(MockS3Backend)
	h := ObjPutnewHandler(t, backend, ObjPutopts{})
	ObjPutcapturePut(backend, `"stored-etag"`, "")

	payload := ObjPutpayload(9000)
	req := httptest.NewRequest(http.MethodPut, "/b/k", bytes.NewReader(payload))
	req.Header.Set("x-amz-checksum-crc32c", ObjCrcwant(payload))

	rr := ObjPutdo(h, req, "b", "k")

	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	assert.Equal(t, ObjCrcwant(payload), rr.Header().Get("x-amz-checksum-crc32c"))
}

// A ranged read still answers none: a checksum over part of an object says
// nothing about the object, and this is the one read that must stay silent.
func TestObjCrcARangedReadStatesNoChecksum(t *testing.T) {
	backend := new(MockS3Backend)
	h := ObjGetnewHandler(t, backend)
	stored, metadata := ObjGetrangeStore(t, h, "k", ObjGetpayload(1<<20))

	backend.On("GetObject", mock.Anything, mock.Anything).
		Return(ObjGetrangeAnswer(t, stored, metadata, "bytes=0-65603"), nil)

	rr := ObjGetdo(h, ObjGetrangeRequest("k", "bytes=0-99"), "b", "k")

	require.Equal(t, http.StatusPartialContent, rr.Code, rr.Body.String())
	assert.Empty(t, rr.Header().Get("x-amz-checksum-crc32c"))
}
