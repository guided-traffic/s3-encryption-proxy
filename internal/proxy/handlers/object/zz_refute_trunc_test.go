package object

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption/dataencryption"
	"github.com/stretchr/testify/require"
)

// A: aws-chunked framing that stops after one data chunk, no 0-chunk,
// no X-Amz-Decoded-Content-Length.
func TestZZTruncatedAWSChunkedNoDecodedLength(t *testing.T) {
	backend := new(MockS3Backend)
	h := ObjPutnewHandler(t, backend, ObjPutopts{awsChunked: true, segmentSize: 2 * dataencryption.SegmentSize})
	rec := ObjPutwireMultipart(backend, "auto-id")

	payload := ObjPutpayload(3 * dataencryption.SegmentSize) // 196608
	var framed bytes.Buffer
	fmt.Fprintf(&framed, "%x;chunk-signature=%064x\r\n", len(payload), 0)
	framed.Write(payload)
	framed.WriteString("\r\n")
	// no terminating 0-chunk

	req := httptest.NewRequest(http.MethodPut, "/b/k", bytes.NewReader(framed.Bytes()))
	req.Header.Set("Content-Encoding", "aws-chunked")
	req.Header.Set("X-Amz-Content-Sha256", "STREAMING-UNSIGNED-PAYLOAD-TRAILER")
	req.ContentLength = int64(framed.Len())

	rr := ObjPutdo(h, req, "b", "k")
	t.Logf("A status=%d body=%s", rr.Code, rr.Body.String())

	rec.mu.Lock()
	abort := rec.abort
	complete := rec.complete
	create := rec.create
	rec.mu.Unlock()
	t.Logf("A abort=%v completeCalled=%v", abort != nil, complete != nil)

	if rr.Code == http.StatusOK && complete != nil {
		stored := rec.ObjPutjoinParts()
		reader, err := h.encryptionMgr.OpenSegmented("k", create.Metadata, bytes.NewReader(stored))
		require.NoError(t, err)
		plain, err := io.ReadAll(reader)
		require.NoError(t, err, "trailer verification must pass for the truncation to be invisible")
		require.NoError(t, reader.Close())
		t.Logf("A committed plaintext bytes=%d (client framing declared %d payload bytes in one chunk)", len(plain), len(payload))
		t.Logf("A digest match with what arrived: %v", ObjPutdigest(plain) == ObjPutdigest(payload))
	}
	_ = aws.String
}

// B: unknown length (ContentLength -1) and a body that ends with
// io.ErrUnexpectedEOF - the "client hangs up mid-body" case.
func TestZZUnknownLengthUnexpectedEOF(t *testing.T) {
	backend := new(MockS3Backend)
	h := ObjPutnewHandler(t, backend, ObjPutopts{segmentSize: 2 * dataencryption.SegmentSize})
	rec := ObjPutwireMultipart(backend, "auto-id")

	payload := ObjPutpayload(3 * dataencryption.SegmentSize)
	req := httptest.NewRequest(http.MethodPut, "/b/k", &ObjPuterrReader{prefix: payload, err: io.ErrUnexpectedEOF})
	req.ContentLength = -1

	rr := ObjPutdo(h, req, "b", "k")
	t.Logf("B status=%d body=%s", rr.Code, rr.Body.String())

	rec.mu.Lock()
	abort := rec.abort
	complete := rec.complete
	create := rec.create
	rec.mu.Unlock()
	t.Logf("B abort=%v completeCalled=%v", abort != nil, complete != nil)

	if rr.Code == http.StatusOK && complete != nil {
		stored := rec.ObjPutjoinParts()
		reader, err := h.encryptionMgr.OpenSegmented("k", create.Metadata, bytes.NewReader(stored))
		require.NoError(t, err)
		plain, err := io.ReadAll(reader)
		require.NoError(t, err)
		require.NoError(t, reader.Close())
		t.Logf("B committed plaintext bytes=%d of %d, digest match=%v", len(plain), len(payload), ObjPutdigest(plain) == ObjPutdigest(payload))
	}
}

// C: control - same as B but with a declared plaintext length.
func TestZZKnownLengthUnexpectedEOF(t *testing.T) {
	backend := new(MockS3Backend)
	h := ObjPutnewHandler(t, backend, ObjPutopts{segmentSize: 2 * dataencryption.SegmentSize})
	rec := ObjPutwireMultipart(backend, "auto-id")

	payload := ObjPutpayload(3 * dataencryption.SegmentSize)
	req := httptest.NewRequest(http.MethodPut, "/b/k", &ObjPuterrReader{prefix: payload, err: io.ErrUnexpectedEOF})
	req.ContentLength = int64(len(payload)) + 100000 // declared more than arrives, > segmentSize

	rr := ObjPutdo(h, req, "b", "k")
	rec.mu.Lock()
	abort := rec.abort
	complete := rec.complete
	rec.mu.Unlock()
	t.Logf("C status=%d abort=%v completeCalled=%v body=%s", rr.Code, abort != nil, complete != nil, rr.Body.String())
}
