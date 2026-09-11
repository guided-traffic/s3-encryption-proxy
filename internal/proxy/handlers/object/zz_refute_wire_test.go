package object

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption/dataencryption"
	"github.com/stretchr/testify/require"
)

// Real net/http server, real socket: aws-chunked framing truncated after one
// data chunk, Content-Length counts exactly the framed bytes written, no
// X-Amz-Decoded-Content-Length, connection stays open.
func TestZZWireTruncatedAWSChunked(t *testing.T) {
	backend := new(MockS3Backend)
	h := ObjPutnewHandler(t, backend, ObjPutopts{awsChunked: true, segmentSize: 2 * dataencryption.SegmentSize})
	rec := ObjPutwireMultipart(backend, "auto-id")

	r := mux.NewRouter()
	r.PathPrefix("/{bucket}/{key:.*}").Handler(http.HandlerFunc(h.Handle))
	srv := &http.Server{Handler: r, ReadHeaderTimeout: 5 * time.Second}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()

	payload := ObjPutpayload(3 * dataencryption.SegmentSize)
	var framed bytes.Buffer
	fmt.Fprintf(&framed, "%x;chunk-signature=%064x\r\n", len(payload), 0)
	framed.Write(payload)
	framed.WriteString("\r\n")

	conn, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	defer conn.Close()

	head := fmt.Sprintf("PUT /b/k HTTP/1.1\r\nHost: x\r\nContent-Encoding: aws-chunked\r\n"+
		"X-Amz-Content-Sha256: STREAMING-UNSIGNED-PAYLOAD-TRAILER\r\nContent-Length: %d\r\n\r\n", framed.Len())
	_, err = conn.Write([]byte(head))
	require.NoError(t, err)
	_, err = conn.Write(framed.Bytes())
	require.NoError(t, err)
	// The connection stays open on purpose: nothing cancels the request context.

	require.NoError(t, conn.SetReadDeadline(time.Now().Add(10*time.Second)))
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodPut})
	require.NoError(t, err)
	body, _ := io.ReadAll(resp.Body)
	t.Logf("WIRE status=%d body=%s", resp.StatusCode, string(body))

	rec.mu.Lock()
	abort, complete, create := rec.abort, rec.complete, rec.create
	rec.mu.Unlock()
	t.Logf("WIRE abort=%v completeCalled=%v", abort != nil, complete != nil)
	if complete != nil {
		reader, oerr := h.encryptionMgr.OpenSegmented("k", create.Metadata, bytes.NewReader(rec.ObjPutjoinParts()))
		require.NoError(t, oerr)
		plain, rerr := io.ReadAll(reader)
		require.NoError(t, rerr)
		require.NoError(t, reader.Close())
		t.Logf("WIRE committed plaintext=%d bytes, verifies clean", len(plain))
	}
}

// Same, but the client hangs up mid-body instead (Content-Length promises the
// full framed size and the socket closes early).
func TestZZWireClientHangsUp(t *testing.T) {
	backend := new(MockS3Backend)
	h := ObjPutnewHandler(t, backend, ObjPutopts{awsChunked: true, segmentSize: 2 * dataencryption.SegmentSize})
	rec := ObjPutwireMultipart(backend, "auto-id")

	r := mux.NewRouter()
	r.PathPrefix("/{bucket}/{key:.*}").Handler(http.HandlerFunc(h.Handle))
	srv := &http.Server{Handler: r, ReadHeaderTimeout: 5 * time.Second}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()

	payload := ObjPutpayload(3 * dataencryption.SegmentSize)
	var framed bytes.Buffer
	fmt.Fprintf(&framed, "%x;chunk-signature=%064x\r\n", len(payload), 0)
	framed.Write(payload)
	framed.WriteString("\r\n")
	fmt.Fprintf(&framed, "0;chunk-signature=%064x\r\n\r\n", 0)

	conn, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)

	head := fmt.Sprintf("PUT /b/k HTTP/1.1\r\nHost: x\r\nContent-Encoding: aws-chunked\r\n"+
		"X-Amz-Content-Sha256: STREAMING-UNSIGNED-PAYLOAD-TRAILER\r\nContent-Length: %d\r\n\r\n", framed.Len())
	_, err = conn.Write([]byte(head))
	require.NoError(t, err)
	// Everything but the terminating chunk, then hang up.
	_, err = conn.Write(framed.Bytes()[:framed.Len()-70])
	require.NoError(t, err)
	_ = conn.Close()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		rec.mu.Lock()
		done := rec.complete != nil || rec.abort != nil
		rec.mu.Unlock()
		if done {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	rec.mu.Lock()
	abort, complete := rec.abort, rec.complete
	rec.mu.Unlock()
	t.Logf("HANGUP abort=%v completeCalled=%v", abort != nil, complete != nil)
}
