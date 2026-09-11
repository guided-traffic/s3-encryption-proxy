package object

import (
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

// The client promises 6 segments of payload in Content-Length, sends 4 of them,
// then the socket dies. No X-Amz-Decoded-Content-Length.
func TestZZWireHangUpMidPayload(t *testing.T) {
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

	payload := ObjPutpayload(6 * dataencryption.SegmentSize)
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
	// Header line plus 4 segments of payload, then hang up mid-object.
	cut := bytes.IndexByte(framed.Bytes(), '\n') + 1 + 4*dataencryption.SegmentSize
	_, err = conn.Write(framed.Bytes()[:cut])
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
	abort, complete, create := rec.abort, rec.complete, rec.create
	rec.mu.Unlock()
	t.Logf("MIDCUT abort=%v completeCalled=%v", abort != nil, complete != nil)
	require.NotNil(t, complete, "the upload was committed")
	reader, oerr := h.encryptionMgr.OpenSegmented("k", create.Metadata, bytes.NewReader(rec.ObjPutjoinParts()))
	require.NoError(t, oerr)
	plain, rerr := io.ReadAll(reader)
	require.NoError(t, rerr)
	require.NoError(t, reader.Close())
	t.Logf("MIDCUT committed plaintext=%d of %d bytes, opens and verifies clean", len(plain), len(payload))
}
