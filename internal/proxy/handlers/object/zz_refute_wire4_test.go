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

	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption/dataencryption"
	"github.com/stretchr/testify/require"
)

// The chunk header declares 6 segments, the body carries 4, Content-Length
// counts exactly the bytes written, the connection stays open. Nothing cancels
// the request context - the HTTP message is complete, only the aws-chunked
// payload is short. No X-Amz-Decoded-Content-Length.
func TestZZWireShortChunkLiveContext(t *testing.T) {
	backend := new(MockS3Backend)
	h := ObjPutnewHandler(t, backend, ObjPutopts{awsChunked: true, segmentSize: 2 * dataencryption.SegmentSize})
	rec := zzWire(backend)
	ln := zzServe(t, h)

	declared := 6 * dataencryption.SegmentSize
	sent := ObjPutpayload(4 * dataencryption.SegmentSize)

	var framed bytes.Buffer
	fmt.Fprintf(&framed, "%x;chunk-signature=%064x\r\n", declared, 0)
	framed.Write(sent)

	conn, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	defer conn.Close()
	head := fmt.Sprintf("PUT /b/k HTTP/1.1\r\nHost: x\r\nContent-Encoding: aws-chunked\r\n"+
		"X-Amz-Content-Sha256: STREAMING-UNSIGNED-PAYLOAD-TRAILER\r\nContent-Length: %d\r\n\r\n", framed.Len())
	_, err = conn.Write([]byte(head))
	require.NoError(t, err)
	_, err = conn.Write(framed.Bytes())
	require.NoError(t, err)

	require.NoError(t, conn.SetReadDeadline(time.Now().Add(10*time.Second)))
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodPut})
	require.NoError(t, err)
	body, _ := io.ReadAll(resp.Body)

	rec.mu.Lock()
	defer rec.mu.Unlock()
	t.Logf("status=%d body=%q abort=%v complete=%v completeCtxErr=%v partCtxErr=%v",
		resp.StatusCode, string(body), rec.abort, rec.complete != nil, rec.completeCtxErr, rec.partCtxErr)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.NotNil(t, rec.complete)
	require.NoError(t, rec.completeCtxErr)

	var joined []byte
	for i := 1; i <= len(rec.parts); i++ {
		joined = append(joined, rec.parts[i]...)
	}
	reader, oerr := h.encryptionMgr.OpenSegmented("k", rec.create.Metadata, bytes.NewReader(joined))
	require.NoError(t, oerr)
	plain, rerr := io.ReadAll(reader)
	require.NoError(t, rerr, "the committed object must verify for the truncation to be invisible")
	require.NoError(t, reader.Close())
	t.Logf("committed plaintext=%d, client framing declared %d, ETag=%s", len(plain), declared, resp.Header.Get("ETag"))
	require.Less(t, len(plain), declared)
}
