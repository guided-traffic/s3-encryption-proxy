package object

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/gorilla/mux"
	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption/dataencryption"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

type zzRec struct {
	mu         sync.Mutex
	parts      map[int][]byte
	partCtxErr map[int]error
	create     *s3.CreateMultipartUploadInput
	complete   *s3.CompleteMultipartUploadInput
	completeCtxErr error
	abort      bool
}

func zzWire(backend *MockS3Backend) *zzRec {
	r := &zzRec{parts: map[int][]byte{}, partCtxErr: map[int]error{}}
	backend.On("CreateMultipartUpload", mock.Anything, mock.Anything).Run(func(a mock.Arguments) {
		r.mu.Lock(); defer r.mu.Unlock()
		r.create = a.Get(1).(*s3.CreateMultipartUploadInput)
	}).Return(&s3.CreateMultipartUploadOutput{UploadId: aws.String("u")}, nil).Maybe()
	backend.On("UploadPart", mock.Anything, mock.Anything).Run(func(a mock.Arguments) {
		in := a.Get(1).(*s3.UploadPartInput)
		body, _ := io.ReadAll(in.Body)
		r.mu.Lock(); defer r.mu.Unlock()
		r.parts[int(aws.ToInt32(in.PartNumber))] = body
		r.partCtxErr[int(aws.ToInt32(in.PartNumber))] = a.Get(0).(context.Context).Err()
	}).Return(&s3.UploadPartOutput{ETag: aws.String(`"e"`)}, nil).Maybe()
	backend.On("CompleteMultipartUpload", mock.Anything, mock.Anything).Run(func(a mock.Arguments) {
		r.mu.Lock(); defer r.mu.Unlock()
		r.complete = a.Get(1).(*s3.CompleteMultipartUploadInput)
		r.completeCtxErr = a.Get(0).(context.Context).Err()
	}).Return(&s3.CompleteMultipartUploadOutput{ETag: aws.String(`"c"`)}, nil).Maybe()
	backend.On("AbortMultipartUpload", mock.Anything, mock.Anything).Run(func(a mock.Arguments) {
		r.mu.Lock(); defer r.mu.Unlock()
		r.abort = true
	}).Return(&s3.AbortMultipartUploadOutput{}, nil).Maybe()
	return r
}

func zzServe(t *testing.T, h *Handler) net.Listener {
	t.Helper()
	r := mux.NewRouter()
	r.PathPrefix("/{bucket}/{key:.*}").Handler(http.HandlerFunc(h.Handle))
	srv := &http.Server{Handler: r, ReadHeaderTimeout: 5 * time.Second}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return ln
}

func TestZZWireCtxAware(t *testing.T) {
	cases := []struct {
		name      string
		cutAt     func(framed []byte, headerEnd int) int // bytes to send
		hangUp    bool
	}{
		{"complete_http_message_truncated_framing", nil, false},
		{"hangup_mid_payload", func(f []byte, he int) int { return he + 4*dataencryption.SegmentSize }, true},
		{"hangup_before_terminator", func(f []byte, he int) int { return len(f) - 86 }, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			backend := new(MockS3Backend)
			h := ObjPutnewHandler(t, backend, ObjPutopts{awsChunked: true, segmentSize: 2 * dataencryption.SegmentSize})
			rec := zzWire(backend)
			ln := zzServe(t, h)

			payload := ObjPutpayload(6 * dataencryption.SegmentSize)
			var framed bytes.Buffer
			fmt.Fprintf(&framed, "%x;chunk-signature=%064x\r\n", len(payload), 0)
			headerEnd := framed.Len()
			framed.Write(payload)
			framed.WriteString("\r\n")
			if !tc.hangUp {
				// no terminator at all, Content-Length counts exactly what is sent
			} else {
				fmt.Fprintf(&framed, "0;chunk-signature=%064x\r\n\r\n", 0)
			}

			conn, err := net.Dial("tcp", ln.Addr().String())
			require.NoError(t, err)
			head := fmt.Sprintf("PUT /b/k HTTP/1.1\r\nHost: x\r\nContent-Encoding: aws-chunked\r\n"+
				"X-Amz-Content-Sha256: STREAMING-UNSIGNED-PAYLOAD-TRAILER\r\nContent-Length: %d\r\n\r\n", framed.Len())
			_, err = conn.Write([]byte(head))
			require.NoError(t, err)
			send := framed.Bytes()
			if tc.cutAt != nil {
				send = send[:tc.cutAt(framed.Bytes(), headerEnd)]
			}
			_, err = conn.Write(send)
			require.NoError(t, err)
			if tc.hangUp {
				_ = conn.Close()
			}

			deadline := time.Now().Add(5 * time.Second)
			for time.Now().Before(deadline) {
				rec.mu.Lock()
				done := rec.complete != nil || rec.abort
				rec.mu.Unlock()
				if done {
					break
				}
				time.Sleep(20 * time.Millisecond)
			}
			time.Sleep(100 * time.Millisecond)
			if !tc.hangUp {
				_ = conn.Close()
			}

			rec.mu.Lock()
			defer rec.mu.Unlock()
			t.Logf("%s: abort=%v complete=%v completeCtxErr=%v partCtxErr=%v",
				tc.name, rec.abort, rec.complete != nil, rec.completeCtxErr, rec.partCtxErr)
			if rec.complete != nil && rec.completeCtxErr == nil {
				var joined []byte
				for i := 1; i <= len(rec.parts); i++ {
					joined = append(joined, rec.parts[i]...)
				}
				reader, oerr := h.encryptionMgr.OpenSegmented("k", rec.create.Metadata, bytes.NewReader(joined))
				require.NoError(t, oerr)
				plain, rerr := io.ReadAll(reader)
				t.Logf("%s: committed with a live context; readback err=%v plaintext=%d of %d",
					tc.name, rerr, len(plain), len(payload))
				if rerr == nil {
					_ = reader.Close()
				}
			}
		})
	}
}
