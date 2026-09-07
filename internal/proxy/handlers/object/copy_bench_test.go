package object

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
)

// D-29 asks for the GET response copy path to be measured rather than decided by
// which middlewares happen to wrap the ResponseWriter. This file is the
// instrument: the repository had no benchmark that could answer the question,
// and after copyWithPooledBuffer started hiding ReadFrom there is no deployment
// configuration left in which net/http's ReadFrom path is even reached, so the
// comparison has to be made here.

// benchBodySize is what one iteration streams to the client.
const benchBodySize = 64 << 20

// benchReader yields benchBodySize bytes without touching memory. It stands in
// for the decrypting reader: not an *os.File and not a socket, so neither
// sendfile nor splice can ever apply to it - which is the whole point.
type benchReader struct{ left int64 }

func (r *benchReader) Read(p []byte) (int, error) {
	if r.left <= 0 {
		return 0, io.EOF
	}
	if int64(len(p)) > r.left {
		p = p[:r.left]
	}
	r.left -= int64(len(p))
	return len(p), nil
}

// hidingWriter reproduces the production wrappers: it embeds the interface and
// therefore hides ReadFrom, Flush, Hijack and Unwrap.
type hidingWriter struct{ http.ResponseWriter }

// forwardingWriter keeps net/http's ReadFrom reachable. It exists only so the
// benchmark has something to compare against; it is deliberately not shipped.
type forwardingWriter struct{ http.ResponseWriter }

func (w forwardingWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w forwardingWriter) ReadFrom(src io.Reader) (int64, error) {
	if rf, ok := w.ResponseWriter.(io.ReaderFrom); ok {
		return rf.ReadFrom(src)
	}
	return io.Copy(writerOnly{w.ResponseWriter}, src)
}

// copyWithSize is copyWithPooledBuffer with the buffer size as a parameter, so
// the shipped 128 KiB can be compared against its neighbours.
func copyWithSize(size int) func(io.Writer, io.Reader) (int64, error) {
	pool := sync.Pool{New: func() any { b := make([]byte, size); return &b }}
	return func(dst io.Writer, src io.Reader) (int64, error) {
		bufp := pool.Get().(*[]byte)
		defer pool.Put(bufp)
		return io.CopyBuffer(writerOnly{dst}, src, *bufp)
	}
}

func benchGetResponse(b *testing.B, useTLS bool, wrap func(http.ResponseWriter) http.ResponseWriter, copyFn func(io.Writer, io.Reader) (int64, error)) {
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if wrap != nil {
			w = wrap(w)
		}
		w.Header().Set("Content-Length", strconv.FormatInt(benchBodySize, 10))
		w.WriteHeader(http.StatusOK)
		if _, err := copyFn(w, &benchReader{left: benchBodySize}); err != nil {
			b.Error(err)
		}
	})

	var srv *httptest.Server
	if useTLS {
		srv = httptest.NewTLSServer(h)
	} else {
		srv = httptest.NewServer(h)
	}
	defer srv.Close()
	client := srv.Client()

	b.SetBytes(benchBodySize)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp, err := client.Get(srv.URL)
		if err != nil {
			b.Fatal(err)
		}
		if _, err := io.Copy(io.Discard, resp.Body); err != nil {
			b.Fatal(err)
		}
		_ = resp.Body.Close()
	}
}

// BenchmarkGetResponseCopy answers D-29: the pooled buffer versus net/http's
// ReadFrom, with and without a middleware wrapper, on HTTP/1 and on TLS.
//
// Decision rule fixed before the run: keep the pooled buffer unless a ReadFrom
// cell beats the 128 KiB pooled cell by more than 3 % in MB/s AND does not lose
// on allocs/op, in the h1 no-wrapper cell - the only cell where ReadFrom can
// differ at all.
//
// Note the instrument's bias: httptest over loopback exaggerates syscall cost
// relative to a real network path. That is the right bias for this question,
// because syscall count and per-request allocation are exactly what separate the
// two copy paths, and the wrong instrument for absolute MB/s.
func BenchmarkGetResponseCopy(b *testing.B) {
	plainCopy := func(dst io.Writer, src io.Reader) (int64, error) { return io.Copy(dst, src) }
	hide := func(w http.ResponseWriter) http.ResponseWriter { return hidingWriter{w} }
	forward := func(w http.ResponseWriter) http.ResponseWriter { return forwardingWriter{w} }

	for _, tc := range []struct {
		name   string
		useTLS bool
		wrap   func(http.ResponseWriter) http.ResponseWriter
		copyFn func(io.Writer, io.Reader) (int64, error)
	}{
		{"h1/readfrom/no-wrapper", false, nil, plainCopy},
		{"h1/readfrom/forwarding-wrapper", false, forward, plainCopy},
		{"h1/pooled32k/wrapper", false, hide, copyWithSize(32 << 10)},
		{"h1/pooled128k/wrapper", false, hide, copyWithSize(128 << 10)},
		{"h1/pooled512k/wrapper", false, hide, copyWithSize(512 << 10)},
		{"tls/readfrom/no-wrapper", true, nil, plainCopy},
		{"tls/pooled128k/wrapper", true, hide, copyWithSize(128 << 10)},
	} {
		b.Run(tc.name, func(b *testing.B) { benchGetResponse(b, tc.useTLS, tc.wrap, tc.copyFn) })
	}
}
