package middleware

import (
	"bufio"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	logrustest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MwtestLogger returns a logrus entry whose records are captured instead of
// printed, so a test can assert on what was logged.
func MwtestLogger() (*logrus.Entry, *logrustest.Hook) {
	logger, hook := logrustest.NewNullLogger()
	logger.SetLevel(logrus.DebugLevel)
	return logrus.NewEntry(logger), hook
}

// MwechoHandler records that it ran and writes a recognisable body.
func MwechoHandler(called *bool, status int) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		*called = true
		w.Header().Set("X-Mw-Downstream", "yes")
		w.WriteHeader(status)
		_, _ = w.Write([]byte("downstream-body"))
	})
}

func TestMwCORSMiddleware(t *testing.T) {
	entry, _ := MwtestLogger()
	cors := NewCORS(entry)
	require.NotNil(t, cors)

	expectedHeaders := map[string]string{
		"Access-Control-Allow-Origin":   "*",
		"Access-Control-Allow-Methods":  "GET, PUT, POST, DELETE, HEAD, OPTIONS",
		"Access-Control-Allow-Headers":  "Content-Type, Authorization, x-amz-*, Content-MD5, Content-Length",
		"Access-Control-Expose-Headers": "ETag, x-amz-*, Content-Length",
		"Access-Control-Max-Age":        "3600",
	}

	t.Run("preflight is answered without reaching the handler", func(t *testing.T) {
		downstreamCalled := false
		rec := httptest.NewRecorder()
		cors.Middleware(MwechoHandler(&downstreamCalled, http.StatusTeapot)).
			ServeHTTP(rec, httptest.NewRequest(http.MethodOptions, "/bucket/key", nil))

		assert.False(t, downstreamCalled, "OPTIONS must be terminated by the CORS middleware")
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Empty(t, rec.Body.String())
		for name, want := range expectedHeaders {
			assert.Equal(t, want, rec.Header().Get(name), "header %s", name)
		}
	})

	t.Run("other methods pass through with CORS headers", func(t *testing.T) {
		downstreamCalled := false
		rec := httptest.NewRecorder()
		cors.Middleware(MwechoHandler(&downstreamCalled, http.StatusPartialContent)).
			ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/bucket/key", nil))

		assert.True(t, downstreamCalled)
		assert.Equal(t, http.StatusPartialContent, rec.Code)
		assert.Equal(t, "downstream-body", rec.Body.String())
		assert.Equal(t, "yes", rec.Header().Get("X-Mw-Downstream"))
		for name, want := range expectedHeaders {
			assert.Equal(t, want, rec.Header().Get(name), "header %s", name)
		}
	})
}

func TestMwLoggerMiddleware(t *testing.T) {
	tests := []struct {
		name              string
		path              string
		logHealthRequests bool
		status            int
		wantLogged        bool
	}{
		{name: "object request is logged", path: "/bucket/key", status: http.StatusCreated, wantLogged: true},
		{name: "health is skipped by default", path: "/health", status: http.StatusOK, wantLogged: false},
		{name: "version is skipped by default", path: "/version", status: http.StatusOK, wantLogged: false},
		{name: "health is logged when enabled", path: "/health", logHealthRequests: true, status: http.StatusOK, wantLogged: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entry, hook := MwtestLogger()
			downstreamCalled := false
			rec := httptest.NewRecorder()

			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			req.RemoteAddr = "192.0.2.10:4711"
			req.Header.Set("User-Agent", "mw-test-agent")

			NewLogger(entry, tt.logHealthRequests).
				Middleware(MwechoHandler(&downstreamCalled, tt.status)).
				ServeHTTP(rec, req)

			// The handler always runs; only the log record is conditional.
			assert.True(t, downstreamCalled)
			assert.Equal(t, tt.status, rec.Code)
			assert.Equal(t, "downstream-body", rec.Body.String())

			if !tt.wantLogged {
				assert.Empty(t, hook.AllEntries(), "no record expected for %s", tt.path)
				return
			}

			require.Len(t, hook.AllEntries(), 1)
			logged := hook.LastEntry()
			assert.Equal(t, logrus.DebugLevel, logged.Level)
			assert.Equal(t, "HTTP request processed", logged.Message)
			assert.Equal(t, tt.status, logged.Data["status"], "wrapped writer must capture the real status")
			assert.Equal(t, tt.path, logged.Data["path"])
			assert.Equal(t, http.MethodGet, logged.Data["method"])
			assert.Equal(t, "192.0.2.10:4711", logged.Data["remote_addr"])
			assert.Equal(t, "mw-test-agent", logged.Data["user_agent"])
			assert.Contains(t, logged.Data, "duration")
		})
	}
}

// TestMwLoggerDefaultsToOKWithoutExplicitWriteHeader pins the responseWriter
// default: a handler that only writes a body still reports 200, not 0.
func TestMwLoggerDefaultsToOKWithoutExplicitWriteHeader(t *testing.T) {
	entry, hook := MwtestLogger()
	rec := httptest.NewRecorder()

	NewLogger(entry, false).Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, err := io.WriteString(w, "no explicit status")
		assert.NoError(t, err)
	})).ServeHTTP(rec, httptest.NewRequest(http.MethodPut, "/bucket/key", nil))

	require.Len(t, hook.AllEntries(), 1)
	assert.Equal(t, http.StatusOK, hook.LastEntry().Data["status"])
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestMwRequestTracker(t *testing.T) {
	t.Run("start and end handlers wrap the request", func(t *testing.T) {
		entry, _ := MwtestLogger()
		tracker := NewRequestTracker(entry)

		var order []string
		tracker.SetHandlers(
			func() { order = append(order, "start") },
			func() { order = append(order, "end") },
		)

		rec := httptest.NewRecorder()
		tracker.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			order = append(order, "handler")
			w.WriteHeader(http.StatusNoContent)
		})).ServeHTTP(rec, httptest.NewRequest(http.MethodDelete, "/bucket/key", nil))

		assert.Equal(t, []string{"start", "handler", "end"}, order)
		assert.Equal(t, http.StatusNoContent, rec.Code)
	})

	t.Run("nil handlers are tolerated", func(t *testing.T) {
		entry, _ := MwtestLogger()
		downstreamCalled := false
		rec := httptest.NewRecorder()

		NewRequestTracker(entry).
			Middleware(MwechoHandler(&downstreamCalled, http.StatusOK)).
			ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/bucket/key", nil))

		assert.True(t, downstreamCalled)
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("end handler runs even when the handler panics", func(t *testing.T) {
		entry, _ := MwtestLogger()
		tracker := NewRequestTracker(entry)

		ended := false
		tracker.SetHandlers(func() {}, func() { ended = true })

		assert.Panics(t, func() {
			tracker.Middleware(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
				panic("boom")
			})).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/bucket/key", nil))
		})

		// Without the deferred end handler the in-flight counter would leak and
		// graceful shutdown would hang forever on a panicking request.
		assert.True(t, ended, "end handler must run through the defer")
	})
}

// ADR 0015: a layer that wraps the response preserves the capabilities of the
// writer beneath it. This wrapper is applied to every S3 route unconditionally
// (router.go s3Router.Use(s.loggingMiddleware)), and it embedded
// http.ResponseWriter, so it hid every optional interface of the writer
// underneath in every configuration - monitoring on or off. That is why
// http.NewResponseController does not work on any S3 route today, and it is
// twice the reach the original finding recorded, which blamed the monitoring
// wrapper alone.
func TestMwResponseWriterKeepsTheWriterCapabilities(t *testing.T) {
	rec := httptest.NewRecorder()
	rw := &responseWriter{ResponseWriter: rec, statusCode: http.StatusOK}

	t.Run("Unwrap reaches the writer underneath", func(t *testing.T) {
		assert.Same(t, rec, rw.Unwrap())
	})

	t.Run("Flush forwards to the inner Flusher", func(t *testing.T) {
		require.NoError(t, rw.FlushError())
		assert.True(t, rec.Flushed)
	})

	t.Run("Hijack answers ErrNotSupported when the inner writer cannot hijack", func(t *testing.T) {
		conn, buf, err := rw.Hijack()
		assert.Nil(t, conn)
		assert.Nil(t, buf)
		assert.ErrorIs(t, err, http.ErrNotSupported)
	})

	t.Run("FlushError reports ErrNotSupported rather than swallowing it", func(t *testing.T) {
		bare := &responseWriter{ResponseWriter: MwNotAFlusher{}, statusCode: http.StatusOK}
		assert.ErrorIs(t, bare.FlushError(), http.ErrNotSupported)
		assert.NotPanics(t, bare.Flush)
	})

	// ReadFrom must stay hidden: io.copyBuffer prefers dst.ReadFrom over the
	// buffer it is handed, so a passthrough here would decide the GET response
	// copy path by middleware count instead of by measurement.
	t.Run("ReadFrom stays hidden on purpose", func(t *testing.T) {
		_, ok := interface{}(rw).(io.ReaderFrom)
		assert.False(t, ok, "declaring ReadFrom would re-create the defect ADR 0015 removes")
	})

	// http.NewResponseController is the caller that matters: it is what a
	// per-transfer write deadline needs instead of the blanket 30 s one on the
	// listener (ADR 0015).
	t.Run("http.NewResponseController reaches through the wrapper", func(t *testing.T) {
		assert.NoError(t, http.NewResponseController(rw).Flush())
	})
}

// MwNotAFlusher is an http.ResponseWriter and nothing else.
type MwNotAFlusher struct{}

func (MwNotAFlusher) Header() http.Header         { return http.Header{} }
func (MwNotAFlusher) Write(b []byte) (int, error) { return len(b), nil }
func (MwNotAFlusher) WriteHeader(int)             {}

// The fallback arms are only half the contract. These drive the arms that are
// live in production - net/http's *response implements both FlushError and
// Hijacker - so that gutting either passthrough (returning nil from FlushError,
// or an unconditional ErrNotSupported from Hijack) fails here instead of
// silently regressing every S3 route.
func TestMwResponseWriterForwardsToTheLiveWriter(t *testing.T) {
	t.Run("FlushError propagates the inner error rather than swallowing it", func(t *testing.T) {
		want := errors.New("flush failed on the wire")
		rw := &responseWriter{ResponseWriter: &MwFlushErrorWriter{err: want}, statusCode: http.StatusOK}

		assert.ErrorIs(t, rw.FlushError(), want,
			"a flush that failed must not be reported to the caller as success")
	})

	t.Run("FlushError prefers the inner FlushError over the inner Flush", func(t *testing.T) {
		inner := &MwFlushErrorWriter{}
		rw := &responseWriter{ResponseWriter: inner, statusCode: http.StatusOK}

		require.NoError(t, rw.FlushError())
		assert.Equal(t, 1, inner.flushErrorCalls)
		assert.Zero(t, inner.flushCalls, "http.ResponseController prefers FlushError, so this wrapper must too")
	})

	t.Run("Hijack forwards to the inner Hijacker", func(t *testing.T) {
		inner := &MwHijackWriter{}
		rw := &responseWriter{ResponseWriter: inner, statusCode: http.StatusOK}

		conn, buf, err := rw.Hijack()

		require.NoError(t, err)
		assert.Equal(t, inner.conn, conn, "the hijacked connection must be the inner one")
		assert.NotNil(t, buf)
		assert.Equal(t, 1, inner.calls)
	})

	// This is what a per-transfer write deadline (ADR 0015) needs and what
	// Unwrap exists for: the controller has no SetWriteDeadline of its own, so
	// it can only get there by walking the Unwrap chain to the real
	// *http.response.
	t.Run("http.NewResponseController reaches the real writer through Unwrap", func(t *testing.T) {
		errCh := make(chan error, 1)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}
			errCh <- http.NewResponseController(wrapped).SetWriteDeadline(time.Now().Add(time.Minute))
			_, _ = wrapped.Write([]byte("ok"))
		}))
		defer srv.Close()

		resp, err := srv.Client().Get(srv.URL)
		require.NoError(t, err)
		require.NoError(t, resp.Body.Close())

		assert.NoError(t, <-errCh,
			"SetWriteDeadline is only reachable through Unwrap; without it this is ErrNotSupported")
	})
}

// MwFlushErrorWriter implements FlushError as net/http's own writer does.
type MwFlushErrorWriter struct {
	err             error
	flushErrorCalls int
	flushCalls      int
}

func (w *MwFlushErrorWriter) Header() http.Header         { return http.Header{} }
func (w *MwFlushErrorWriter) Write(b []byte) (int, error) { return len(b), nil }
func (w *MwFlushErrorWriter) WriteHeader(int)             {}
func (w *MwFlushErrorWriter) Flush()                      { w.flushCalls++ }
func (w *MwFlushErrorWriter) FlushError() error           { w.flushErrorCalls++; return w.err }

// MwHijackWriter is an http.Hijacker, which an httptest.ResponseRecorder is not.
type MwHijackWriter struct {
	conn  net.Conn
	calls int
}

func (w *MwHijackWriter) Header() http.Header         { return http.Header{} }
func (w *MwHijackWriter) Write(b []byte) (int, error) { return len(b), nil }
func (w *MwHijackWriter) WriteHeader(int)             {}
func (w *MwHijackWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	w.calls++
	if w.conn == nil {
		server, client := net.Pipe()
		_ = client.Close()
		w.conn = server
	}
	return w.conn, bufio.NewReadWriter(bufio.NewReader(w.conn), bufio.NewWriter(w.conn)), nil
}
