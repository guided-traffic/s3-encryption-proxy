package monitoring

import (
	"bufio"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MonrequestMetric reads a RequestsTotal child. Those two collectors live in the
// package-private registry rather than the default one, so they need their own
// accessor.
func MonrequestMetric(t *testing.T, name string, labels map[string]string) MonmetricValue {
	t.Helper()
	return MongatherMetric(t, registry, name, labels)
}

func TestMonResponseWriterCapturesStatusCode(t *testing.T) {
	rec := httptest.NewRecorder()
	wrapped := &responseWriter{ResponseWriter: rec, statusCode: http.StatusOK}

	wrapped.WriteHeader(http.StatusServiceUnavailable)
	n, err := wrapped.Write([]byte("unavailable"))
	require.NoError(t, err)
	assert.Equal(t, len("unavailable"), n)

	assert.Equal(t, http.StatusServiceUnavailable, wrapped.statusCode,
		"the wrapper must record the status code it forwarded")
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code,
		"the status code must still reach the underlying writer")
	assert.Equal(t, "unavailable", rec.Body.String())
}

func TestMonHTTPMiddlewareRecordsRoutedRequest(t *testing.T) {
	const pathTemplate = "/mon-bucket/{key}"

	router := mux.NewRouter()
	router.Use(HTTPMiddleware)
	router.HandleFunc(pathTemplate, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
		if _, err := w.Write([]byte("teapot")); err != nil {
			t.Errorf("failed to write response body: %v", err)
		}
	}).Methods(http.MethodGet)

	countLabels := map[string]string{
		"method":      http.MethodGet,
		"endpoint":    pathTemplate,
		"status_code": "418",
	}
	durationLabels := map[string]string{
		"method":   http.MethodGet,
		"endpoint": pathTemplate,
	}

	before := MonrequestMetric(t, "s3ep_requests_total", countLabels)
	beforeDuration := MonrequestMetric(t, "s3ep_request_duration_seconds", durationLabels)

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/mon-bucket/object.txt", nil))

	assert.Equal(t, http.StatusTeapot, rec.Code)
	assert.Equal(t, "teapot", rec.Body.String())

	after := MonrequestMetric(t, "s3ep_requests_total", countLabels)
	require.True(t, after.Found, "the request counter must use the mux path template as endpoint")
	assert.Equal(t, before.Value+1, after.Value)

	afterDuration := MonrequestMetric(t, "s3ep_request_duration_seconds", durationLabels)
	require.True(t, afterDuration.Found)
	assert.Equal(t, beforeDuration.HistCount+1, afterDuration.HistCount)
	assert.Greater(t, afterDuration.HistSum, beforeDuration.HistSum,
		"the observed duration must be strictly positive")
}

func TestMonHTTPMiddlewareDefaultsToStatus200(t *testing.T) {
	const pathTemplate = "/mon-default-status"

	router := mux.NewRouter()
	router.Use(HTTPMiddleware)
	router.HandleFunc(pathTemplate, func(w http.ResponseWriter, _ *http.Request) {
		// Deliberately no WriteHeader call: the wrapper must report 200.
		if _, err := w.Write([]byte("ok")); err != nil {
			t.Errorf("failed to write response body: %v", err)
		}
	})

	labels := map[string]string{
		"method":      http.MethodPut,
		"endpoint":    pathTemplate,
		"status_code": "200",
	}
	before := MonrequestMetric(t, "s3ep_requests_total", labels)

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodPut, pathTemplate, nil))
	assert.Equal(t, http.StatusOK, rec.Code)

	after := MonrequestMetric(t, "s3ep_requests_total", labels)
	require.True(t, after.Found)
	assert.Equal(t, before.Value+1, after.Value)
}

func TestMonHTTPMiddlewareUnknownEndpoint(t *testing.T) {
	tests := []struct {
		name    string
		handler http.Handler
		method  string
		target  string
		status  string
	}{
		{
			name: "no mux route in the request context",
			handler: HTTPMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusNotFound)
			})),
			method: http.MethodDelete,
			target: "/mon-no-route",
			status: "404",
		},
		{
			name: "matched route without a path template",
			handler: func() http.Handler {
				router := mux.NewRouter()
				router.Use(HTTPMiddleware)
				// A method-only route matches but has no path, so
				// GetPathTemplate returns an error.
				router.NewRoute().Methods(http.MethodHead).HandlerFunc(
					func(w http.ResponseWriter, _ *http.Request) {
						w.WriteHeader(http.StatusNoContent)
					})
				return router
			}(),
			method: http.MethodHead,
			target: "/mon-path-less-route",
			status: "204",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			labels := map[string]string{
				"method":      tt.method,
				"endpoint":    "unknown",
				"status_code": tt.status,
			}
			before := MonrequestMetric(t, "s3ep_requests_total", labels)

			rec := httptest.NewRecorder()
			tt.handler.ServeHTTP(rec, httptest.NewRequest(tt.method, tt.target, nil))

			after := MonrequestMetric(t, "s3ep_requests_total", labels)
			require.True(t, after.Found, "an unresolvable route must be labelled unknown")
			assert.Equal(t, before.Value+1, after.Value)
		})
	}
}

func TestMonHTTPMiddlewareTracksActiveConnections(t *testing.T) {
	baseline := MondefaultMetric(t, "s3ep_active_connections", map[string]string{})

	var inFlight float64
	handler := HTTPMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		inFlight = MondefaultMetric(t, "s3ep_active_connections", map[string]string{}).Value
		w.WriteHeader(http.StatusOK)
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/mon-active", nil))

	assert.Equal(t, baseline.Value+1, inFlight,
		"active connections must be incremented for the duration of the handler")
	after := MondefaultMetric(t, "s3ep_active_connections", map[string]string{})
	assert.Equal(t, baseline.Value, after.Value,
		"active connections must be decremented once the handler returns")
}

func TestMonRecordS3Operation(t *testing.T) {
	const (
		operation = "mon-PutObject"
		bucket    = "mon-bucket"
	)
	countLabels := map[string]string{"operation": operation, "bucket": bucket, "status": "success"}
	durationLabels := map[string]string{"operation": operation, "bucket": bucket}

	before := MondefaultMetric(t, "s3ep_s3_operations_total", countLabels)
	beforeDuration := MondefaultMetric(t, "s3ep_s3_operation_duration_seconds", durationLabels)

	RecordS3Operation(operation, bucket, "success", 150*time.Millisecond)

	after := MondefaultMetric(t, "s3ep_s3_operations_total", countLabels)
	require.True(t, after.Found)
	assert.Equal(t, before.Value+1, after.Value)

	afterDuration := MondefaultMetric(t, "s3ep_s3_operation_duration_seconds", durationLabels)
	require.True(t, afterDuration.Found)
	assert.Equal(t, beforeDuration.HistCount+1, afterDuration.HistCount)
	assert.InDelta(t, beforeDuration.HistSum+0.15, afterDuration.HistSum, 0.0001)
}

func TestMonRecordEncryptionOperation(t *testing.T) {
	const (
		operation    = "mon-encrypt"
		providerType = "aes"
	)
	countLabels := map[string]string{"operation": operation, "provider_type": providerType, "status": "error"}
	durationLabels := map[string]string{"operation": operation, "provider_type": providerType}

	before := MondefaultMetric(t, "s3ep_encryption_operations_total", countLabels)
	beforeDuration := MondefaultMetric(t, "s3ep_encryption_duration_seconds", durationLabels)

	RecordEncryptionOperation(operation, providerType, "error", 40*time.Millisecond)

	after := MondefaultMetric(t, "s3ep_encryption_operations_total", countLabels)
	require.True(t, after.Found)
	assert.Equal(t, before.Value+1, after.Value)

	afterDuration := MondefaultMetric(t, "s3ep_encryption_duration_seconds", durationLabels)
	require.True(t, afterDuration.Found)
	assert.Equal(t, beforeDuration.HistCount+1, afterDuration.HistCount)
	assert.InDelta(t, beforeDuration.HistSum+0.04, afterDuration.HistSum, 0.0001)
}

func TestMonRecordBytesTransferred(t *testing.T) {
	labels := map[string]string{"direction": "mon-upload", "operation": "PUT"}
	before := MondefaultMetric(t, "s3ep_bytes_transferred_total", labels)

	RecordBytesTransferred("mon-upload", "PUT", 4096)
	RecordBytesTransferred("mon-upload", "PUT", 1024)

	after := MondefaultMetric(t, "s3ep_bytes_transferred_total", labels)
	require.True(t, after.Found)
	assert.Equal(t, before.Value+5120, after.Value, "byte counters must accumulate")
}

func TestMonRecordMultipartMetrics(t *testing.T) {
	tests := []struct {
		name       string
		status     string
		record     func(string)
		metricName string
	}{
		{
			name:       "completed multipart upload",
			status:     "mon-completed",
			record:     RecordMultipartUpload,
			metricName: "s3ep_multipart_uploads_total",
		},
		{
			name:       "aborted multipart upload",
			status:     "mon-aborted",
			record:     RecordMultipartUpload,
			metricName: "s3ep_multipart_uploads_total",
		},
		{
			name:       "uploaded part",
			status:     "mon-part-uploaded",
			record:     RecordMultipartUploadPart,
			metricName: "s3ep_multipart_upload_parts_total",
		},
		{
			name:       "failed part",
			status:     "mon-part-failed",
			record:     RecordMultipartUploadPart,
			metricName: "s3ep_multipart_upload_parts_total",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			labels := map[string]string{"status": tt.status}
			before := MondefaultMetric(t, tt.metricName, labels)

			tt.record(tt.status)

			after := MondefaultMetric(t, tt.metricName, labels)
			require.True(t, after.Found)
			assert.Equal(t, before.Value+1, after.Value)
		})
	}
}

// D-29: the wrapper embeds http.ResponseWriter and so hid every optional
// interface of the writer underneath. http.NewResponseController therefore did
// not work on any route this middleware covers, which is what blocks per-copy
// deadlines on long transfers (ticket 012 item 1.2).
func TestMonResponseWriterKeepsTheWriterCapabilities(t *testing.T) {
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
		bare := &responseWriter{ResponseWriter: MonNotAFlusher{}, statusCode: http.StatusOK}
		assert.ErrorIs(t, bare.FlushError(), http.ErrNotSupported)
		assert.NotPanics(t, bare.Flush)
	})

	// ReadFrom must stay hidden. io.copyBuffer prefers dst.ReadFrom over a
	// supplied buffer, so a passthrough here would put the GET response copy
	// path back under the control of how many middlewares are in the chain.
	t.Run("ReadFrom stays hidden on purpose", func(t *testing.T) {
		_, ok := interface{}(rw).(io.ReaderFrom)
		assert.False(t, ok, "declaring ReadFrom would re-create the defect D-29 removes")
	})
}

// MonNotAFlusher is an http.ResponseWriter and nothing else.
type MonNotAFlusher struct{}

func (MonNotAFlusher) Header() http.Header         { return http.Header{} }
func (MonNotAFlusher) Write(b []byte) (int, error) { return len(b), nil }
func (MonNotAFlusher) WriteHeader(int)             {}

// The fallback arms are only half the contract. These drive the arms that are
// live in production - net/http's *response implements both FlushError and
// Hijacker - so that gutting either passthrough (returning nil from FlushError,
// or an unconditional ErrNotSupported from Hijack) fails here instead of
// silently regressing every S3 route.
func TestMonResponseWriterForwardsToTheLiveWriter(t *testing.T) {
	t.Run("FlushError propagates the inner error rather than swallowing it", func(t *testing.T) {
		want := errors.New("flush failed on the wire")
		rw := &responseWriter{ResponseWriter: &MonFlushErrorWriter{err: want}, statusCode: http.StatusOK}

		assert.ErrorIs(t, rw.FlushError(), want,
			"a flush that failed must not be reported to the caller as success")
	})

	t.Run("FlushError prefers the inner FlushError over the inner Flush", func(t *testing.T) {
		inner := &MonFlushErrorWriter{}
		rw := &responseWriter{ResponseWriter: inner, statusCode: http.StatusOK}

		require.NoError(t, rw.FlushError())
		assert.Equal(t, 1, inner.flushErrorCalls)
		assert.Zero(t, inner.flushCalls, "http.ResponseController prefers FlushError, so this wrapper must too")
	})

	t.Run("Hijack forwards to the inner Hijacker", func(t *testing.T) {
		inner := &MonHijackWriter{}
		rw := &responseWriter{ResponseWriter: inner, statusCode: http.StatusOK}

		conn, buf, err := rw.Hijack()

		require.NoError(t, err)
		assert.Equal(t, inner.conn, conn, "the hijacked connection must be the inner one")
		assert.NotNil(t, buf)
		assert.Equal(t, 1, inner.calls)
	})

	// This is what ticket 012 item 1.2 needs and what Unwrap exists for: the
	// controller has no SetWriteDeadline of its own, so it can only get there by
	// walking the Unwrap chain to the real *http.response.
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

// MonFlushErrorWriter implements FlushError as net/http's own writer does.
type MonFlushErrorWriter struct {
	err             error
	flushErrorCalls int
	flushCalls      int
}

func (w *MonFlushErrorWriter) Header() http.Header         { return http.Header{} }
func (w *MonFlushErrorWriter) Write(b []byte) (int, error) { return len(b), nil }
func (w *MonFlushErrorWriter) WriteHeader(int)             {}
func (w *MonFlushErrorWriter) Flush()                      { w.flushCalls++ }
func (w *MonFlushErrorWriter) FlushError() error           { w.flushErrorCalls++; return w.err }

// MonHijackWriter is an http.Hijacker, which an httptest.ResponseRecorder is not.
type MonHijackWriter struct {
	conn  net.Conn
	calls int
}

func (w *MonHijackWriter) Header() http.Header         { return http.Header{} }
func (w *MonHijackWriter) Write(b []byte) (int, error) { return len(b), nil }
func (w *MonHijackWriter) WriteHeader(int)             {}
func (w *MonHijackWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	w.calls++
	if w.conn == nil {
		server, client := net.Pipe()
		_ = client.Close()
		w.conn = server
	}
	return w.conn, bufio.NewReadWriter(bufio.NewReader(w.conn), bufio.NewWriter(w.conn)), nil
}
