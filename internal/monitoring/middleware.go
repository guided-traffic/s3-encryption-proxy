package monitoring

import (
	"bufio"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/mux"
)

// responseWriter wraps http.ResponseWriter to capture status code
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// Unwrap hands http.NewResponseController the writer underneath. Without it the
// controller stops here and SetReadDeadline, SetWriteDeadline, EnableFullDuplex
// and Hijack all answer ErrNotSupported on every route this wrapper covers -
// which is what makes per-copy deadlines on long transfers (ADR 0015)
// impossible today.
func (rw *responseWriter) Unwrap() http.ResponseWriter { return rw.ResponseWriter }

// FlushError forwards a flush and reports its error. http.ResponseController
// prefers FlushError over Flush, so declaring it keeps a failed flush visible
// instead of swallowing it behind the Flush below.
func (rw *responseWriter) FlushError() error {
	switch t := rw.ResponseWriter.(type) {
	case interface{ FlushError() error }:
		return t.FlushError()
	case http.Flusher:
		t.Flush()
		return nil
	default:
		return http.ErrNotSupported
	}
}

// Flush satisfies http.Flusher for callers that type-assert the writer directly.
func (rw *responseWriter) Flush() { _ = rw.FlushError() }

// Hijack satisfies http.Hijacker for callers that type-assert the writer directly.
func (rw *responseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := rw.ResponseWriter.(http.Hijacker); ok {
		return h.Hijack()
	}
	return nil, nil, http.ErrNotSupported
}

// ReadFrom is deliberately NOT declared. io.copyBuffer prefers dst.ReadFrom over
// a supplied buffer, so a passthrough here would put the response copy path back
// under the control of how many middlewares are in the chain. See ADR 0020.

// HTTPMiddleware provides Prometheus metrics for HTTP requests
func HTTPMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Wrap response writer to capture status code
		wrapped := &responseWriter{
			ResponseWriter: w,
			statusCode:     http.StatusOK,
		}

		// Increment active connections
		ActiveConnections.Inc()
		defer ActiveConnections.Dec()

		// Call next handler
		next.ServeHTTP(wrapped, r)

		// Extract route pattern from gorilla/mux
		route := mux.CurrentRoute(r)
		endpoint := "unknown"
		if route != nil {
			if template, err := route.GetPathTemplate(); err == nil {
				endpoint = template
			}
		}

		// Record metrics
		duration := time.Since(start).Seconds()
		method := r.Method
		statusCode := strconv.Itoa(wrapped.statusCode)

		RequestsTotal.WithLabelValues(method, endpoint, statusCode).Inc()
		RequestDuration.WithLabelValues(method, endpoint).Observe(duration)
	})
}

// S3OperationMetrics records metrics for S3 operations
func RecordS3Operation(operation, bucket, status string, duration time.Duration) {
	S3OperationsTotal.WithLabelValues(operation, bucket, status).Inc()
	S3OperationDuration.WithLabelValues(operation, bucket).Observe(duration.Seconds())
}

// EncryptionOperationMetrics records metrics for encryption operations
func RecordEncryptionOperation(operation, providerType, status string, duration time.Duration) {
	EncryptionOperationsTotal.WithLabelValues(operation, providerType, status).Inc()
	EncryptionDuration.WithLabelValues(operation, providerType).Observe(duration.Seconds())
}

// BytesTransferredMetrics records data transfer metrics
func RecordBytesTransferred(direction, operation string, bytes int64) {
	BytesTransferred.WithLabelValues(direction, operation).Add(float64(bytes))
}

// MultipartUploadMetrics records multipart upload metrics
func RecordMultipartUpload(status string) {
	MultipartUploadsTotal.WithLabelValues(status).Inc()
}

// MultipartUploadPartMetrics records multipart upload part metrics
func RecordMultipartUploadPart(status string) {
	MultipartUploadPartsTotal.WithLabelValues(status).Inc()
}
