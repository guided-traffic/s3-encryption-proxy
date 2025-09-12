package monitoring

import (
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
