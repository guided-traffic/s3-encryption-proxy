package middleware

import (
	"bufio"
	"net"
	"net/http"
	"time"

	"github.com/sirupsen/logrus"
)

// Logger provides HTTP request logging
type Logger struct {
	logger            *logrus.Entry
	logHealthRequests bool
}

// NewLogger creates a new logging middleware
func NewLogger(logger *logrus.Entry, logHealthRequests bool) *Logger {
	return &Logger{
		logger:            logger,
		logHealthRequests: logHealthRequests,
	}
}

// Middleware returns the HTTP middleware function
func (l *Logger) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Create a wrapped writer to capture status code
		wrapped := &responseWriter{
			ResponseWriter: w,
			statusCode:     http.StatusOK, // default
		}

		next.ServeHTTP(wrapped, r)

		duration := time.Since(start)

		// Skip logging health requests if configured to do so
		if !l.logHealthRequests && (r.URL.Path == "/health" || r.URL.Path == "/version") {
			return
		}

		l.logger.WithFields(logrus.Fields{
			"method":      r.Method,
			"path":        r.URL.Path,
			"status":      wrapped.statusCode,
			"duration":    duration,
			"remote_addr": r.RemoteAddr,
			"user_agent":  r.UserAgent(),
		}).Debug("HTTP request processed")
	})
}

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
// which is what makes per-copy deadlines on long transfers (ticket 012 item 1.2)
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
// under the control of how many middlewares are in the chain. See D-29.
