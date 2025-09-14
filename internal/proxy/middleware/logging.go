package middleware

import (
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
		}).Info("HTTP request processed")
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
