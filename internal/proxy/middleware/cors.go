package middleware

import (
	"net/http"

	"github.com/sirupsen/logrus"
)

// CORS provides CORS headers middleware
type CORS struct {
	logger *logrus.Entry
}

// NewCORS creates a new CORS middleware
func NewCORS(logger *logrus.Entry) *CORS {
	return &CORS{
		logger: logger,
	}
}

// Middleware returns the HTTP middleware function
func (c *CORS) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set CORS headers
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, PUT, POST, DELETE, HEAD, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, x-amz-*, Content-MD5, Content-Length")
		w.Header().Set("Access-Control-Expose-Headers", "ETag, x-amz-*, Content-Length")
		w.Header().Set("Access-Control-Max-Age", "3600")

		// Handle preflight requests
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}
