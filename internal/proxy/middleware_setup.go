package proxy

import (
	"fmt"
	"net/http"

	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/middleware"
)

// setupMiddleware sets up the middleware for the server
func (s *Server) setupMiddleware() {
	// Initialize middleware
	s.requestTracker = middleware.NewRequestTracker(s.logger)
	s.requestTracker.SetHandlers(s.requestStartHandler, s.requestEndHandler)

	// Safe config access with default
	logHealthRequests := false
	if s.config != nil {
		logHealthRequests = s.config.LogHealthRequests
	}
	s.httpLogger = middleware.NewLogger(s.logger, logHealthRequests)
	s.corsHandler = middleware.NewCORS(s.logger)

	// Initialize S3 authentication service
	s.s3AuthService = middleware.NewS3AuthenticationService(s.config, s.logger.Logger)
}

// Middleware wrapper functions for compatibility with existing code
func (s *Server) requestTrackingMiddleware(next http.Handler) http.Handler {
	if s.requestTracker == nil {
		s.setupMiddleware()
	}
	return s.requestTracker.Middleware(next)
}

func (s *Server) loggingMiddleware(next http.Handler) http.Handler {
	if s.httpLogger == nil {
		s.setupMiddleware()
	}
	return s.httpLogger.Middleware(next)
}

func (s *Server) corsMiddleware(next http.Handler) http.Handler {
	if s.corsHandler == nil {
		s.setupMiddleware()
	}
	return s.corsHandler.Middleware(next)
}

func (s *Server) s3AuthMiddleware(next http.Handler) http.Handler {
	if s.s3AuthService == nil {
		s.setupMiddleware()
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Perform comprehensive authentication using the robust service
		if err := s.s3AuthService.AuthenticateRequest(r); err != nil {
			s.writeS3Error(w, s.determineErrorCode(err), err.Error(), http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// determineErrorCode maps authentication errors to appropriate S3 error codes
func (s *Server) determineErrorCode(err error) string {
	errMsg := err.Error()

	switch {
	case contains(errMsg, "access key not found"):
		return "InvalidAccessKeyId"
	case contains(errMsg, "signature"):
		return "SignatureDoesNotMatch"
	case contains(errMsg, "timestamp"), contains(errMsg, "clock skew"), contains(errMsg, "replay"):
		return "RequestTimeTooSkewed"
	case contains(errMsg, "authorization header"):
		return "InvalidRequest"
	case contains(errMsg, "malformed"):
		return "AuthorizationHeaderMalformed"
	default:
		return "AccessDenied"
	}
}

// contains checks if a string contains a substring (case-insensitive helper)
func contains(s, substr string) bool {
	return len(s) >= len(substr) &&
		(s == substr ||
			len(s) > len(substr) &&
				(s[0:len(substr)] == substr ||
					s[len(s)-len(substr):] == substr ||
					findInString(s, substr)))
}

func findInString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// writeS3Error writes an S3-compatible error response with security headers
func (s *Server) writeS3Error(w http.ResponseWriter, code, message string, statusCode int) {
	// Security headers
	w.Header().Set("Content-Type", "application/xml")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.WriteHeader(statusCode)

	// S3-compatible error response
	errorXML := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<Error>
	<Code>%s</Code>
	<Message>%s</Message>
	<RequestId>%s</RequestId>
	<Resource>%s</Resource>
</Error>`, code, message, "s3-encryption-proxy", "")

	_, _ = w.Write([]byte(errorXML)) // gosec: ignore any write errors to response writer
}
