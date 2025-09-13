package proxy

import (
	"net/http"

	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/middleware"
)

// setupMiddleware sets up the middleware for the server
func (s *Server) setupMiddleware() {
	// Initialize middleware
	s.requestTracker = middleware.NewRequestTracker(s.logger)
	s.requestTracker.SetHandlers(s.requestStartHandler, s.requestEndHandler)

	s.httpLogger = middleware.NewLogger(s.logger)
	s.corsHandler = middleware.NewCORS(s.logger)
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
