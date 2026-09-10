package proxy

import (
	"net/http"
	"strings"

	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/middleware"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/response"
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
		accessKeyID, err := s.s3AuthService.AuthenticateRequest(r)
		if err != nil {
			s.writeS3Error(w, s.determineErrorCode(err), http.StatusForbidden)
			return
		}
		// The handlers describe the caller, never the backend account (ADR 0008).
		next.ServeHTTP(w, middleware.WithClientIdentity(r, accessKeyID))
	})
}

// determineErrorCode maps authentication errors to appropriate S3 error codes
func (s *Server) determineErrorCode(err error) string {
	errMsg := err.Error()

	switch {
	case strings.Contains(errMsg, "access key not found"):
		return "InvalidAccessKeyId"
	case strings.Contains(errMsg, "signature"):
		return "SignatureDoesNotMatch"
	case strings.Contains(errMsg, "timestamp"), strings.Contains(errMsg, "clock skew"), strings.Contains(errMsg, "replay"):
		return "RequestTimeTooSkewed"
	case strings.Contains(errMsg, "authorization header"):
		return "InvalidRequest"
	case strings.Contains(errMsg, "malformed"):
		return "AuthorizationHeaderMalformed"
	default:
		return "AccessDenied"
	}
}

// authErrorMessage is the client-facing wording per authentication error code.
// The raw error text carries the attempted access key id, signed header names
// and clock offsets. The auth service already logs it through logSecurityEvent;
// reflecting it into the response body echoed attacker-controlled text back to
// the caller and broke the XML document whenever the key contained & or <.
var authErrorMessage = map[string]string{
	"InvalidAccessKeyId":           "The access key ID you provided does not exist in our records",
	"SignatureDoesNotMatch":        "The request signature does not match the signature the server calculated",
	"RequestTimeTooSkewed":         "The difference between the request time and the current time is too large",
	"InvalidRequest":               "The authorization mechanism you provided is not supported",
	"AuthorizationHeaderMalformed": "The authorization header you provided is invalid",
	"AccessDenied":                 "Access Denied",
}

// writeS3Error writes an S3-compatible error response with security headers
func (s *Server) writeS3Error(w http.ResponseWriter, code string, statusCode int) {
	// Security headers, set before the writer commits the status
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")

	message, ok := authErrorMessage[code]
	if !ok {
		message = authErrorMessage["AccessDenied"]
	}
	response.NewErrorWriter(s.logger).WriteGenericError(w, statusCode, code, message)
}
