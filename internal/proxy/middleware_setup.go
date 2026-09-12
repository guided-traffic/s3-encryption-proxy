package proxy

import (
	"net/http"
	"strings"

	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/handlers/object"
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

// drainGuardMiddleware refuses new S3 work once the proxy has been asked to
// stop, without taking the listener down (ADR 0029 D1). A closed listener
// answers a request that arrives while a load balancer still has this instance
// in rotation with a connection refusal, which an SDK cannot tell apart from a
// broken backend; an open listener answering `503 ServiceUnavailable` with
// `Retry-After` is a retry the SDK makes against another replica on its own.
//
// It sits in front of authentication, so a request that will not be served
// costs no signature verification, and in front of the request tracker, so a
// refusal is not counted as work the drain has to wait for. The health and
// version routes are on their own subrouter and are not affected: a readiness
// probe has to keep getting an answer while this is in force.
func (s *Server) drainGuardMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.shutdownStateHandler != nil {
			if draining, _ := s.shutdownStateHandler(); draining {
				w.Header().Set("Retry-After", "1")
				response.NewErrorWriter(s.logger).WriteGenericError(w, http.StatusServiceUnavailable,
					"ServiceUnavailable", "The proxy is shutting down and is not accepting new requests")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// rawQueryGuardMiddleware refuses a raw query string containing a ';' with
// 400 InvalidArgument (ADR 0007 D13). net/url discards every &-separated
// segment that contains one and swallows the error, while the router splits on
// both characters: such a request is routed by one reading of its query and
// handled by another. A PUT whose query carried a ';' therefore fell through to
// the plain object PUT with an empty parsed query and overwrote the object.
// A percent-encoded %3B is a value byte, not a separator, and is not affected.
func (s *Server) rawQueryGuardMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.RawQuery, ";") {
			response.NewErrorWriter(s.logger).WriteGenericError(w, http.StatusBadRequest,
				"InvalidArgument", "The query string must not contain a semicolon")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// sseCustomerGuardMiddleware refuses the three customer-key headers with
// 501 NotImplemented, naming the header (ADR 0007 D6). No read path carries the
// customer key, so accepting one on upload would write an object this proxy
// could never read back - a silent time bomb rather than a silent drop. The
// refusal sits in front of every S3 route because the decision lifts only when
// every verb that touches an object carries the key.
func (s *Server) sseCustomerGuardMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if header := object.SSECustomerHeader(r.Header); header != "" {
			response.NewErrorWriter(s.logger).WriteNotImplemented(w, header)
			return
		}
		next.ServeHTTP(w, r)
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
