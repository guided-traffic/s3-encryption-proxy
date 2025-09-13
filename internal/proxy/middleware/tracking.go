package middleware

import (
	"net/http"

	"github.com/sirupsen/logrus"
)

// RequestTracker tracks active requests for graceful shutdown
type RequestTracker struct {
	logger            *logrus.Entry
	requestStartHandler func()
	requestEndHandler   func()
}

// NewRequestTracker creates a new request tracker middleware
func NewRequestTracker(logger *logrus.Entry) *RequestTracker {
	return &RequestTracker{
		logger: logger,
	}
}

// SetHandlers sets the start and end handlers for request tracking
func (rt *RequestTracker) SetHandlers(onStart, onEnd func()) {
	rt.requestStartHandler = onStart
	rt.requestEndHandler = onEnd
}

// Middleware returns the HTTP middleware function
func (rt *RequestTracker) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if rt.requestStartHandler != nil {
			rt.requestStartHandler()
		}

		defer func() {
			if rt.requestEndHandler != nil {
				rt.requestEndHandler()
			}
		}()

		next.ServeHTTP(w, r)
	})
}
