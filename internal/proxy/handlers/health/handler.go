package health

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/sirupsen/logrus"
)

// Handler handles health and version endpoints
type Handler struct {
	logger               *logrus.Entry
	logHealthRequests    bool
	shutdownStateHandler func() (bool, time.Time)
	requestStartHandler  func()
	requestEndHandler    func()
}

// NewHandler creates a new health handler
func NewHandler(logger *logrus.Entry, logHealthRequests bool) *Handler {
	return &Handler{
		logger:            logger,
		logHealthRequests: logHealthRequests,
	}
}

// SetShutdownStateHandler sets the handler to check shutdown state
func (h *Handler) SetShutdownStateHandler(handler func() (bool, time.Time)) {
	h.shutdownStateHandler = handler
}

// SetRequestTracker sets handlers for tracking active requests
func (h *Handler) SetRequestTracker(onStart, onEnd func()) {
	h.requestStartHandler = onStart
	h.requestEndHandler = onEnd
}

// Health handles the health check endpoint
func (h *Handler) Health(w http.ResponseWriter, r *http.Request) {
	// Track request if handlers are set
	if h.requestStartHandler != nil {
		h.requestStartHandler()
	}
	if h.requestEndHandler != nil {
		defer h.requestEndHandler()
	}

	// Optional logging for health requests
	if h.logHealthRequests {
		h.logger.WithFields(logrus.Fields{
			"method": r.Method,
			"path":   r.URL.Path,
			"remote": r.RemoteAddr,
		}).Debug("Health check request")
	}

	// Check if we're in shutdown mode
	if h.shutdownStateHandler != nil {
		if shutdownInitiated, shutdownTime := h.shutdownStateHandler(); shutdownInitiated {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)

			response := map[string]interface{}{
				"status":        "shutting_down",
				"shutdown_time": shutdownTime.Format(time.RFC3339),
				"message":       "Server is shutting down gracefully",
			}

			if err := json.NewEncoder(w).Encode(response); err != nil {
				h.logger.WithError(err).Error("Failed to write health response")
			}
			return
		}
	}

	// Normal health response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	response := map[string]string{
		"status": "healthy",
	}

	if err := json.NewEncoder(w).Encode(response); err != nil {
		h.logger.WithError(err).Error("Failed to write health response")
	}
}

// Version handles the version endpoint
func (h *Handler) Version(w http.ResponseWriter, r *http.Request) {
	// Track request if handlers are set
	if h.requestStartHandler != nil {
		h.requestStartHandler()
	}
	if h.requestEndHandler != nil {
		defer h.requestEndHandler()
	}

	// Optional logging for version requests (also controlled by logHealthRequests)
	if h.logHealthRequests {
		h.logger.WithFields(logrus.Fields{
			"method": r.Method,
			"path":   r.URL.Path,
			"remote": r.RemoteAddr,
		}).Debug("Version check request")
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	// This would typically come from build info
	response := map[string]string{
		"version": "dev", // This should be injected at build time
		"service": "s3-encryption-proxy",
	}

	if err := json.NewEncoder(w).Encode(response); err != nil {
		h.logger.WithError(err).Error("Failed to write version response")
	}
}
