package health

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/sirupsen/logrus"
)

// Handler serves the two probe endpoints of the S3 listener.
type Handler struct {
	logger               *logrus.Entry
	logHealthRequests    bool
	shutdownStateHandler func() (bool, time.Time)
	requestStartHandler  func()
	requestEndHandler    func()
}

// NewHandler creates a new probe handler
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

// Live answers the liveness probe, and it answers 200 unconditionally: it
// reports neither the drain, nor the backend, nor the licence, nor the
// configuration. The only reaction kubelet has to a failing liveness probe is to
// kill the container and restart it, and a restart repairs none of those — for
// the backend it would turn a foreign outage into a crash loop that strands
// exactly the multipart uploads the shutdown sweep exists to end (ADR 0028,
// ADR 0034). What is left is the single case a liveness probe is for: a process
// that is alive but can no longer answer HTTP. Add no check here.
func (h *Handler) Live(w http.ResponseWriter, r *http.Request) {
	defer h.track(r, "Liveness probe")()

	h.writeJSON(w, http.StatusOK, map[string]string{"status": "alive"})
}

// Ready answers the readiness probe: whether this instance wants and can take
// traffic. The drain is the only thing that may make it false — readiness is a
// lifecycle signal and never a load signal, because a probe that reports
// pressure takes the pod out of rotation and moves its share onto the pods that
// are left (ADR 0034). It keeps answering while the server drains: the listener
// closes last (ADR 0029 D1), so a probe during the sweep reads a refusal rather
// than a connection error.
func (h *Handler) Ready(w http.ResponseWriter, r *http.Request) {
	defer h.track(r, "Readiness probe")()

	if h.shutdownStateHandler != nil {
		if shutdownInitiated, shutdownTime := h.shutdownStateHandler(); shutdownInitiated {
			h.writeJSON(w, http.StatusServiceUnavailable, map[string]string{
				"status":        "shutting_down",
				"shutdown_time": shutdownTime.Format(time.RFC3339),
				"message":       "Server is shutting down gracefully",
			})
			return
		}
	}

	h.writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

// track counts the request for the drain and records it when
// log_health_requests is on. The returned function releases the count and is
// deferred by the caller, so it runs after the body has been written.
func (h *Handler) track(r *http.Request, message string) func() {
	if h.requestStartHandler != nil {
		h.requestStartHandler()
	}

	if h.logHealthRequests {
		h.logger.WithFields(logrus.Fields{
			"method": r.Method,
			"path":   r.URL.Path,
			"remote": r.RemoteAddr,
		}).Debug(message)
	}

	return func() {
		if h.requestEndHandler != nil {
			h.requestEndHandler()
		}
	}
}

func (h *Handler) writeJSON(w http.ResponseWriter, status int, body map[string]string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	if err := json.NewEncoder(w).Encode(body); err != nil {
		h.logger.WithError(err).Error("Failed to write probe response")
	}
}
