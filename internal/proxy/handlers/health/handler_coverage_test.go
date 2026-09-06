package health

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	logrustest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// HlthnewTestLogger returns a logrus entry writing into a capturing test hook so
// that log emission can be asserted deterministically.
func HlthnewTestLogger() (*logrus.Entry, *logrustest.Hook) {
	logger, hook := logrustest.NewNullLogger()
	logger.SetLevel(logrus.DebugLevel)
	return logrus.NewEntry(logger), hook
}

// HlthfailingWriter is an http.ResponseWriter whose Write always fails. It is
// used to exercise the JSON encoding error branches of the handlers.
type HlthfailingWriter struct {
	header http.Header
	code   int
	writes int
}

func HlthnewFailingWriter() *HlthfailingWriter {
	return &HlthfailingWriter{header: make(http.Header)}
}

func (w *HlthfailingWriter) Header() http.Header { return w.header }

func (w *HlthfailingWriter) Write(_ []byte) (int, error) {
	w.writes++
	return 0, errors.New("Hlth: simulated write failure")
}

func (w *HlthfailingWriter) WriteHeader(statusCode int) { w.code = statusCode }

// HlthrecordingWriter records the relative order of body writes so that the
// deferred request-end tracker can be proven to run after the response body.
type HlthrecordingWriter struct {
	*httptest.ResponseRecorder
	events *[]string
}

func (w *HlthrecordingWriter) Write(p []byte) (int, error) {
	*w.events = append(*w.events, "write")
	return w.ResponseRecorder.Write(p)
}

func TestHlthNewHandler(t *testing.T) {
	logger, _ := HlthnewTestLogger()

	for _, tc := range []struct {
		name              string
		logHealthRequests bool
	}{
		{name: "logging disabled", logHealthRequests: false},
		{name: "logging enabled", logHealthRequests: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := NewHandler(logger, tc.logHealthRequests)

			require.NotNil(t, h)
			assert.Same(t, logger, h.logger)
			assert.Equal(t, tc.logHealthRequests, h.logHealthRequests)
			// A fresh handler has no optional collaborators wired up yet.
			assert.Nil(t, h.shutdownStateHandler)
			assert.Nil(t, h.requestStartHandler)
			assert.Nil(t, h.requestEndHandler)
		})
	}
}

func TestHlthSetShutdownStateHandler(t *testing.T) {
	logger, _ := HlthnewTestLogger()
	h := NewHandler(logger, false)

	expectedTime := time.Date(2024, 3, 1, 12, 30, 0, 0, time.UTC)
	h.SetShutdownStateHandler(func() (bool, time.Time) { return true, expectedTime })

	require.NotNil(t, h.shutdownStateHandler)
	shuttingDown, at := h.shutdownStateHandler()
	assert.True(t, shuttingDown)
	assert.Equal(t, expectedTime, at)
}

func TestHlthSetRequestTracker(t *testing.T) {
	logger, _ := HlthnewTestLogger()
	h := NewHandler(logger, false)

	started, ended := 0, 0
	h.SetRequestTracker(func() { started++ }, func() { ended++ })

	require.NotNil(t, h.requestStartHandler)
	require.NotNil(t, h.requestEndHandler)

	h.requestStartHandler()
	h.requestEndHandler()
	assert.Equal(t, 1, started)
	assert.Equal(t, 1, ended)
}

func TestHlthHealthHealthyResponse(t *testing.T) {
	logger, _ := HlthnewTestLogger()
	h := NewHandler(logger, false)

	rr := httptest.NewRecorder()
	h.Health(rr, httptest.NewRequest(http.MethodGet, "/health", nil))

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))
	// json.Encoder terminates the document with a newline.
	assert.Equal(t, "{\"status\":\"healthy\"}\n", rr.Body.String())

	var body map[string]string
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
	assert.Equal(t, map[string]string{"status": "healthy"}, body)
}

func TestHlthHealthShutdownStateHandlerVariants(t *testing.T) {
	shutdownAt := time.Date(2025, 7, 4, 8, 15, 30, 0, time.FixedZone("CEST", 2*60*60))

	for _, tc := range []struct {
		name     string
		handler  func() (bool, time.Time)
		wantCode int
		wantBody map[string]string
	}{
		{
			name:     "no shutdown handler configured",
			handler:  nil,
			wantCode: http.StatusOK,
			wantBody: map[string]string{"status": "healthy"},
		},
		{
			name:     "shutdown not initiated",
			handler:  func() (bool, time.Time) { return false, time.Time{} },
			wantCode: http.StatusOK,
			wantBody: map[string]string{"status": "healthy"},
		},
		{
			name:     "shutdown initiated",
			handler:  func() (bool, time.Time) { return true, shutdownAt },
			wantCode: http.StatusServiceUnavailable,
			wantBody: map[string]string{
				"status":        "shutting_down",
				"shutdown_time": "2025-07-04T08:15:30+02:00",
				"message":       "Server is shutting down gracefully",
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logger, _ := HlthnewTestLogger()
			h := NewHandler(logger, false)
			if tc.handler != nil {
				h.SetShutdownStateHandler(tc.handler)
			}

			rr := httptest.NewRecorder()
			h.Health(rr, httptest.NewRequest(http.MethodGet, "/health", nil))

			assert.Equal(t, tc.wantCode, rr.Code)
			assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))

			var body map[string]string
			require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
			assert.Equal(t, tc.wantBody, body)

			// The shutdown timestamp must be a parsable RFC3339 value.
			if raw, ok := body["shutdown_time"]; ok {
				parsed, err := time.Parse(time.RFC3339, raw)
				require.NoError(t, err)
				assert.True(t, parsed.Equal(shutdownAt), "timestamp must round-trip")
			}
		})
	}
}

func TestHlthHealthShutdownStateIsReEvaluatedPerRequest(t *testing.T) {
	logger, _ := HlthnewTestLogger()
	h := NewHandler(logger, false)

	shuttingDown := false
	h.SetShutdownStateHandler(func() (bool, time.Time) {
		return shuttingDown, time.Unix(0, 0).UTC()
	})

	first := httptest.NewRecorder()
	h.Health(first, httptest.NewRequest(http.MethodGet, "/health", nil))
	assert.Equal(t, http.StatusOK, first.Code)

	shuttingDown = true

	second := httptest.NewRecorder()
	h.Health(second, httptest.NewRequest(http.MethodGet, "/health", nil))
	assert.Equal(t, http.StatusServiceUnavailable, second.Code)
	assert.Contains(t, second.Body.String(), "shutting_down")
	assert.Contains(t, second.Body.String(), "1970-01-01T00:00:00Z")
}

func TestHlthVersionResponse(t *testing.T) {
	logger, _ := HlthnewTestLogger()
	h := NewHandler(logger, false)
	// Version must ignore the shutdown state and stay available.
	h.SetShutdownStateHandler(func() (bool, time.Time) { return true, time.Now() })

	rr := httptest.NewRecorder()
	h.Version(rr, httptest.NewRequest(http.MethodGet, "/version", nil))

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))

	var body map[string]string
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
	assert.Equal(t, map[string]string{
		"version": "dev",
		"service": "s3-encryption-proxy",
	}, body)
}

func TestHlthRequestTrackerInvocation(t *testing.T) {
	for _, tc := range []struct {
		name   string
		invoke func(h *Handler, w http.ResponseWriter, r *http.Request)
		path   string
	}{
		{
			name:   "health",
			invoke: func(h *Handler, w http.ResponseWriter, r *http.Request) { h.Health(w, r) },
			path:   "/health",
		},
		{
			name:   "version",
			invoke: func(h *Handler, w http.ResponseWriter, r *http.Request) { h.Version(w, r) },
			path:   "/version",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logger, _ := HlthnewTestLogger()
			h := NewHandler(logger, false)

			var events []string
			h.SetRequestTracker(
				func() { events = append(events, "start") },
				func() { events = append(events, "end") },
			)

			rr := &HlthrecordingWriter{ResponseRecorder: httptest.NewRecorder(), events: &events}
			tc.invoke(h, rr, httptest.NewRequest(http.MethodGet, tc.path, nil))

			// The end tracker is deferred, so it must run after the body write.
			assert.Equal(t, []string{"start", "write", "end"}, events)
			assert.Equal(t, http.StatusOK, rr.Code)
		})
	}
}

func TestHlthRequestTrackerIsBalancedAcrossRequests(t *testing.T) {
	logger, _ := HlthnewTestLogger()
	h := NewHandler(logger, false)
	h.SetShutdownStateHandler(func() (bool, time.Time) { return true, time.Unix(0, 0).UTC() })

	active, maxActive := 0, 0
	h.SetRequestTracker(
		func() {
			active++
			if active > maxActive {
				maxActive = active
			}
		},
		func() { active-- },
	)

	for i := 0; i < 3; i++ {
		rr := httptest.NewRecorder()
		h.Health(rr, httptest.NewRequest(http.MethodGet, "/health", nil))
		require.Equal(t, http.StatusServiceUnavailable, rr.Code)
	}

	// Even on the early-return shutdown path the counter must be released.
	assert.Equal(t, 0, active)
	assert.Equal(t, 1, maxActive)
}

func TestHlthRequestTrackerPartiallyConfigured(t *testing.T) {
	for _, tc := range []struct {
		name      string
		setStart  bool
		setEnd    bool
		wantStart int
		wantEnd   int
	}{
		{name: "only start handler", setStart: true, setEnd: false, wantStart: 2, wantEnd: 0},
		{name: "only end handler", setStart: false, setEnd: true, wantStart: 0, wantEnd: 2},
		{name: "no handlers", setStart: false, setEnd: false, wantStart: 0, wantEnd: 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logger, _ := HlthnewTestLogger()
			h := NewHandler(logger, false)

			started, ended := 0, 0
			var onStart, onEnd func()
			if tc.setStart {
				onStart = func() { started++ }
			}
			if tc.setEnd {
				onEnd = func() { ended++ }
			}
			h.SetRequestTracker(onStart, onEnd)

			healthRR := httptest.NewRecorder()
			h.Health(healthRR, httptest.NewRequest(http.MethodGet, "/health", nil))
			versionRR := httptest.NewRecorder()
			h.Version(versionRR, httptest.NewRequest(http.MethodGet, "/version", nil))

			assert.Equal(t, http.StatusOK, healthRR.Code)
			assert.Equal(t, http.StatusOK, versionRR.Code)
			assert.Equal(t, tc.wantStart, started)
			assert.Equal(t, tc.wantEnd, ended)
		})
	}
}

func TestHlthLogHealthRequests(t *testing.T) {
	for _, tc := range []struct {
		name        string
		logRequests bool
		invoke      func(h *Handler, w http.ResponseWriter, r *http.Request)
		path        string
		wantMessage string
	}{
		{
			name:        "health logs when enabled",
			logRequests: true,
			invoke:      func(h *Handler, w http.ResponseWriter, r *http.Request) { h.Health(w, r) },
			path:        "/health",
			wantMessage: "Health check request",
		},
		{
			name:        "version logs when enabled",
			logRequests: true,
			invoke:      func(h *Handler, w http.ResponseWriter, r *http.Request) { h.Version(w, r) },
			path:        "/version",
			wantMessage: "Version check request",
		},
		{
			name:        "health silent when disabled",
			logRequests: false,
			invoke:      func(h *Handler, w http.ResponseWriter, r *http.Request) { h.Health(w, r) },
			path:        "/health",
		},
		{
			name:        "version silent when disabled",
			logRequests: false,
			invoke:      func(h *Handler, w http.ResponseWriter, r *http.Request) { h.Version(w, r) },
			path:        "/version",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logger, hook := HlthnewTestLogger()
			h := NewHandler(logger, tc.logRequests)

			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			req.RemoteAddr = "203.0.113.7:54321"

			rr := httptest.NewRecorder()
			tc.invoke(h, rr, req)

			assert.Equal(t, http.StatusOK, rr.Code)

			if tc.wantMessage == "" {
				assert.Empty(t, hook.AllEntries(), "no log entry expected when logging is disabled")
				return
			}

			entries := hook.AllEntries()
			require.Len(t, entries, 1)
			entry := entries[0]
			assert.Equal(t, logrus.DebugLevel, entry.Level)
			assert.Equal(t, tc.wantMessage, entry.Message)
			assert.Equal(t, http.MethodGet, entry.Data["method"])
			assert.Equal(t, tc.path, entry.Data["path"])
			assert.Equal(t, "203.0.113.7:54321", entry.Data["remote"])
		})
	}
}

func TestHlthResponseWriteFailureIsLogged(t *testing.T) {
	for _, tc := range []struct {
		name        string
		setup       func(h *Handler)
		invoke      func(h *Handler, w http.ResponseWriter, r *http.Request)
		path        string
		wantCode    int
		wantMessage string
	}{
		{
			name:        "healthy response write fails",
			invoke:      func(h *Handler, w http.ResponseWriter, r *http.Request) { h.Health(w, r) },
			path:        "/health",
			wantCode:    http.StatusOK,
			wantMessage: "Failed to write health response",
		},
		{
			name: "shutdown response write fails",
			setup: func(h *Handler) {
				h.SetShutdownStateHandler(func() (bool, time.Time) { return true, time.Unix(0, 0).UTC() })
			},
			invoke:      func(h *Handler, w http.ResponseWriter, r *http.Request) { h.Health(w, r) },
			path:        "/health",
			wantCode:    http.StatusServiceUnavailable,
			wantMessage: "Failed to write health response",
		},
		{
			name:        "version response write fails",
			invoke:      func(h *Handler, w http.ResponseWriter, r *http.Request) { h.Version(w, r) },
			path:        "/version",
			wantCode:    http.StatusOK,
			wantMessage: "Failed to write version response",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logger, hook := HlthnewTestLogger()
			h := NewHandler(logger, false)
			if tc.setup != nil {
				tc.setup(h)
			}

			ended := 0
			h.SetRequestTracker(func() {}, func() { ended++ })

			w := HlthnewFailingWriter()
			tc.invoke(h, w, httptest.NewRequest(http.MethodGet, tc.path, nil))

			assert.Equal(t, tc.wantCode, w.code)
			assert.Equal(t, "application/json", w.header.Get("Content-Type"))
			assert.Positive(t, w.writes, "handler must have attempted a body write")
			assert.Equal(t, 1, ended, "request tracking must be released even on write failure")

			entries := hook.AllEntries()
			require.Len(t, entries, 1)
			assert.Equal(t, logrus.ErrorLevel, entries[0].Level)
			assert.Equal(t, tc.wantMessage, entries[0].Message)
			loggedErr, ok := entries[0].Data[logrus.ErrorKey].(error)
			require.True(t, ok, "log entry must carry the write error")
			assert.EqualError(t, loggedErr, "Hlth: simulated write failure")
		})
	}
}
