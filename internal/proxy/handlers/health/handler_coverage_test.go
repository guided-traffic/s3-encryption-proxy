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

// Hlthprobe is one of the two endpoints, so every shared property is asserted
// for both without writing it twice.
type Hlthprobe struct {
	name   string
	path   string
	invoke func(h *Handler, w http.ResponseWriter, r *http.Request)
	logged string
}

var Hlthprobes = []Hlthprobe{
	{
		name:   "livez",
		path:   "/livez",
		invoke: func(h *Handler, w http.ResponseWriter, r *http.Request) { h.Live(w, r) },
		logged: "Liveness probe",
	},
	{
		name:   "readyz",
		path:   "/readyz",
		invoke: func(h *Handler, w http.ResponseWriter, r *http.Request) { h.Ready(w, r) },
		logged: "Readiness probe",
	},
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

// The defect this endpoint exists to remove: one handler served both probes and
// answered 503 from the moment the drain started, so a draining pod failed its
// liveness probe by design and a kill inside the grace period skipped the
// multipart sweep entirely (ADR 0028, ADR 0029 D1). Liveness answers 200 while
// the drain runs, and it reports nothing else either (ADR 0034).
func TestHlthLiveIsConstantEvenWhileDraining(t *testing.T) {
	for _, tc := range []struct {
		name    string
		handler func() (bool, time.Time)
	}{
		{name: "no shutdown handler configured", handler: nil},
		{name: "not draining", handler: func() (bool, time.Time) { return false, time.Time{} }},
		{
			name:    "draining",
			handler: func() (bool, time.Time) { return true, time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC) },
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logger, _ := HlthnewTestLogger()
			h := NewHandler(logger, false)
			if tc.handler != nil {
				h.SetShutdownStateHandler(tc.handler)
			}

			rr := httptest.NewRecorder()
			h.Live(rr, httptest.NewRequest(http.MethodGet, "/livez", nil))

			require.Equal(t, http.StatusOK, rr.Code,
				"a restart repairs nothing a liveness probe could detect here, so it never fails")
			assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))
			// json.Encoder terminates the document with a newline.
			assert.Equal(t, "{\"status\":\"alive\"}\n", rr.Body.String())
			assert.NotContains(t, rr.Body.String(), "shutting_down",
				"liveness must not report the drain")
		})
	}
}

// The drain is a per-request state: the same handler answers 200 and then 503
// on the same running server, which is exactly how main installs it.
func TestHlthReadyReportsTheDrain(t *testing.T) {
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
			wantBody: map[string]string{"status": "ready"},
		},
		{
			name:     "shutdown not initiated",
			handler:  func() (bool, time.Time) { return false, time.Time{} },
			wantCode: http.StatusOK,
			wantBody: map[string]string{"status": "ready"},
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
			h.Ready(rr, httptest.NewRequest(http.MethodGet, "/readyz", nil))

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

func TestHlthReadyShutdownStateIsReEvaluatedPerRequest(t *testing.T) {
	logger, _ := HlthnewTestLogger()
	h := NewHandler(logger, false)

	shuttingDown := false
	h.SetShutdownStateHandler(func() (bool, time.Time) {
		return shuttingDown, time.Unix(0, 0).UTC()
	})

	first := httptest.NewRecorder()
	h.Ready(first, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	assert.Equal(t, http.StatusOK, first.Code)

	shuttingDown = true

	second := httptest.NewRecorder()
	h.Ready(second, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	assert.Equal(t, http.StatusServiceUnavailable, second.Code)
	assert.Contains(t, second.Body.String(), "shutting_down")
	assert.Contains(t, second.Body.String(), "1970-01-01T00:00:00Z")

	// Liveness on the same handler is unaffected by that state.
	live := httptest.NewRecorder()
	h.Live(live, httptest.NewRequest(http.MethodGet, "/livez", nil))
	assert.Equal(t, http.StatusOK, live.Code)
}

func TestHlthRequestTrackerInvocation(t *testing.T) {
	for _, probe := range Hlthprobes {
		t.Run(probe.name, func(t *testing.T) {
			logger, _ := HlthnewTestLogger()
			h := NewHandler(logger, false)

			var events []string
			h.SetRequestTracker(
				func() { events = append(events, "start") },
				func() { events = append(events, "end") },
			)

			rr := &HlthrecordingWriter{ResponseRecorder: httptest.NewRecorder(), events: &events}
			probe.invoke(h, rr, httptest.NewRequest(http.MethodGet, probe.path, nil))

			// The end tracker is deferred, so it must run after the body write.
			assert.Equal(t, []string{"start", "write", "end"}, events)
			assert.Equal(t, http.StatusOK, rr.Code)
		})
	}
}

func TestHlthRequestTrackerIsBalancedAcrossRequests(t *testing.T) {
	for _, probe := range Hlthprobes {
		t.Run(probe.name, func(t *testing.T) {
			logger, _ := HlthnewTestLogger()
			h := NewHandler(logger, false)
			// Draining: readiness takes its early return here, liveness does not.
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
				probe.invoke(h, rr, httptest.NewRequest(http.MethodGet, probe.path, nil))
			}

			// Even on the early-return shutdown path the counter is released.
			assert.Equal(t, 0, active)
			assert.Equal(t, 1, maxActive)
		})
	}
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

			liveRR := httptest.NewRecorder()
			h.Live(liveRR, httptest.NewRequest(http.MethodGet, "/livez", nil))
			readyRR := httptest.NewRecorder()
			h.Ready(readyRR, httptest.NewRequest(http.MethodGet, "/readyz", nil))

			assert.Equal(t, http.StatusOK, liveRR.Code)
			assert.Equal(t, http.StatusOK, readyRR.Code)
			assert.Equal(t, tc.wantStart, started)
			assert.Equal(t, tc.wantEnd, ended)
		})
	}
}

func TestHlthLogHealthRequests(t *testing.T) {
	for _, probe := range Hlthprobes {
		for _, logRequests := range []bool{true, false} {
			name := probe.name + " silent when disabled"
			if logRequests {
				name = probe.name + " logs when enabled"
			}

			t.Run(name, func(t *testing.T) {
				logger, hook := HlthnewTestLogger()
				h := NewHandler(logger, logRequests)

				req := httptest.NewRequest(http.MethodGet, probe.path, nil)
				req.RemoteAddr = "203.0.113.7:54321"

				rr := httptest.NewRecorder()
				probe.invoke(h, rr, req)

				assert.Equal(t, http.StatusOK, rr.Code)

				if !logRequests {
					assert.Empty(t, hook.AllEntries(), "no log entry expected when logging is disabled")
					return
				}

				entries := hook.AllEntries()
				require.Len(t, entries, 1)
				entry := entries[0]
				assert.Equal(t, logrus.DebugLevel, entry.Level)
				assert.Equal(t, probe.logged, entry.Message)
				assert.Equal(t, http.MethodGet, entry.Data["method"])
				assert.Equal(t, probe.path, entry.Data["path"])
				assert.Equal(t, "203.0.113.7:54321", entry.Data["remote"])
			})
		}
	}
}

func TestHlthResponseWriteFailureIsLogged(t *testing.T) {
	for _, tc := range []struct {
		name     string
		setup    func(h *Handler)
		invoke   func(h *Handler, w http.ResponseWriter, r *http.Request)
		path     string
		wantCode int
	}{
		{
			name:     "liveness response write fails",
			invoke:   func(h *Handler, w http.ResponseWriter, r *http.Request) { h.Live(w, r) },
			path:     "/livez",
			wantCode: http.StatusOK,
		},
		{
			name:     "readiness response write fails",
			invoke:   func(h *Handler, w http.ResponseWriter, r *http.Request) { h.Ready(w, r) },
			path:     "/readyz",
			wantCode: http.StatusOK,
		},
		{
			name: "shutdown response write fails",
			setup: func(h *Handler) {
				h.SetShutdownStateHandler(func() (bool, time.Time) { return true, time.Unix(0, 0).UTC() })
			},
			invoke:   func(h *Handler, w http.ResponseWriter, r *http.Request) { h.Ready(w, r) },
			path:     "/readyz",
			wantCode: http.StatusServiceUnavailable,
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
			assert.Equal(t, "Failed to write probe response", entries[0].Message)
			loggedErr, ok := entries[0].Data[logrus.ErrorKey].(error)
			require.True(t, ok, "log entry must carry the write error")
			assert.EqualError(t, loggedErr, "Hlth: simulated write failure")
		})
	}
}
