package monitoring

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	logrustest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MonfreeAddr reserves an ephemeral loopback port and releases it again so a
// test can hand a concrete address to a server that only accepts a string.
func MonfreeAddr(t *testing.T) string {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := listener.Addr().String()
	require.NoError(t, listener.Close())
	return addr
}

// Monserve runs one request against the monitoring mux without binding a port.
func Monserve(t *testing.T, s *Server, method, target string) *httptest.ResponseRecorder {
	t.Helper()

	rec := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rec, httptest.NewRequest(method, target, nil))
	return rec
}

func TestMonNewServerConfiguration(t *testing.T) {
	tests := []struct {
		name                 string
		cfg                  *Config
		expectedWriteTimeout time.Duration
	}{
		{
			name: "pprof disabled keeps a write timeout",
			cfg: &Config{
				BindAddress:  "127.0.0.1:19090",
				MetricsPath:  "/metrics",
				PprofEnabled: false,
			},
			expectedWriteTimeout: 30 * time.Second,
		},
		{
			name: "pprof enabled drops the write timeout so profiles are not cut off",
			cfg: &Config{
				BindAddress:  "127.0.0.1:19091",
				MetricsPath:  "/metrics",
				PprofEnabled: true,
			},
			expectedWriteTimeout: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewServer(tt.cfg)

			require.NotNil(t, s)
			require.NotNil(t, s.httpServer)
			require.NotNil(t, s.logger)
			assert.Equal(t, tt.cfg.BindAddress, s.httpServer.Addr)
			assert.Equal(t, tt.expectedWriteTimeout, s.httpServer.WriteTimeout)
			assert.Equal(t, 30*time.Second, s.httpServer.ReadTimeout)
			assert.Equal(t, 60*time.Second, s.httpServer.IdleTimeout)
			assert.Equal(t, "monitoring-server", s.logger.Data["component"])
		})
	}
}

func TestMonServerHealthEndpoint(t *testing.T) {
	s := NewServer(&Config{BindAddress: "127.0.0.1:0", MetricsPath: "/metrics"})

	rec := Monserve(t, s, http.MethodGet, "/health")

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "OK", rec.Body.String())
}

func TestMonServerInfoEndpoint(t *testing.T) {
	s := NewServer(&Config{BindAddress: "127.0.0.1:0", MetricsPath: "/metrics"})

	rec := Monserve(t, s, http.MethodGet, "/info")

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
	assert.JSONEq(t, `{"service":"s3-encryption-proxy","monitoring":"enabled"}`, rec.Body.String())
}

func TestMonServerMetricsEndpoint(t *testing.T) {
	// A custom metrics path must be honoured, and the default path must then
	// no longer answer.
	s := NewServer(&Config{BindAddress: "127.0.0.1:0", MetricsPath: "/mon-metrics"})

	// Produce a sample so the exposition output is not empty.
	RecordS3Operation("mon-metrics-endpoint", "mon-bucket", "success", time.Millisecond)

	rec := Monserve(t, s, http.MethodGet, "/mon-metrics")
	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()
	assert.Contains(t, rec.Header().Get("Content-Type"), "text/plain")
	assert.Contains(t, body, "s3ep_s3_operations_total")
	assert.Contains(t, body, `operation="mon-metrics-endpoint"`)

	notFound := Monserve(t, s, http.MethodGet, "/metrics")
	assert.Equal(t, http.StatusNotFound, notFound.Code,
		"only the configured metrics path may be served")
}

func TestMonServerPprofRegistration(t *testing.T) {
	tests := []struct {
		name           string
		pprofEnabled   bool
		expectedStatus int
	}{
		{name: "pprof disabled returns 404", pprofEnabled: false, expectedStatus: http.StatusNotFound},
		{name: "pprof enabled serves the index", pprofEnabled: true, expectedStatus: http.StatusOK},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hook := logrustest.NewGlobal()
			t.Cleanup(hook.Reset)

			s := NewServer(&Config{
				BindAddress:  "127.0.0.1:0",
				MetricsPath:  "/metrics",
				PprofEnabled: tt.pprofEnabled,
			})

			index := Monserve(t, s, http.MethodGet, "/debug/pprof/")
			assert.Equal(t, tt.expectedStatus, index.Code)

			cmdline := Monserve(t, s, http.MethodGet, "/debug/pprof/cmdline")
			assert.Equal(t, tt.expectedStatus, cmdline.Code)

			symbol := Monserve(t, s, http.MethodGet, "/debug/pprof/symbol")
			assert.Equal(t, tt.expectedStatus, symbol.Code)

			warned := false
			for _, entry := range hook.AllEntries() {
				if entry.Level == logrus.WarnLevel && strings.Contains(entry.Message, "pprof endpoints enabled") {
					warned = true
				}
			}
			assert.Equal(t, tt.pprofEnabled, warned,
				"enabling pprof must warn about the exposed admin surface")
		})
	}
}

func TestMonServerStartServesAndShutsDownOnContextCancel(t *testing.T) {
	addr := MonfreeAddr(t)
	s := NewServer(&Config{BindAddress: addr, MetricsPath: "/mon-metrics"})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- s.Start(ctx)
	}()

	client := &http.Client{Timeout: 2 * time.Second}
	url := "http://" + addr + "/health"

	require.Eventually(t, func() bool {
		resp, err := client.Get(url)
		if err != nil {
			return false
		}
		if err := resp.Body.Close(); err != nil {
			t.Logf("failed to close response body: %v", err)
		}
		return resp.StatusCode == http.StatusOK
	}, 5*time.Second, 5*time.Millisecond, "monitoring server must accept connections after Start")

	cancel()

	select {
	case err := <-errCh:
		require.NoError(t, err, "a graceful shutdown must not report an error")
	case <-time.After(15 * time.Second):
		t.Fatal("Start did not return after the context was cancelled")
	}

	// The listener must be gone once Start returned.
	require.Eventually(t, func() bool {
		resp, err := client.Get(url)
		if err != nil {
			return true
		}
		if err := resp.Body.Close(); err != nil {
			t.Logf("failed to close response body: %v", err)
		}
		return false
	}, 5*time.Second, 5*time.Millisecond, "the port must no longer be served after shutdown")
}

func TestMonServerStartLogsListenFailure(t *testing.T) {
	// Hold the port so ListenAndServe fails immediately.
	blocker, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() {
		if err := blocker.Close(); err != nil {
			t.Logf("failed to close blocking listener: %v", err)
		}
	})

	hook := logrustest.NewGlobal()
	t.Cleanup(hook.Reset)

	s := NewServer(&Config{BindAddress: blocker.Addr().String(), MetricsPath: "/metrics"})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- s.Start(ctx)
	}()

	require.Eventually(t, func() bool {
		for _, entry := range hook.AllEntries() {
			if entry.Level == logrus.ErrorLevel && strings.Contains(entry.Message, "Monitoring server error") {
				return true
			}
		}
		return false
	}, 5*time.Second, 5*time.Millisecond, "a failed bind must be logged")

	cancel()

	select {
	case err := <-errCh:
		// Known behaviour: a bind failure is only logged, Start still reports success.
		assert.NoError(t, err)
	case <-time.After(15 * time.Second):
		t.Fatal("Start did not return after the context was cancelled")
	}
}

func TestMonServerStop(t *testing.T) {
	addr := MonfreeAddr(t)
	s := NewServer(&Config{BindAddress: addr, MetricsPath: "/metrics"})

	// Stop is safe on a server that was never started.
	require.NoError(t, s.Stop())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	started := NewServer(&Config{BindAddress: addr, MetricsPath: "/metrics"})
	errCh := make(chan error, 1)
	go func() {
		errCh <- started.Start(ctx)
	}()

	client := &http.Client{Timeout: 2 * time.Second}
	url := "http://" + addr + "/health"
	require.Eventually(t, func() bool {
		resp, err := client.Get(url)
		if err != nil {
			return false
		}
		if err := resp.Body.Close(); err != nil {
			t.Logf("failed to close response body: %v", err)
		}
		return resp.StatusCode == http.StatusOK
	}, 5*time.Second, 5*time.Millisecond)

	require.NoError(t, started.Stop(), "Stop must close the listener without error")

	require.Eventually(t, func() bool {
		resp, err := client.Get(url)
		if err != nil {
			return true
		}
		if err := resp.Body.Close(); err != nil {
			t.Logf("failed to close response body: %v", err)
		}
		return false
	}, 5*time.Second, 5*time.Millisecond, "Stop must stop serving the port")

	cancel()
	select {
	case err := <-errCh:
		assert.NoError(t, err)
	case <-time.After(15 * time.Second):
		t.Fatal("Start did not return after the context was cancelled")
	}
}

// MonfailingWriter is a ResponseWriter whose body writes always fail, which is
// what a disconnected client looks like to a handler.
type MonfailingWriter struct {
	header http.Header
	status int
}

func (w *MonfailingWriter) Header() http.Header {
	if w.header == nil {
		w.header = http.Header{}
	}
	return w.header
}

func (w *MonfailingWriter) Write([]byte) (int, error) {
	return 0, errors.New("mon: connection reset by peer")
}

func (w *MonfailingWriter) WriteHeader(statusCode int) {
	w.status = statusCode
}

func TestMonServerEndpointsSurviveWriteFailures(t *testing.T) {
	s := NewServer(&Config{BindAddress: "127.0.0.1:0", MetricsPath: "/metrics"})

	tests := []struct {
		name           string
		target         string
		expectedStatus int
		expectedHeader string
	}{
		{
			name:           "health endpoint with a broken connection",
			target:         "/health",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "info endpoint with a broken connection",
			target:         "/info",
			expectedStatus: http.StatusOK,
			expectedHeader: "application/json",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := &MonfailingWriter{}

			// A failed body write must not panic; the status line is still sent.
			assert.NotPanics(t, func() {
				s.httpServer.Handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, tt.target, nil))
			})

			assert.Equal(t, tt.expectedStatus, w.status)
			if tt.expectedHeader != "" {
				assert.Equal(t, tt.expectedHeader, w.Header().Get("Content-Type"))
			}
		})
	}
}

// MonfailingListener fails on Close so that the graceful shutdown path has an
// error to propagate.
type MonfailingListener struct {
	net.Listener
	accepted atomic.Bool
}

func (l *MonfailingListener) Accept() (net.Conn, error) {
	l.accepted.Store(true)
	return l.Listener.Accept()
}

func (l *MonfailingListener) Close() error {
	_ = l.Listener.Close()
	return errors.New("mon: listener close failed")
}

func TestMonServerStartReportsShutdownFailure(t *testing.T) {
	// The bind itself fails immediately, so the only listener the server tracks
	// is the one handed to Serve below - and that one refuses to close.
	s := NewServer(&Config{BindAddress: "mon-invalid-address", MetricsPath: "/metrics"})

	base, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	failing := &MonfailingListener{Listener: base}

	serveDone := make(chan struct{})
	go func() {
		defer close(serveDone)
		_ = s.httpServer.Serve(failing)
	}()

	// Accept having been entered guarantees the listener is tracked by the
	// server and will therefore be closed during shutdown.
	require.Eventually(t, failing.accepted.Load, 5*time.Second, 5*time.Millisecond,
		"the server must have started accepting on the failing listener")

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- s.Start(ctx)
	}()
	cancel()

	select {
	case err := <-errCh:
		require.Error(t, err, "a failing shutdown must be reported to the caller")
		assert.Contains(t, err.Error(), "monitoring server shutdown failed")
		assert.Contains(t, err.Error(), "listener close failed",
			"the underlying cause must be wrapped, not swallowed")
	case <-time.After(15 * time.Second):
		t.Fatal("Start did not return after the context was cancelled")
	}

	select {
	case <-serveDone:
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return after shutdown")
	}
}
