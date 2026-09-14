package monitoring

import (
	"context"
	"github.com/sirupsen/logrus"
	logrustest "github.com/sirupsen/logrus/hooks/test"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The pprof listener is the one place profiling is served. It carries no write
// timeout on purpose: /debug/pprof/profile streams for the requested duration.
func TestPprofNewServerConfiguration(t *testing.T) {
	s := NewPprofServer("127.0.0.1:16060")

	require.NotNil(t, s)
	require.NotNil(t, s.httpServer)
	assert.Equal(t, "127.0.0.1:16060", s.httpServer.Addr)
	assert.Equal(t, 30*time.Second, s.httpServer.ReadTimeout)
	assert.Zero(t, s.httpServer.WriteTimeout,
		"a 30s CPU profile must not be cut off by a write timeout")
	assert.Equal(t, 60*time.Second, s.httpServer.IdleTimeout)
	assert.Equal(t, "pprof-server", s.logger.Data["component"])
}

// Every endpoint the monitoring mux used to carry is here instead, and nothing
// else is: /metrics stays on the monitoring listener so it can be scraped
// cluster-wide, and this one is loopback-only.
func TestPprofServerServesOnlyProfiling(t *testing.T) {
	s := NewPprofServer("127.0.0.1:0")

	for _, target := range []string{
		"/debug/pprof/",
		"/debug/pprof/cmdline",
		"/debug/pprof/heap",
		"/debug/pprof/goroutine",
	} {
		t.Run("serves "+target, func(t *testing.T) {
			assert.Equal(t, http.StatusOK, Monserve(t, &Server{httpServer: s.httpServer}, http.MethodGet, target).Code)
		})
	}

	for _, target := range []string{"/metrics", "/health", "/info"} {
		t.Run("does not serve "+target, func(t *testing.T) {
			assert.Equal(t, http.StatusNotFound,
				Monserve(t, &Server{httpServer: s.httpServer}, http.MethodGet, target).Code,
				"the pprof listener must not double as the monitoring listener")
		})
	}
}

func TestPprofServerStartServesAndShutsDownOnContextCancel(t *testing.T) {
	addr := MonfreeAddr(t)
	s := NewPprofServer(addr)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- s.Start(ctx) }()

	client := &http.Client{Timeout: 2 * time.Second}
	require.Eventually(t, func() bool {
		resp, err := client.Get("http://" + addr + "/debug/pprof/")
		if err != nil {
			return false
		}
		if err := resp.Body.Close(); err != nil {
			t.Logf("failed to close response body: %v", err)
		}
		return resp.StatusCode == http.StatusOK
	}, 5*time.Second, 5*time.Millisecond, "pprof server must accept connections after Start")

	cancel()

	select {
	case err := <-errCh:
		require.NoError(t, err, "a graceful shutdown must not report an error")
	case <-time.After(15 * time.Second):
		t.Fatal("Start did not return after the context was cancelled")
	}

	_, err := client.Get("http://" + addr + "/debug/pprof/")
	assert.Error(t, err, "the listener must be gone once Start returned")
}

// The two failure paths. 127.0.0.1:6060 is a shipped default now rather than an
// opt-in port, so a second proxy on the same host hits the bind error, and a
// profile in flight holds its connection open past the shutdown budget.
func TestPprofServerReportsItsFailures(t *testing.T) {
	t.Run("a bind that fails is logged, and Start still returns on cancel", func(t *testing.T) {
		hook := logrustest.NewGlobal()
		t.Cleanup(hook.Reset)

		// Hold the address so the server cannot have it.
		blocker, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		defer func() { _ = blocker.Close() }()

		s := NewPprofServer(blocker.Addr().String())

		ctx, cancel := context.WithCancel(context.Background())
		errCh := make(chan error, 1)
		go func() { errCh <- s.Start(ctx) }()

		require.Eventually(t, func() bool {
			for _, e := range hook.AllEntries() {
				if e.Level == logrus.ErrorLevel && strings.Contains(e.Message, "pprof server error") {
					return true
				}
			}
			return false
		}, 5*time.Second, 10*time.Millisecond,
			"a listener that never bound must say so; Start reports success either way")

		cancel()
		select {
		case err := <-errCh:
			assert.NoError(t, err)
		case <-time.After(10 * time.Second):
			t.Fatal("Start did not return after the context was cancelled")
		}
	})

	// A shutdown that cannot complete - a profile in flight holds its connection
	// for the full requested duration, and a listener can refuse to close. Start
	// must then force the listener closed and report the failure rather than delay
	// the process exit further.
	t.Run("a shutdown that fails is forced and reported", func(t *testing.T) {
		// The bind itself fails immediately, so the only listener the server
		// tracks is the one handed to Serve below - and that one refuses to close.
		s := NewPprofServer("mon-invalid-pprof-address")

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
		go func() { errCh <- s.Start(ctx) }()
		cancel()

		select {
		case err := <-errCh:
			require.Error(t, err, "a failing shutdown must be reported to the caller")
			assert.Contains(t, err.Error(), "pprof server shutdown failed")
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
	})
}
