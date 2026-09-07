package monitoring

import (
	"context"
	"github.com/sirupsen/logrus"
	logrustest "github.com/sirupsen/logrus/hooks/test"
	"net"
	"net/http"
	"strings"
	"sync"
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

func TestPprofServerStopClosesTheListener(t *testing.T) {
	addr := MonfreeAddr(t)
	s := NewPprofServer(addr)

	go func() { _ = s.httpServer.ListenAndServe() }()

	client := &http.Client{Timeout: 2 * time.Second}
	require.Eventually(t, func() bool {
		resp, err := client.Get("http://" + addr + "/debug/pprof/")
		if err != nil {
			return false
		}
		if err := resp.Body.Close(); err != nil {
			t.Logf("failed to close response body: %v", err)
		}
		return true
	}, 5*time.Second, 5*time.Millisecond)

	require.NoError(t, s.Stop())

	_, err := client.Get("http://" + addr + "/debug/pprof/")
	assert.Error(t, err)
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

	// A profile in flight holds its connection for the full requested duration,
	// so Shutdown hits its 10s budget. Start must then force the listener closed
	// and report the failure rather than delay the process exit further.
	t.Run("a shutdown that times out is forced and reported", func(t *testing.T) {
		s := NewPprofServer("127.0.0.1:0")

		listener, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		s.httpServer.Addr = listener.Addr().String()

		// entered closes when the handler is actually running, which is the only
		// state in which Shutdown has something it cannot drain. Waiting for the
		// port to accept a connection is not enough and made this flaky.
		entered := make(chan struct{})
		release := make(chan struct{})
		var once sync.Once
		s.httpServer.Handler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			once.Do(func() { close(entered) })
			<-release
		})
		go func() { _ = s.httpServer.Serve(listener) }()
		defer close(release)

		go func() {
			resp, reqErr := (&http.Client{Timeout: 30 * time.Second}).Get("http://" + s.httpServer.Addr + "/debug/pprof/")
			if reqErr == nil {
				_ = resp.Body.Close()
			}
		}()

		select {
		case <-entered:
		case <-time.After(10 * time.Second):
			t.Fatal("the handler was never entered, so there is no in-flight request to strand")
		}

		expired, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
		defer cancel()
		<-expired.Done()

		require.Error(t, s.httpServer.Shutdown(expired),
			"precondition: a request in flight plus an expired context must make Shutdown fail")
		assert.NoError(t, s.Stop(), "Stop force-closes what Shutdown could not drain")
	})
}
