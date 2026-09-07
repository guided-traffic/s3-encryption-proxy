package monitoring

import (
	"context"
	"net/http"
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
