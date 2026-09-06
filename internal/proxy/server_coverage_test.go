package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/guided-traffic/s3-encryption-proxy/internal/config"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// RtPxaesKey is a 32-byte AES key, base64 encoded, for tests only.
const RtPxaesKey = "1UR+yQO2Ap3NJabyhkwSm0qk/vllEa2Jae+NSxyVas8="

// RtPxaccessKey / RtPxsecretKey are the client credentials the signed-request
// tests use. The secret has to be at least 16 characters, see config validation.
const (
	RtPxaccessKey = "RTPXTESTACCESSKEY"
	RtPxsecretKey = "rtpx-test-secret-key-0001"
	RtPxhost      = "proxy.rtpx.test"
)

// RtPxquietWriter swallows log output so a failing test prints assertions only.
type RtPxquietWriter struct{}

func (RtPxquietWriter) Write(p []byte) (int, error) { return len(p), nil }

// RtPxconfig returns a configuration that NewServer accepts: one active AES KEK
// provider and one static S3 client.
func RtPxconfig() *config.Config {
	return &config.Config{
		BindAddress: "127.0.0.1:0",
		LogLevel:    "error",
		S3Backend: config.S3BackendConfig{
			TargetEndpoint: "https://minio.invalid:9000",
			Region:         "us-east-1",
			AccessKeyID:    "backend-key",
			SecretKey:      "backend-secret",
		},
		S3Clients: []config.S3ClientCredentials{
			{
				Type:        "static",
				AccessKeyID: RtPxaccessKey,
				SecretKey:   RtPxsecretKey,
				Description: "RtPx test client",
			},
		},
		Encryption: config.EncryptionConfig{
			EncryptionMethodAlias: "rtpx-active",
			Providers: []config.EncryptionProvider{
				{
					Alias:  "rtpx-active",
					Type:   "aes",
					Config: map[string]interface{}{"aes_key": RtPxaesKey},
				},
			},
		},
	}
}

// RtPxstringPtr is the *string helper the optional metadata prefix needs.
func RtPxstringPtr(s string) *string { return &s }

// A configuration the encryption manager cannot use must fail at NewServer, not
// at the first request: a proxy that starts without a usable KEK provider would
// answer PUTs it cannot encrypt.
func TestRtPxNewServerRejectsUnusableConfig(t *testing.T) {
	logrus.SetLevel(logrus.ErrorLevel)

	cases := []struct {
		name    string
		cfg     *config.Config
		wantMsg string
	}{
		{
			name:    "nil configuration",
			cfg:     nil,
			wantMsg: "failed to create encryption manager",
		},
		{
			name: "active alias names no configured provider",
			cfg: func() *config.Config {
				c := RtPxconfig()
				c.Encryption.EncryptionMethodAlias = "does-not-exist"
				return c
			}(),
			wantMsg: "failed to create encryption manager",
		},
		{
			name: "unsupported provider type",
			cfg: func() *config.Config {
				c := RtPxconfig()
				c.Encryption.Providers[0].Type = "quantum"
				return c
			}(),
			wantMsg: "invalid type 'quantum'",
		},
		{
			name: "AES key is not usable key material",
			cfg: func() *config.Config {
				c := RtPxconfig()
				c.Encryption.Providers[0].Config = map[string]interface{}{"aes_key": "not-base64-!!"}
				return c
			}(),
			wantMsg: "failed to create key encryptor",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server, err := NewServer(tc.cfg)
			require.Error(t, err)
			assert.Nil(t, server, "a server must not be returned alongside an error")
			assert.Contains(t, err.Error(), tc.wantMsg)
		})
	}
}

// The metadata prefix is what tells a later read which S3 user metadata belongs
// to the proxy. An explicitly empty prefix is a deliberate configuration and
// must not silently become the default.
func TestRtPxMetadataPrefixResolution(t *testing.T) {
	logrus.SetLevel(logrus.ErrorLevel)

	cases := []struct {
		name   string
		prefix *string
		want   string
	}{
		{name: "not set in config uses the default", prefix: nil, want: "s3ep-"},
		{name: "explicit empty prefix is honoured", prefix: RtPxstringPtr(""), want: ""},
		{name: "explicit value is honoured", prefix: RtPxstringPtr("rtpx-"), want: "rtpx-"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := RtPxconfig()
			cfg.Encryption.MetadataKeyPrefix = tc.prefix

			server, err := NewServer(cfg)
			require.NoError(t, err)
			assert.Equal(t, tc.want, server.getMetadataPrefix())
		})
	}
}

// Every configured KEK provider has to be loaded so old objects stay readable,
// and exactly the aliased one may be used for writes. The distinction is
// operator-visible in the startup log.
func TestRtPxNewServerLoadsAllProvidersButActivatesOne(t *testing.T) {
	var buf bytes.Buffer
	std := logrus.StandardLogger()
	oldOut, oldLevel := std.Out, std.GetLevel()
	std.SetOutput(&buf)
	std.SetLevel(logrus.InfoLevel)
	defer func() {
		std.SetOutput(oldOut)
		std.SetLevel(oldLevel)
	}()

	cfg := RtPxconfig()
	cfg.Encryption.Providers = append(cfg.Encryption.Providers, config.EncryptionProvider{
		Alias:  "rtpx-retired",
		Type:   "aes",
		Config: map[string]interface{}{"aes_key": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="},
	})

	server, err := NewServer(cfg)
	require.NoError(t, err)

	providers := server.encryptionMgr.GetLoadedProviders()
	require.Len(t, providers, 2, "a retired provider must stay loaded so its objects remain readable")

	active := map[string]bool{}
	for _, p := range providers {
		active[p.Alias] = p.IsActive
		assert.NotEmpty(t, p.Fingerprint, "every provider needs a fingerprint for decryption selection")
	}
	assert.True(t, active["rtpx-active"], "the aliased provider encrypts new writes")
	assert.False(t, active["rtpx-retired"], "a non-aliased provider must never be selected for writes")

	logged := buf.String()
	assert.Contains(t, logged, "Active KEK provider")
	assert.Contains(t, logged, "Available KEK provider")
	assert.NotContains(t, logged, RtPxaesKey, "key material must never be logged")
}

// SetShutdownStateHandler is what a readiness probe sees during a graceful
// shutdown: /health has to flip to 503 so no new traffic is routed to a
// draining instance. The handler is set after NewServer, which is exactly how
// cmd/s3-encryption-proxy/main.go uses it.
func TestRtPxHealthReportsShutdownState(t *testing.T) {
	logrus.SetLevel(logrus.ErrorLevel)

	server, err := NewServer(RtPxconfig())
	require.NoError(t, err)

	get := func() *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		server.httpServer.Handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/health", nil))
		return w
	}

	// Before shutdown.
	w := get()
	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))
	var healthy map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &healthy))
	assert.Equal(t, "healthy", healthy["status"])

	// After shutdown was initiated, on the very same running server.
	shutdownAt := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	server.SetShutdownStateHandler(func() (bool, time.Time) { return true, shutdownAt })

	w = get()
	require.Equal(t, http.StatusServiceUnavailable, w.Code,
		"a draining server must report 503 to its readiness probe")
	var draining map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &draining))
	assert.Equal(t, "shutting_down", draining["status"])
	assert.Equal(t, shutdownAt.Format(time.RFC3339), draining["shutdown_time"])
}

// SetRequestTracker feeds the drain loop in main: a request that is in flight
// when the signal arrives must keep the counter above zero.
func TestRtPxRequestTrackerCountsRequests(t *testing.T) {
	logrus.SetLevel(logrus.ErrorLevel)

	server, err := NewServer(RtPxconfig())
	require.NoError(t, err)

	var started, ended, inFlightDuringRequest int
	server.SetRequestTracker(
		func() { started++ },
		func() { ended++ },
	)
	server.SetShutdownStateHandler(func() (bool, time.Time) {
		inFlightDuringRequest = started - ended
		return false, time.Time{}
	})

	w := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/health", nil))

	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, 1, started, "the request start handler must run once per request")
	assert.Equal(t, 1, ended, "the request end handler must run once per request")
	assert.Equal(t, 1, inFlightDuringRequest, "the counter has to be above zero while the request runs")
}

// GetHandler builds a fresh router; it must be usable on its own and must not
// hand out the running server's handler instance.
func TestRtPxGetHandlerBuildsUsableRouter(t *testing.T) {
	logrus.SetLevel(logrus.ErrorLevel)

	server, err := NewServer(RtPxconfig())
	require.NoError(t, err)

	handler := server.GetHandler()
	require.NotNil(t, handler)
	assert.NotSame(t, server.httpServer.Handler, handler, "GetHandler must not return the live handler")

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/version", nil))
	require.Equal(t, http.StatusOK, w.Code)

	var version map[string]string
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &version))
	assert.Equal(t, "s3-encryption-proxy", version["service"])
}

// A bind address the OS cannot serve has to surface as an error from Start, not
// as a server that silently never listens.
func TestRtPxStartReportsListenFailure(t *testing.T) {
	logrus.SetLevel(logrus.ErrorLevel)

	cfg := RtPxconfig()
	cfg.BindAddress = "127.0.0.1:99999" // outside the valid port range
	server, err := NewServer(cfg)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = server.Start(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "HTTP server failed")
	assert.NotContains(t, err.Error(), "HTTPS", "TLS is disabled in this configuration")
}

// A cancelled context shuts the server down gracefully and reports no error.
func TestRtPxStartShutsDownOnContextCancel(t *testing.T) {
	logrus.SetLevel(logrus.ErrorLevel)

	server, err := NewServer(RtPxconfig()) // port 0: the OS picks a free port
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled: Start must return through the shutdown path

	done := make(chan error, 1)
	go func() { done <- server.Start(ctx) }()

	select {
	case err := <-done:
		assert.NoError(t, err, "a cancelled context is a graceful shutdown, not a failure")
	case <-time.After(10 * time.Second):
		t.Fatal("Start did not return after context cancellation")
	}
}

// RtPxfailingListener is a listener that never accepts and reports a failure
// when it is closed, which is what Shutdown sees when a listener cannot be
// released (a unix socket whose file is gone, for instance).
type RtPxfailingListener struct {
	accepting chan struct{}
	closed    chan struct{}
	acceptOne sync.Once
	closeOne  sync.Once
}

func RtPxnewFailingListener() *RtPxfailingListener {
	return &RtPxfailingListener{
		accepting: make(chan struct{}),
		closed:    make(chan struct{}),
	}
}

func (l *RtPxfailingListener) Accept() (net.Conn, error) {
	l.acceptOne.Do(func() { close(l.accepting) })
	<-l.closed
	return nil, errors.New("rtpx listener closed")
}

func (l *RtPxfailingListener) Close() error {
	l.closeOne.Do(func() { close(l.closed) })
	return errors.New("rtpx listener close failed")
}

func (l *RtPxfailingListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
}

// A shutdown that does not complete cleanly must be reported, not swallowed:
// the exit code is what tells an orchestrator whether the drain worked.
func TestRtPxStartReportsShutdownFailure(t *testing.T) {
	logrus.SetLevel(logrus.ErrorLevel)

	server, err := NewServer(RtPxconfig())
	require.NoError(t, err)

	ln := RtPxnewFailingListener()
	served := make(chan struct{})
	go func() {
		defer close(served)
		_ = server.httpServer.Serve(ln)
	}()

	// Serve registers the listener before its first Accept, so waiting for the
	// Accept means the listener is known to Shutdown.
	select {
	case <-ln.accepting:
	case <-time.After(5 * time.Second):
		t.Fatal("the test listener was never accepted on")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	done := make(chan error, 1)
	go func() { done <- server.Start(ctx) }()

	select {
	case err := <-done:
		require.Error(t, err, "a failing shutdown must surface")
		assert.Contains(t, err.Error(), "rtpx listener close failed")
	case <-time.After(10 * time.Second):
		t.Fatal("Start did not return after context cancellation")
	}

	select {
	case <-served:
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return after shutdown")
	}
}
