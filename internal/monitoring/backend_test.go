package monitoring

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MonresetBackendObservation puts the package back to "nothing observed yet",
// state and gauges alike, so one test cannot read another's observation.
func MonresetBackendObservation(t *testing.T) {
	t.Helper()

	backendMu.Lock()
	backendObservedAny = false
	backendLastResponse = time.Time{}
	backendLastFailure = time.Time{}
	backendLastFailureClass = ""
	backendMu.Unlock()

	BackendObserved.Set(0)
	BackendLastResponseTimestamp.Set(0)
	BackendLastFailureTimestamp.Reset()
	BackendTransportFailures.Reset()
}

// MoncounterValue reads one counter child. The response counter has no labels
// and prometheus gives a plain counter no Reset, so the tests below assert a
// delta rather than an absolute value.
func MoncounterValue(t *testing.T, name string, labels map[string]string) float64 {
	t.Helper()
	return MondefaultMetric(t, name, labels).Value
}

// MonstubBackend is the inner client ObserveBackendClient wraps.
type MonstubBackend struct {
	resp *http.Response
	err  error
}

func (s MonstubBackend) Do(*http.Request) (*http.Response, error) { return s.resp, s.err }

// MonbackendRequest is a request to the backend with a live context.
func MonbackendRequest() *http.Request {
	return httptest.NewRequest(http.MethodGet, "http://backend.invalid/bucket/key", nil)
}

func TestMonBackendUnobservedSaysSoRatherThanOK(t *testing.T) {
	MonresetBackendObservation(t)

	status := backendSnapshot()

	assert.Equal(t, "no request since start", status.Status,
		"a proxy that has served nothing must not claim the backend is reachable")
	assert.Empty(t, status.LastResponse)
	assert.Empty(t, status.LastFailure)
	assert.Empty(t, status.LastFailureClass)
	assert.Equal(t, float64(0), MondefaultMetric(t, "s3ep_backend_observed", map[string]string{}).Value)
}

// Any HTTP response is reachability - the status code is about the request, not
// about the backend being there.
func TestMonBackendRecordsAnyResponseAsReachability(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusForbidden, http.StatusInternalServerError} {
		t.Run(fmt.Sprintf("status %d", status), func(t *testing.T) {
			MonresetBackendObservation(t)
			client := ObserveBackendClient(MonstubBackend{
				resp: &http.Response{StatusCode: status, Body: http.NoBody},
			})

			resp, err := client.Do(MonbackendRequest())
			require.NoError(t, err)
			require.Equal(t, status, resp.StatusCode, "the wrapper must pass the response through")

			observed := backendSnapshot()
			assert.Equal(t, "ok", observed.Status)
			require.NotEmpty(t, observed.LastResponse)
			assert.Empty(t, observed.LastFailure)
			assert.Empty(t, observed.LastFailureClass)

			// The document and the gauge are one measurement, two renderings.
			at, parseErr := time.Parse(time.RFC3339, observed.LastResponse)
			require.NoError(t, parseErr)
			gauge := MondefaultMetric(t, "s3ep_backend_last_response_timestamp", map[string]string{})
			require.True(t, gauge.Found)
			assert.Equal(t, float64(at.Unix()), gauge.Value)
			assert.Equal(t, float64(1), MondefaultMetric(t, "s3ep_backend_observed", map[string]string{}).Value)
		})
	}
}

func TestMonBackendRecordsAFailureAsFailing(t *testing.T) {
	MonresetBackendObservation(t)
	client := ObserveBackendClient(MonstubBackend{err: &net.DNSError{Err: "no such host", Name: "backend.invalid"}})

	_, err := client.Do(MonbackendRequest())
	require.Error(t, err, "the wrapper must pass the error through")

	observed := backendSnapshot()
	assert.Equal(t, "failing", observed.Status)
	assert.Empty(t, observed.LastResponse, "nothing has answered yet")
	require.NotEmpty(t, observed.LastFailure)
	assert.Equal(t, "dns", observed.LastFailureClass)

	at, parseErr := time.Parse(time.RFC3339, observed.LastFailure)
	require.NoError(t, parseErr)
	gauge := MondefaultMetric(t, "s3ep_backend_last_failure_timestamp", map[string]string{"class": "dns"})
	require.True(t, gauge.Found)
	assert.Equal(t, float64(at.Unix()), gauge.Value)
	assert.Equal(t, float64(1), MondefaultMetric(t, "s3ep_backend_observed", map[string]string{}).Value)
}

// Which of the two is newer decides the verdict, and both timestamps stay
// visible either way: an operator wants to see when it last broke.
func TestMonBackendVerdictFollowsTheNewerEvent(t *testing.T) {
	base := time.Now()

	t.Run("a failure after a response is failing", func(t *testing.T) {
		MonresetBackendObservation(t)
		recordBackendResponse(base)
		recordBackendFailure("connect", base.Add(time.Second), nil, errors.New("dial tcp: connection refused"))

		observed := backendSnapshot()
		assert.Equal(t, "failing", observed.Status)
		assert.NotEmpty(t, observed.LastResponse)
		assert.NotEmpty(t, observed.LastFailure)
		assert.Equal(t, "connect", observed.LastFailureClass)
	})

	t.Run("a response after a failure is ok", func(t *testing.T) {
		MonresetBackendObservation(t)
		recordBackendFailure("timeout", base, nil, errors.New("context deadline exceeded"))
		recordBackendResponse(base.Add(time.Second))

		observed := backendSnapshot()
		assert.Equal(t, "ok", observed.Status)
		assert.NotEmpty(t, observed.LastResponse)
		assert.NotEmpty(t, observed.LastFailure,
			"the failure that was recovered from stays readable")
		assert.Equal(t, "timeout", observed.LastFailureClass)
	})
}

func TestMonBackendClassifiesFailures(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected string
	}{
		{"name resolution", &net.DNSError{Err: "no such host", Name: "backend.invalid"}, "dns"},
		{
			"a dns failure that timed out is still dns",
			&net.DNSError{Err: "i/o timeout", Name: "backend.invalid", IsTimeout: true},
			"dns",
		},
		{"plaintext answer to a TLS handshake", tls.RecordHeaderError{Msg: "first record does not look like TLS"}, "tls"},
		{
			"certificate verification",
			&tls.CertificateVerificationError{Err: x509.UnknownAuthorityError{}},
			"tls",
		},
		{"unknown authority", x509.UnknownAuthorityError{}, "tls"},
		{"wrong hostname", x509.HostnameError{Host: "backend.invalid"}, "tls"},
		{"expired certificate", x509.CertificateInvalidError{Reason: x509.Expired}, "tls"},
		{"a read deadline", &net.OpError{Op: "read", Net: "tcp", Err: os.ErrDeadlineExceeded}, "timeout"},
		{"a deadline the SDK wrapped", fmt.Errorf("Get %q: %w", "http://backend.invalid", context.DeadlineExceeded), "timeout"},
		{
			"a dial that timed out is a timeout, not a connect failure",
			&net.OpError{Op: "dial", Net: "tcp", Err: os.ErrDeadlineExceeded},
			"timeout",
		},
		{"connection refused", &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED}, "connect"},
		{"connection reset", syscall.ECONNRESET, "connect"},
		{"host unreachable", &net.OpError{Op: "dial", Net: "tcp", Err: syscall.EHOSTUNREACH}, "connect"},
		{"network unreachable", syscall.ENETUNREACH, "connect"},
		{"any other dial failure", &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("no route")}, "connect"},
		{"anything else", errors.New("malformed response from backend"), "other"},
		{"a non-dial operation with an unknown cause", &net.OpError{Op: "read", Net: "tcp", Err: errors.New("short read")}, "other"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			MonresetBackendObservation(t)
			client := ObserveBackendClient(MonstubBackend{err: tt.err})

			_, err := client.Do(MonbackendRequest())
			require.ErrorIs(t, err, tt.err)

			observed := backendSnapshot()
			assert.Equal(t, "failing", observed.Status)
			assert.Equal(t, tt.expected, observed.LastFailureClass)
			assert.True(t,
				MondefaultMetric(t, "s3ep_backend_last_failure_timestamp", map[string]string{"class": tt.expected}).Found,
				"the class the document names must carry a gauge of its own")
		})
	}
}

// A failure under a request context that is already done is ours - a client
// that hung up, or a shutdown - and says nothing about the backend. The
// endpoint reports what the traffic showed about the BACKEND (ADR 0034).
func TestMonBackendRecordsNothingForOurOwnCancellation(t *testing.T) {
	for _, tt := range []struct {
		name string
		ctx  func() (context.Context, context.CancelFunc)
	}{
		{"the client hung up", func() (context.Context, context.CancelFunc) {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			return ctx, func() {}
		}},
		{"the request's own deadline passed", func() (context.Context, context.CancelFunc) {
			ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
			return ctx, cancel
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			MonresetBackendObservation(t)
			ctx, cancel := tt.ctx()
			defer cancel()

			client := ObserveBackendClient(MonstubBackend{err: context.Canceled})
			_, err := client.Do(MonbackendRequest().WithContext(ctx))
			require.Error(t, err)

			observed := backendSnapshot()
			assert.Equal(t, "no request since start", observed.Status,
				"our own cancellation must not be recorded against the backend")
			assert.Empty(t, observed.LastFailure)
			assert.Empty(t, observed.LastFailureClass)
			assert.Equal(t, float64(0), MondefaultMetric(t, "s3ep_backend_observed", map[string]string{}).Value)
		})
	}
}

// The observation is written on every backend round trip and read by every
// /status request, so the two run concurrently by construction.
func TestMonBackendObservationIsRaceFree(t *testing.T) {
	MonresetBackendObservation(t)

	answering := ObserveBackendClient(MonstubBackend{resp: &http.Response{StatusCode: http.StatusOK, Body: http.NoBody}})
	failing := ObserveBackendClient(MonstubBackend{err: &net.DNSError{Err: "no such host"}})
	server := NewServer(&Config{BindAddress: "127.0.0.1:0", MetricsPath: "/metrics"})

	var wg sync.WaitGroup
	for range 8 {
		wg.Add(3)
		go func() {
			defer wg.Done()
			for range 50 {
				_, _ = answering.Do(MonbackendRequest())
			}
		}()
		go func() {
			defer wg.Done()
			for range 50 {
				_, _ = failing.Do(MonbackendRequest())
			}
		}()
		go func() {
			defer wg.Done()
			for range 50 {
				rec := httptest.NewRecorder()
				server.httpServer.Handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/status", nil))
				if rec.Code != http.StatusOK {
					t.Errorf("status endpoint answered %d", rec.Code)
					return
				}
			}
		}()
	}
	wg.Wait()

	assert.Equal(t, float64(1), MondefaultMetric(t, "s3ep_backend_observed", map[string]string{}).Value)
}

// A failure that never produced an HTTP response has to be countable and
// readable, not only timestamped: the SDK retries, so a round trip that failed
// and then succeeded reaches no handler and appears in no other log, and a
// last-seen gauge cannot express a rate (ADR 0034 D6).
func TestMonBackendFailureIsCountedAndLogged(t *testing.T) {
	MonresetBackendObservation(t)
	hook := test.NewGlobal()
	t.Cleanup(hook.Reset)

	before := MoncounterValue(t, "s3ep_backend_transport_failures_total", map[string]string{"class": "connect"})

	client := ObserveBackendClient(MonstubBackend{err: &net.OpError{
		Op:  "dial",
		Net: "tcp",
		Err: syscall.ECONNREFUSED,
	}})
	_, err := client.Do(MonbackendRequest())
	require.Error(t, err)

	after := MoncounterValue(t, "s3ep_backend_transport_failures_total", map[string]string{"class": "connect"})
	assert.Equal(t, before+1, after, "the failure counter is what an alert reads")

	entry := hook.LastEntry()
	require.NotNil(t, entry, "a transport failure must not be silent")
	assert.Equal(t, logrus.WarnLevel, entry.Level,
		"debug would hide the only record of a retried-away failure")
	assert.Equal(t, "connect", entry.Data["class"])
	assert.Equal(t, "backend.invalid", entry.Data["host"])
	assert.Equal(t, http.MethodGet, entry.Data["method"])
	assert.Contains(t, entry.Data, logrus.ErrorKey,
		"a class of \"other\" is a dead end without the error that produced it")
}

// The denominator. Without it the failure counter cannot be read: a few
// failures an hour is normal, the same number per minute is an outage.
func TestMonBackendResponseIsCounted(t *testing.T) {
	MonresetBackendObservation(t)

	before := MoncounterValue(t, "s3ep_backend_responses_total", map[string]string{})

	client := ObserveBackendClient(MonstubBackend{resp: &http.Response{StatusCode: http.StatusForbidden}})
	_, err := client.Do(MonbackendRequest())
	require.NoError(t, err)

	assert.Equal(t, before+1, MoncounterValue(t, "s3ep_backend_responses_total", map[string]string{}),
		"any HTTP response counts, a 403 included")
}

// A client that hung up is not the backend's failure, so it reaches neither the
// counter nor the log. Without this the log floods on every aborted download.
func TestMonBackendCancelledRequestIsNeitherCountedNorLogged(t *testing.T) {
	MonresetBackendObservation(t)
	hook := test.NewGlobal()
	t.Cleanup(hook.Reset)

	before := MoncounterValue(t, "s3ep_backend_transport_failures_total", map[string]string{"class": "other"})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req := MonbackendRequest().WithContext(ctx)

	client := ObserveBackendClient(MonstubBackend{err: context.Canceled})
	_, err := client.Do(req)
	require.Error(t, err)

	assert.Equal(t, before,
		MoncounterValue(t, "s3ep_backend_transport_failures_total", map[string]string{"class": "other"}))
	assert.Empty(t, hook.AllEntries(), "a client hangup must not be logged as a backend failure")
}

// MonfailingBody is the proxy's own reader chain failing mid-stream: an upload
// checksum that did not verify, or a seal that could not be produced.
type MonfailingBody struct{ err error }

func (b MonfailingBody) Read([]byte) (int, error) { return 0, b.err }
func (b MonfailingBody) Close() error             { return nil }

// A failure the proxy's own request body raised is not the backend's. net/http
// reports it as the error of the round trip, so without this the backend leg
// would be blamed for a client sending one wrong checksum - counted, logged
// against the backend host, and rendered as backend.status "failing" while the
// backend behaved perfectly (ADR 0034 D7).
func TestMonBackendOwnBodyFailureIsNotTheBackends(t *testing.T) {
	MonresetBackendObservation(t)
	hook := test.NewGlobal()
	t.Cleanup(hook.Reset)

	before := MoncounterValue(t, "s3ep_backend_transport_failures_total", map[string]string{"class": "other"})

	bodyErr := errors.New("x-amz-checksum-crc32c: client checksum does not match the payload")
	req := MonbackendRequest()
	req.Body = MonfailingBody{err: bodyErr}

	// What net/http does: it reads the body, the read fails, and that error
	// comes back out of Do wrapped as the round trip's error.
	client := ObserveBackendClient(MonreadingBackend{})
	_, err := client.Do(req)
	require.Error(t, err)

	assert.Equal(t, before,
		MoncounterValue(t, "s3ep_backend_transport_failures_total", map[string]string{"class": "other"}),
		"the proxy's own body error must not move the backend failure counter")
	assert.Empty(t, hook.AllEntries(),
		"a checksum the client got wrong must not be logged against the backend host")
	assert.Equal(t, backendStatusUnobserved, backendSnapshot().Status,
		"the status document must not claim the backend failed")
}

// The other direction: a real transport failure on a request that also carries
// a body is still the backend's, and is still recorded.
func TestMonBackendTransportFailureWithAHealthyBodyIsRecorded(t *testing.T) {
	MonresetBackendObservation(t)

	before := MoncounterValue(t, "s3ep_backend_transport_failures_total", map[string]string{"class": "connect"})

	req := MonbackendRequest()
	req.Body = io.NopCloser(strings.NewReader("payload"))

	client := ObserveBackendClient(MonstubBackend{err: &net.OpError{
		Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED,
	}})
	_, err := client.Do(req)
	require.Error(t, err)

	assert.Equal(t, before+1,
		MoncounterValue(t, "s3ep_backend_transport_failures_total", map[string]string{"class": "connect"}),
		"a body that read fine does not excuse the backend")
	assert.Equal(t, backendStatusFailing, backendSnapshot().Status)
}

// MonreadingBackend drains the request body the way a transport does, so a body
// that fails surfaces as the round trip's error.
type MonreadingBackend struct{}

func (MonreadingBackend) Do(req *http.Request) (*http.Response, error) {
	if req.Body == nil {
		return &http.Response{StatusCode: http.StatusOK}, nil
	}
	if _, err := io.Copy(io.Discard, req.Body); err != nil {
		return nil, &url.Error{Op: "Put", URL: req.URL.String(), Err: err}
	}
	return &http.Response{StatusCode: http.StatusOK}, nil
}
