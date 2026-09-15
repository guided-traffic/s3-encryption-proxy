package monitoring

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"
)

// The classes a backend transport failure is reported under.
const (
	backendFailureDNS     = "dns"
	backendFailureConnect = "connect"
	backendFailureTLS     = "tls"
	backendFailureTimeout = "timeout"
	backendFailureOther   = "other"
)

// The three states backendSnapshot reports.
const (
	backendStatusUnobserved = "no request since start"
	backendStatusOK         = "ok"
	backendStatusFailing    = "failing"
)

// BackendStatus is what the real traffic showed about the backend. A proxy that
// has served nothing says so rather than claiming health.
type BackendStatus struct {
	Status           string `json:"status"`
	LastResponse     string `json:"last_response,omitempty"`
	LastFailure      string `json:"last_failure,omitempty"`
	LastFailureClass string `json:"last_failure_class,omitempty"`
}

// BackendHTTPClient is the aws SDK's aws.HTTPClient.
type BackendHTTPClient interface {
	Do(*http.Request) (*http.Response, error)
}

var (
	backendMu               sync.RWMutex
	backendObservedAny      bool
	backendLastResponse     time.Time
	backendLastFailure      time.Time
	backendLastFailureClass string
)

type observedBackendClient struct{ inner BackendHTTPClient }

// ObserveBackendClient wraps the backend HTTP client so every backend round
// trip is observed. Observation is all it does: the status endpoint reports
// what the real traffic showed and never probes on its own (ADR 0034).
func ObserveBackendClient(inner BackendHTTPClient) BackendHTTPClient {
	return &observedBackendClient{inner: inner}
}

func (c *observedBackendClient) Do(req *http.Request) (*http.Response, error) {
	// The request body is the proxy's own reader chain — the upload checksum
	// verifier in front of the segment sealer — and net/http reports an error it
	// raises as the error of the round trip. Without knowing which end failed,
	// a client sending one wrong Content-MD5 would count as a backend transport
	// failure, log a warning naming the backend host, and flip the status
	// document to "failing" while the backend behaved perfectly (ADR 0034 D7).
	req, body := observeRequestBody(req)

	resp, err := c.inner.Do(req)
	if err != nil {
		// Two failures are ours rather than the backend's, and neither says
		// anything about it: a request whose context was already done — a client
		// that hung up, or a shutdown — and one our own body reader ended.
		if req.Context().Err() == nil && !body.failed() {
			recordBackendFailure(classifyBackendFailure(err), time.Now(), req, err)
		}
		return resp, err
	}

	// Any HTTP response is reachability, a 403 included: the status code is
	// about the request, not about the backend being there.
	recordBackendResponse(time.Now())
	return resp, nil
}

// observedBody remembers whether the proxy's own reader ended the round trip.
// io.EOF is not a failure; anything else is, and it is ours.
type observedBody struct {
	inner io.ReadCloser
	err   atomic.Pointer[error]
}

func (b *observedBody) Read(p []byte) (int, error) {
	n, err := b.inner.Read(p)
	if err != nil && !errors.Is(err, io.EOF) {
		b.err.Store(&err)
	}
	return n, err
}

func (b *observedBody) Close() error { return b.inner.Close() }

// failed is nil-safe: a request with no body has nothing that can fail.
func (b *observedBody) failed() bool { return b != nil && b.err.Load() != nil }

// observeRequestBody returns the request to send and the handle that says
// afterwards whether its body was what failed. The request is cloned rather
// than mutated: it belongs to the SDK, which may still hold it for a retry.
func observeRequestBody(req *http.Request) (*http.Request, *observedBody) {
	if req.Body == nil || req.Body == http.NoBody {
		return req, nil
	}

	body := &observedBody{inner: req.Body}
	clone := req.Clone(req.Context())
	clone.Body = body
	return clone, body
}

func recordBackendResponse(at time.Time) {
	backendMu.Lock()
	backendObservedAny = true
	backendLastResponse = at
	backendMu.Unlock()

	BackendLastResponseTimestamp.Set(float64(at.Unix()))
	BackendObserved.Set(1)
	BackendResponses.Inc()
}

// recordBackendFailure counts the failure, timestamps it, and logs it.
//
// It is a warning rather than a debug line because this is the only place the
// event exists: the SDK retries, so a round trip that failed and then succeeded
// never reaches a handler and is logged nowhere else. The count is what an alert
// reads; the line is what tells the operator which host and which error produced
// a class, and a class of "other" is a dead end without it. Failures under an
// already-cancelled request context never get here, which is what keeps a client
// that hangs up out of this log.
func recordBackendFailure(class string, at time.Time, req *http.Request, err error) {
	backendMu.Lock()
	backendObservedAny = true
	backendLastFailure = at
	backendLastFailureClass = class
	backendMu.Unlock()

	BackendLastFailureTimestamp.WithLabelValues(class).Set(float64(at.Unix()))
	BackendObserved.Set(1)
	BackendTransportFailures.WithLabelValues(class).Inc()

	fields := logrus.Fields{"component": "backend-observer", "class": class}
	if req != nil && req.URL != nil {
		fields["host"] = req.URL.Host
		fields["method"] = req.Method
	}
	logrus.WithFields(fields).WithError(err).
		Warn("Backend round trip failed before any HTTP response")
}

func backendSnapshot() BackendStatus {
	backendMu.RLock()
	defer backendMu.RUnlock()

	if !backendObservedAny {
		return BackendStatus{Status: backendStatusUnobserved}
	}

	status := BackendStatus{Status: backendStatusFailing}
	if !backendLastResponse.IsZero() {
		status.LastResponse = backendLastResponse.Format(time.RFC3339)
		if !backendLastResponse.Before(backendLastFailure) {
			status.Status = backendStatusOK
		}
	}
	if !backendLastFailure.IsZero() {
		status.LastFailure = backendLastFailure.Format(time.RFC3339)
		status.LastFailureClass = backendLastFailureClass
	}
	return status
}

// classifyBackendFailure names what went wrong on the way to the backend. The
// order is the resolution order: a timed-out dial is a timeout, not a connect
// failure, because the timeout is the actionable half.
func classifyBackendFailure(err error) string {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return backendFailureDNS
	}
	if isTLSFailure(err) {
		return backendFailureTLS
	}
	if isTimeoutFailure(err) {
		return backendFailureTimeout
	}
	if isConnectFailure(err) {
		return backendFailureConnect
	}
	return backendFailureOther
}

func isTLSFailure(err error) bool {
	var recordHeader tls.RecordHeaderError
	var verification *tls.CertificateVerificationError
	var unknownAuthority x509.UnknownAuthorityError
	var hostname x509.HostnameError
	var invalid x509.CertificateInvalidError
	return errors.As(err, &recordHeader) ||
		errors.As(err, &verification) ||
		errors.As(err, &unknownAuthority) ||
		errors.As(err, &hostname) ||
		errors.As(err, &invalid)
}

func isTimeoutFailure(err error) bool {
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	return errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, context.DeadlineExceeded)
}

func isConnectFailure(err error) bool {
	for _, errno := range []syscall.Errno{
		syscall.ECONNREFUSED,
		syscall.ECONNRESET,
		syscall.EHOSTUNREACH,
		syscall.ENETUNREACH,
	} {
		if errors.Is(err, errno) {
			return true
		}
	}

	var opErr *net.OpError
	return errors.As(err, &opErr) && opErr.Op == "dial"
}
