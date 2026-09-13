package proxy

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// RtPxemptyPayloadHash is the SHA256 of an empty body, what S3 clients send for
// a GET.
const RtPxemptyPayloadHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

// RtPxserver builds a Server with only the fields the middleware needs, i.e. the
// state a real server has before its first request.
func RtPxserver(t *testing.T) *Server {
	t.Helper()
	l := logrus.New()
	l.SetOutput(RtPxquietWriter{})
	l.SetLevel(logrus.ErrorLevel)
	return &Server{
		logger: l.WithField("component", "rtpx-test"),
		config: RtPxconfig(),
	}
}

// RtPxsignedRequest signs a request the way an AWS SDK client does, so the
// middleware is tested against a real signer and not against our own idea of one.
func RtPxsignedRequest(t *testing.T, method, target string) *http.Request {
	t.Helper()

	req, err := http.NewRequestWithContext(context.Background(), method, "https://"+RtPxhost+target, nil)
	require.NoError(t, err)
	req.Host = RtPxhost
	req.Header.Set("Host", RtPxhost)
	req.Header.Set("X-Amz-Content-Sha256", RtPxemptyPayloadHash)

	creds, err := credentials.NewStaticCredentialsProvider(RtPxaccessKey, RtPxsecretKey, "").
		Retrieve(context.Background())
	require.NoError(t, err)

	// S3 signs the already-escaped path exactly once.
	signer := v4.NewSigner(func(o *v4.SignerOptions) { o.DisableURIPathEscaping = true })
	require.NoError(t, signer.SignHTTP(context.Background(), creds, req,
		RtPxemptyPayloadHash, "s3", "us-east-1", time.Now().UTC()))

	serverReq := httptest.NewRequest(method, target, nil)
	serverReq.Host = RtPxhost
	for name, values := range req.Header {
		for _, v := range values {
			serverReq.Header.Add(name, v)
		}
	}
	return serverReq
}

// RtPxauthHeader builds an Authorization header with the given access key,
// signature and credential date.
func RtPxauthHeader(accessKey, date, signature string) string {
	return "AWS4-HMAC-SHA256 Credential=" + accessKey + "/" + date +
		"/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=" + signature
}

// A correctly signed request has to reach the handler behind the middleware
// unchanged: the middleware may authenticate, not rewrite.
func TestRtPxS3AuthMiddlewareAcceptsSignedRequest(t *testing.T) {
	server := RtPxserver(t)

	var seen *http.Request
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r
		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte("handler-ran"))
		require.NoError(t, err)
	})

	req := RtPxsignedRequest(t, http.MethodGet, "/test-bucket/dir/object.txt")
	w := httptest.NewRecorder()
	server.s3AuthMiddleware(next).ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code, "a validly signed request must pass: %s", w.Body.String())
	assert.Equal(t, "handler-ran", w.Body.String())
	require.NotNil(t, seen)
	assert.Equal(t, "/test-bucket/dir/object.txt", seen.URL.Path, "the path must reach the handler unchanged")
	assert.NotNil(t, server.s3AuthService, "the middleware initialises the auth service on first use")
}

// Every rejected request gets the S3 error code that names the actual failure,
// a hardened set of headers, and no trace of what the caller sent.
func TestRtPxS3AuthMiddlewareRejections(t *testing.T) {
	today := time.Now().UTC().Format("20060102")
	stale := time.Now().UTC().Add(-20 * time.Minute)

	cases := []struct {
		name       string
		build      func() *http.Request
		wantCode   string
		wantStatus int
	}{
		{
			// An anonymous request, which S3 and MinIO both answer AccessDenied;
			// only a header that is present and unusable is a 400. The cell used
			// to carry the blanket InvalidRequest this proxy answered everything
			// with, under the new status table.
			name: "no Authorization header at all",
			build: func() *http.Request {
				return httptest.NewRequest(http.MethodGet, "/test-bucket/key", nil)
			},
			wantCode:   "AccessDenied",
			wantStatus: http.StatusForbidden,
		},
		{
			name: "not AWS Signature V4",
			build: func() *http.Request {
				r := httptest.NewRequest(http.MethodGet, "/test-bucket/key", nil)
				r.Header.Set("Authorization", "Basic dXNlcjpwYXNzd29yZA==")
				return r
			},
			wantCode:   "InvalidRequest",
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "oversized Authorization header",
			build: func() *http.Request {
				r := httptest.NewRequest(http.MethodGet, "/test-bucket/key", nil)
				r.Header.Set("Authorization", RtPxauthHeader(RtPxaccessKey, today, strings.Repeat("a", 9000)))
				return r
			},
			wantCode:   "InvalidRequest",
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "unknown access key",
			build: func() *http.Request {
				r := httptest.NewRequest(http.MethodGet, "/test-bucket/key", nil)
				r.Header.Set("X-Amz-Date", time.Now().UTC().Format("20060102T150405Z"))
				r.Header.Set("Authorization", RtPxauthHeader("RTPXUNKNOWNKEY", today, "deadbeef"))
				return r
			},
			wantCode:   "InvalidAccessKeyId",
			wantStatus: http.StatusForbidden,
		},
		{
			name: "known key, wrong signature",
			build: func() *http.Request {
				r := httptest.NewRequest(http.MethodGet, "/test-bucket/key", nil)
				r.Header.Set("X-Amz-Date", time.Now().UTC().Format("20060102T150405Z"))
				r.Header.Set("X-Amz-Content-Sha256", RtPxemptyPayloadHash)
				r.Header.Set("Authorization", RtPxauthHeader(RtPxaccessKey, today, "deadbeefdeadbeef"))
				return r
			},
			wantCode:   "SignatureDoesNotMatch",
			wantStatus: http.StatusForbidden,
		},
		{
			name: "request signed 20 minutes ago",
			build: func() *http.Request {
				r := httptest.NewRequest(http.MethodGet, "/test-bucket/key", nil)
				r.Header.Set("X-Amz-Date", stale.Format("20060102T150405Z"))
				r.Header.Set("X-Amz-Content-Sha256", RtPxemptyPayloadHash)
				r.Header.Set("Authorization", RtPxauthHeader(RtPxaccessKey, stale.Format("20060102"), "deadbeef"))
				return r
			},
			wantCode:   "RequestTimeTooSkewed",
			wantStatus: http.StatusForbidden,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := RtPxserver(t)
			called := false
			next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true })

			w := httptest.NewRecorder()
			server.s3AuthMiddleware(next).ServeHTTP(w, tc.build())

			assert.False(t, called, "an unauthenticated request must never reach the S3 handlers")
			// S3's own status per code: 400 for InvalidRequest and
			// AuthorizationHeaderMalformed, 403 for the rest. ADR 0006 D2 — an
			// undocumented deviation is a defect, not a limit.
			// Open decision: the owner may instead keep the blanket 403 and
			// record it in ADR 0014, which is the other half of D2.
			assert.Equal(t, tc.wantStatus, w.Code)
			assert.Equal(t, "application/xml", w.Header().Get("Content-Type"))
			assert.Equal(t, "nosniff", w.Header().Get("X-Content-Type-Options"))
			assert.Equal(t, "DENY", w.Header().Get("X-Frame-Options"))
			assert.Equal(t, "no-cache, no-store, must-revalidate", w.Header().Get("Cache-Control"))

			var doc struct {
				XMLName xml.Name `xml:"Error"`
				Code    string   `xml:"Code"`
				Message string   `xml:"Message"`
			}
			require.NoError(t, xml.Unmarshal(w.Body.Bytes(), &doc), "body must be an S3 error document: %s", w.Body.String())
			assert.Equal(t, tc.wantCode, doc.Code)
			assert.NotEmpty(t, doc.Message)
			assert.NotContains(t, w.Body.String(), RtPxsecretKey)
			assert.NotContains(t, w.Body.String(), "RTPXUNKNOWNKEY",
				"the attempted access key must not be echoed back")
		})
	}
}

// determineErrorCode is the only thing that decides which S3 code an
// authentication failure gets. Every branch has to be pinned, because the
// switch is ordered and a new case in the wrong place silently re-labels
// existing failures.
func TestRtPxDetermineErrorCodeMapping(t *testing.T) {
	server := RtPxserver(t)

	cases := []struct {
		name string
		err  error
		want string
	}{
		{name: "unknown key", err: errors.New("access key not found: AKIAEXAMPLE"), want: "InvalidAccessKeyId"},
		{name: "bad signature", err: errors.New("signature verification failed: signature mismatch"), want: "SignatureDoesNotMatch"},
		{name: "clock skew", err: errors.New("timestamp validation failed: clock skew too large"), want: "RequestTimeTooSkewed"},
		{name: "replay", err: errors.New("request timestamp is too old: potential replay attack"), want: "RequestTimeTooSkewed"},
		{name: "header problem", err: errors.New("authorization header too large"), want: "InvalidRequest"},
		{name: "malformed presigned credential", err: errors.New("malformed presigned credential: bad scope"), want: "AuthorizationHeaderMalformed"},
		{name: "anything else", err: errors.New("presigned URL rejected"), want: "AccessDenied"},
		{
			// S3 answers AuthorizationHeaderMalformed for a header it cannot
			// parse; the ordered switch matches "authorization header" first
			// (ADR 0006 D2 — S3 semantics, or a documented limit).
			name: "malformed authorization header",
			err:  errors.New("malformed authorization header: invalid credential format"),
			want: "AuthorizationHeaderMalformed",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code := server.determineErrorCode(tc.err)
			assert.Equal(t, tc.want, code)
			assert.Contains(t, authErrorMessage, code, "every returned code needs client-facing wording")
		})
	}

	// The caller only reaches determineErrorCode with a non-nil error; a nil one
	// is a programming error and is not silently mapped to AccessDenied.
	assert.Panics(t, func() { _ = server.determineErrorCode(nil) })
}

// writeS3Error is the last thing an unauthenticated caller sees; it has to be a
// complete S3 error document with the security headers, whatever code it is
// handed.
func TestRtPxWriteS3ErrorDocument(t *testing.T) {
	server := RtPxserver(t)

	cases := []struct {
		name        string
		code        string
		status      int
		wantMessage string
	}{
		{
			name:        "known code keeps its own wording",
			code:        "SignatureDoesNotMatch",
			status:      http.StatusForbidden,
			wantMessage: authErrorMessage["SignatureDoesNotMatch"],
		},
		{
			name:        "unknown code falls back to the Access Denied wording",
			code:        "RtPxNoSuchCode",
			status:      http.StatusForbidden,
			wantMessage: authErrorMessage["AccessDenied"],
		},
		{
			name:        "the status is whatever the caller passed",
			code:        "InvalidRequest",
			status:      http.StatusBadRequest,
			wantMessage: authErrorMessage["InvalidRequest"],
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			server.writeS3Error(w, tc.code, tc.status)

			assert.Equal(t, tc.status, w.Code)
			assert.Equal(t, "application/xml", w.Header().Get("Content-Type"))
			assert.Equal(t, "nosniff", w.Header().Get("X-Content-Type-Options"))
			assert.Equal(t, "DENY", w.Header().Get("X-Frame-Options"))
			assert.Equal(t, "no-cache, no-store, must-revalidate", w.Header().Get("Cache-Control"))

			var doc struct {
				XMLName xml.Name `xml:"Error"`
				Code    string   `xml:"Code"`
				Message string   `xml:"Message"`
			}
			require.NoError(t, xml.Unmarshal(w.Body.Bytes(), &doc), "body must be XML: %s", w.Body.String())
			assert.Equal(t, tc.code, doc.Code)
			assert.Equal(t, tc.wantMessage, doc.Message)
		})
	}
}

// The middleware wrappers are used before any request is served, so each one has
// to initialise the shared middleware state on its own.
func TestRtPxMiddlewareWrappersInitialiseOnDemand(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	})

	t.Run("request tracking counts the request", func(t *testing.T) {
		server := RtPxserver(t)
		var start, end int
		// Set before the first use: setupMiddleware copies these into the tracker.
		server.requestStartHandler = func() { start++ }
		server.requestEndHandler = func() { end++ }
		require.Nil(t, server.requestTracker)

		w := httptest.NewRecorder()
		server.requestTrackingMiddleware(next).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/test-bucket", nil))

		assert.NotNil(t, server.requestTracker)
		assert.Equal(t, http.StatusTeapot, w.Code, "tracking must not change the response")
		assert.Equal(t, 1, start)
		assert.Equal(t, 1, end)
	})

	t.Run("logging leaves status and body untouched", func(t *testing.T) {
		server := RtPxserver(t)
		require.Nil(t, server.httpLogger)

		body := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusPartialContent)
			_, err := w.Write([]byte("payload"))
			require.NoError(t, err)
		})
		w := httptest.NewRecorder()
		server.loggingMiddleware(body).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/test-bucket/key", nil))

		assert.NotNil(t, server.httpLogger)
		assert.Equal(t, http.StatusPartialContent, w.Code)
		assert.Equal(t, "payload", w.Body.String())
	})

	t.Run("cors answers the preflight itself", func(t *testing.T) {
		server := RtPxserver(t)
		require.Nil(t, server.corsHandler)

		w := httptest.NewRecorder()
		server.corsMiddleware(next).ServeHTTP(w, httptest.NewRequest(http.MethodOptions, "/test-bucket/key", nil))

		assert.NotNil(t, server.corsHandler)
		assert.Equal(t, http.StatusOK, w.Code, "a preflight must not reach the S3 handlers")
		assert.Equal(t, "*", w.Header().Get("Access-Control-Allow-Origin"))
		assert.Contains(t, w.Header().Get("Access-Control-Allow-Methods"), "PUT")
	})

	t.Run("auth initialises the service", func(t *testing.T) {
		server := RtPxserver(t)
		require.Nil(t, server.s3AuthService)

		w := httptest.NewRecorder()
		server.s3AuthMiddleware(next).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/test-bucket", nil))

		assert.NotNil(t, server.s3AuthService)
		assert.Equal(t, http.StatusForbidden, w.Code)
	})
}

// setupMiddleware is also the place where log_health_requests is applied; both
// settings must produce a working chain.
func TestRtPxSetupMiddlewareHonoursLogHealthRequests(t *testing.T) {
	for _, logHealth := range []bool{false, true} {
		server := RtPxserver(t)
		server.config.LogHealthRequests = logHealth

		var buf bytes.Buffer
		l := logrus.New()
		l.SetOutput(&buf)
		l.SetLevel(logrus.DebugLevel)
		server.logger = l.WithField("component", "rtpx-test")

		server.setupMiddleware()
		require.NotNil(t, server.httpLogger)
		require.NotNil(t, server.requestTracker)
		require.NotNil(t, server.corsHandler)
		require.NotNil(t, server.s3AuthService)

		w := httptest.NewRecorder()
		server.loggingMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/health", nil))

		assert.Equal(t, http.StatusOK, w.Code)
		if logHealth {
			assert.Contains(t, buf.String(), "/health", "health requests are logged when configured")
		} else {
			assert.NotContains(t, buf.String(), "/health", "health requests stay out of the log by default")
		}
	}
}

// The middleware must not swallow or buffer the response body: a large object
// has to stream through unchanged.
func TestRtPxMiddlewareChainStreamsBodyUnchanged(t *testing.T) {
	server := RtPxserver(t)
	payload := bytes.Repeat([]byte("s3-encryption-proxy"), 4096)

	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		_, err := w.Write(payload)
		require.NoError(t, err)
	})

	chain := server.corsMiddleware(server.loggingMiddleware(server.requestTrackingMiddleware(handler)))

	w := httptest.NewRecorder()
	chain.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/test-bucket/big", nil))

	require.Equal(t, http.StatusOK, w.Code)
	got, err := io.ReadAll(w.Body)
	require.NoError(t, err)
	assert.Equal(t, len(payload), len(got))
	assert.True(t, bytes.Equal(payload, got), "the middleware chain must not alter the body")
}

// The three customer-key headers are refused with 501 NotImplemented naming the
// header (ADR 0007 D6). No read path carries the key, so an SSE-C object written
// through the proxy could never be read back - the refusal is what keeps the
// silent drop from becoming an unreadable object.
func TestRtPxSSECustomerHeadersAreRefused(t *testing.T) {
	s := RtPxserver(t)

	for _, header := range []string{
		"x-amz-server-side-encryption-customer-algorithm",
		"x-amz-server-side-encryption-customer-key",
		"x-amz-server-side-encryption-customer-key-MD5",
	} {
		t.Run(header, func(t *testing.T) {
			reached := false
			next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true })

			req := httptest.NewRequest(http.MethodPut, "/b/k", nil)
			req.Header.Set(header, "value")
			rr := httptest.NewRecorder()
			s.sseCustomerGuardMiddleware(next).ServeHTTP(rr, req)

			assert.False(t, reached, "the request never reaches a handler")
			assert.Equal(t, http.StatusNotImplemented, rr.Code)
			assert.Contains(t, rr.Body.String(), "NotImplemented")
			assert.Contains(t, strings.ToLower(rr.Body.String()), strings.ToLower(header),
				"the refusal names the header so the client learns what to remove")
		})
	}

	t.Run("a request without them passes", func(t *testing.T) {
		reached := false
		next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true })

		rr := httptest.NewRecorder()
		s.sseCustomerGuardMiddleware(next).ServeHTTP(rr, httptest.NewRequest(http.MethodPut, "/b/k", nil))

		assert.True(t, reached)
	})
}

// TestRtPxDrainGuardRefusesNewWorkWithoutClosingTheDoor is ADR 0029 D1: while
// the proxy is draining, the listener stays up and new S3 work is answered
// 503 with Retry-After. A closed listener would answer a connection refusal
// instead, which an SDK cannot tell apart from a backend that is down.
func TestRtPxDrainGuardRefusesNewWorkWithoutClosingTheDoor(t *testing.T) {
	s := RtPxserver(t)

	t.Run("no shutdown handler installed means nothing is refused", func(t *testing.T) {
		reached := false
		next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true })
		rr := httptest.NewRecorder()
		s.drainGuardMiddleware(next).ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/b/k", nil))
		assert.True(t, reached)
	})

	t.Run("running normally", func(t *testing.T) {
		s.SetShutdownStateHandler(func() (bool, time.Time) { return false, time.Time{} })
		reached := false
		next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true })
		rr := httptest.NewRecorder()
		s.drainGuardMiddleware(next).ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/b/k", nil))
		assert.True(t, reached)
	})

	t.Run("draining", func(t *testing.T) {
		s.SetShutdownStateHandler(func() (bool, time.Time) { return true, time.Now() })
		reached := false
		next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true })
		rr := httptest.NewRecorder()
		s.drainGuardMiddleware(next).ServeHTTP(rr, httptest.NewRequest(http.MethodPut, "/b/k", nil))

		assert.False(t, reached, "no new work is started once the proxy is draining")
		assert.Equal(t, http.StatusServiceUnavailable, rr.Code)
		assert.Equal(t, "1", rr.Header().Get("Retry-After"),
			"an SDK retries a 503 carrying Retry-After, against another replica")
		assert.Contains(t, rr.Body.String(), "ServiceUnavailable")
	})
}
