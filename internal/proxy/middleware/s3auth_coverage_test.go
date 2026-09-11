package middleware

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/guided-traffic/s3-encryption-proxy/internal/config"
	"github.com/sirupsen/logrus"
	logrustest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MwemptySHA256 is the SHA-256 of the empty payload, computed here instead of
// copied, so the literal hard-coded in buildCanonicalRequest is actually
// checked rather than merely echoed.
var MwemptySHA256 = func() string {
	sum := sha256.Sum256(nil)
	return hex.EncodeToString(sum[:])
}()

// MwauthService builds an authentication service with one known client and a
// log hook, so security events can be asserted.
func MwauthService(t *testing.T, maxClockSkewSeconds int) (*S3AuthenticationService, *logrustest.Hook) {
	t.Helper()
	logger, hook := logrustest.NewNullLogger()
	logger.SetLevel(logrus.DebugLevel)
	svc := NewS3AuthenticationService(&config.Config{
		S3Clients: []config.S3ClientCredentials{
			{Type: "static", AccessKeyID: testAccessKey, SecretKey: testSecretKey, Description: "test client"},
		},
		S3Security: config.S3SecurityConfig{MaxClockSkewSeconds: maxClockSkewSeconds},
	}, logger)
	return svc, hook
}

// MwhmacSHA256 is an independent HMAC-SHA256, deliberately not reusing the
// service method under test.
func MwhmacSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

// MwsignDateHeaderRequest signs a request with an independent SigV4
// implementation that uses the legacy Date header rather than X-Amz-Date, and
// leaves Host out of the header map so the r.Host fallback is exercised too.
// The AWS SDK always emits X-Amz-Date, so this path has no other test.
func MwsignDateHeaderRequest(t *testing.T, secretKey string, signedAt time.Time, target string) *http.Request {
	t.Helper()

	parsed, err := url.Parse(target)
	require.NoError(t, err)

	r := httptest.NewRequest(http.MethodGet, target, nil)
	r.Host = testHost
	r.Header.Set(DateHeader, signedAt.UTC().Format(http.TimeFormat))

	const region, service = "us-east-1", "s3"
	scopeDate := signedAt.UTC().Format(ISO8601DateFormat)
	scope := strings.Join([]string{scopeDate, region, service, AWS4RequestType}, "/")
	signedHeaders := []string{"date", "host"}

	canonicalHeaders := "date:" + r.Header.Get(DateHeader) + "\nhost:" + testHost + "\n"
	canonicalRequest := strings.Join([]string{
		http.MethodGet,
		canonicalURI(parsed.Path),
		canonicalQueryString(parsed.Query()),
		canonicalHeaders,
		strings.Join(signedHeaders, ";"),
		MwemptySHA256,
	}, "\n")

	hashed := sha256.Sum256([]byte(canonicalRequest))
	stringToSign := strings.Join([]string{
		AWS4Algorithm,
		signedAt.UTC().Format(ISO8601BasicFormat),
		scope,
		hex.EncodeToString(hashed[:]),
	}, "\n")

	kDate := MwhmacSHA256([]byte(AWS4Prefix+secretKey), []byte(scopeDate))
	kRegion := MwhmacSHA256(kDate, []byte(region))
	kService := MwhmacSHA256(kRegion, []byte(service))
	kSigning := MwhmacSHA256(kService, []byte(AWS4RequestType))
	signature := hex.EncodeToString(MwhmacSHA256(kSigning, []byte(stringToSign)))

	r.Header.Set(AuthorizationHeader, fmt.Sprintf(
		"%s Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		AWS4Algorithm, testAccessKey, scope, strings.Join(signedHeaders, ";"), signature))
	return r
}

// TestMwAuthenticateRequestDateHeaderPath covers the legacy Date-header form of
// SigV4 end to end: accepted with the right secret, rejected with any other.
func TestMwAuthenticateRequestDateHeaderPath(t *testing.T) {
	svc, _ := MwauthService(t, 900)
	signedAt := time.Now().UTC().Truncate(time.Second)

	t.Run("valid signature is accepted", func(t *testing.T) {
		_, err := svc.AuthenticateRequest(
			MwsignDateHeaderRequest(t, testSecretKey, signedAt, "/bucket/key.txt"))
		require.NoError(t, err)
	})

	t.Run("signature over a query string is accepted", func(t *testing.T) {
		_, err := svc.AuthenticateRequest(
			MwsignDateHeaderRequest(t, testSecretKey, signedAt, "/bucket/?list-type=2&prefix=a%20b"))
		require.NoError(t, err)
	})

	t.Run("wrong secret is rejected", func(t *testing.T) {
		_, err := svc.AuthenticateRequest(
			MwsignDateHeaderRequest(t, "another-secret-key-32-characters", signedAt, "/bucket/key.txt"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "signature verification failed")
	})

	t.Run("path swapped after signing is rejected", func(t *testing.T) {
		r := MwsignDateHeaderRequest(t, testSecretKey, signedAt, "/bucket/key.txt")
		r.URL.Path = "/bucket/other-key.txt"
		_, err := svc.AuthenticateRequest(r)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "signature verification failed")
	})

	t.Run("method swapped after signing is rejected", func(t *testing.T) {
		r := MwsignDateHeaderRequest(t, testSecretKey, signedAt, "/bucket/key.txt")
		r.Method = http.MethodDelete
		_, err := svc.AuthenticateRequest(r)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "signature verification failed")
	})
}

// TestMwAuthenticateRequestRejections covers the guard clauses that run before
// any signature maths.
func TestMwAuthenticateRequestRejections(t *testing.T) {
	svc, hook := MwauthService(t, 900)
	signedAt := time.Now().UTC().Truncate(time.Second)

	tests := []struct {
		name      string
		mutate    func(r *http.Request)
		wantErr   string
		wantEvent string
	}{
		{
			name:      "missing authorization header",
			mutate:    func(r *http.Request) { r.Header.Del(AuthorizationHeader) },
			wantErr:   "missing authorization header",
			wantEvent: "malformed_auth_header",
		},
		{
			name:      "oversized authorization header",
			mutate:    func(r *http.Request) { r.Header.Set(AuthorizationHeader, strings.Repeat("A", MaxAuthHeaderSize+1)) },
			wantErr:   "authorization header too large",
			wantEvent: "oversized_auth_header",
		},
		{
			name:      "unsupported algorithm",
			mutate:    func(r *http.Request) { r.Header.Set(AuthorizationHeader, "AWS4-HMAC-SHA512 Credential=x") },
			wantErr:   "unsupported authorization algorithm",
			wantEvent: "malformed_auth_header",
		},
		{
			name: "incomplete components",
			mutate: func(r *http.Request) {
				r.Header.Set(AuthorizationHeader, AWS4Algorithm+" Credential=a/20250101/us-east-1/s3/aws4_request")
			},
			wantErr:   "incomplete authorization header components",
			wantEvent: "malformed_auth_header",
		},
		{
			name: "credential with too few parts",
			mutate: func(r *http.Request) {
				r.Header.Set(AuthorizationHeader, AWS4Algorithm+
					" Credential=a/20250101/us-east-1/s3, SignedHeaders=host, Signature=abcd")
			},
			wantErr:   "invalid credential format",
			wantEvent: "malformed_auth_header",
		},
		{
			name: "credential for another service",
			mutate: func(r *http.Request) {
				r.Header.Set(AuthorizationHeader, AWS4Algorithm+
					" Credential=a/20250101/us-east-1/sts/aws4_request, SignedHeaders=host, Signature=abcd")
			},
			wantErr:   "invalid credential components",
			wantEvent: "malformed_auth_header",
		},
		{
			name: "credential date that is not a date",
			mutate: func(r *http.Request) {
				r.Header.Set(AuthorizationHeader, AWS4Algorithm+
					" Credential=a/notadate/us-east-1/s3/aws4_request, SignedHeaders=host, Signature=abcd")
			},
			wantErr:   "invalid credential date format",
			wantEvent: "malformed_auth_header",
		},
		{
			name: "unknown access key",
			mutate: func(r *http.Request) {
				auth := r.Header.Get(AuthorizationHeader)
				r.Header.Set(AuthorizationHeader, strings.Replace(auth, testAccessKey, "not-a-client", 1))
			},
			wantErr:   "access key not found: not-a-client",
			wantEvent: "unknown_access_key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hook.Reset()
			r := MwsignDateHeaderRequest(t, testSecretKey, signedAt, "/bucket/key.txt")
			tt.mutate(r)

			_, err := svc.AuthenticateRequest(r)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)

			require.NotEmpty(t, hook.AllEntries(), "a security event must be logged")
			assert.Equal(t, tt.wantEvent, hook.AllEntries()[0].Data["event_type"])
		})
	}
}

// TestMwValidateTimestamp covers clock-skew handling on the header path.
func TestMwValidateTimestamp(t *testing.T) {
	svc, _ := MwauthService(t, 900)
	now := time.Now().UTC()

	tests := []struct {
		name           string
		credentialTime time.Time
		headers        map[string]string
		wantErr        string
	}{
		{
			name:           "x-amz-date within the window",
			credentialTime: now,
			headers:        map[string]string{XAmzDateHeader: now.Format(ISO8601BasicFormat)},
		},
		{
			name:           "date header within the window",
			credentialTime: now,
			headers:        map[string]string{DateHeader: now.Format(http.TimeFormat)},
		},
		{
			name:           "malformed x-amz-date",
			credentialTime: now,
			headers:        map[string]string{XAmzDateHeader: "2025-01-01T00:00:00Z"},
			wantErr:        "invalid X-Amz-Date format",
		},
		{
			name:           "malformed date header",
			credentialTime: now,
			headers:        map[string]string{DateHeader: "yesterday"},
			wantErr:        "invalid Date header format",
		},
		{
			name:           "no timestamp header at all",
			credentialTime: now,
			headers:        map[string]string{},
			wantErr:        "missing timestamp header",
		},
		{
			name:           "timestamp too old",
			credentialTime: now.Add(-20 * time.Minute),
			headers:        map[string]string{XAmzDateHeader: now.Add(-20 * time.Minute).Format(ISO8601BasicFormat)},
			wantErr:        "request timestamp too far from current time",
		},
		{
			name:           "timestamp in the future",
			credentialTime: now.Add(20 * time.Minute),
			headers:        map[string]string{XAmzDateHeader: now.Add(20 * time.Minute).Format(ISO8601BasicFormat)},
			wantErr:        "request timestamp too far from current time",
		},
		{
			name:           "just inside the skew window",
			credentialTime: now.Add(-14 * time.Minute),
			headers:        map[string]string{XAmzDateHeader: now.Add(-14 * time.Minute).Format(ISO8601BasicFormat)},
		},
		{
			name:           "credential scope from another day",
			credentialTime: now.AddDate(0, 0, -3),
			headers:        map[string]string{XAmzDateHeader: now.Format(ISO8601BasicFormat)},
			wantErr:        "credential date mismatch",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/bucket/key", nil)
			for name, value := range tt.headers {
				r.Header.Set(name, value)
			}

			// The credential timestamp only ever carries a date; mirror the
			// truncation parseAuthorizationHeader performs.
			credentialTime, err := time.Parse(ISO8601DateFormat, tt.credentialTime.Format(ISO8601DateFormat))
			require.NoError(t, err)

			err = svc.validateTimestamp(credentialTime, r)
			if tt.wantErr == "" {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

// TestMwValidateSignatureTimestampSources covers the signature-side timestamp
// selection and the canonical-request failure path.
func TestMwValidateSignatureTimestampSources(t *testing.T) {
	svc, _ := MwauthService(t, 900)
	sigInfo := &SignatureInfo{
		Algorithm:       AWS4Algorithm,
		AccessKeyID:     testAccessKey,
		Date:            time.Now().UTC().Format(ISO8601DateFormat),
		Region:          "us-east-1",
		Service:         "s3",
		SignedHeaders:   []string{"host"},
		Signature:       "deadbeef",
		CredentialScope: "scope",
	}

	t.Run("missing timestamp", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/bucket/key", nil)
		err := svc.validateSignature(r, sigInfo, testSecretKey)
		require.Error(t, err)
		assert.Equal(t, "missing timestamp for signature", err.Error())
	})

	t.Run("malformed date header", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/bucket/key", nil)
		r.Header.Set(DateHeader, "not-a-date")
		err := svc.validateSignature(r, sigInfo, testSecretKey)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid date format")
	})

	t.Run("signed header absent from the request", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/bucket/key", nil)
		r.Header.Set(XAmzDateHeader, time.Now().UTC().Format(ISO8601BasicFormat))
		missing := *sigInfo
		missing.SignedHeaders = []string{"host", "x-amz-not-sent"}
		err := svc.validateSignature(r, &missing, testSecretKey)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to build canonical request")
		assert.Contains(t, err.Error(), "x-amz-not-sent")
	})

	t.Run("mismatching signature", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/bucket/key", nil)
		r.Header.Set(XAmzDateHeader, time.Now().UTC().Format(ISO8601BasicFormat))
		err := svc.validateSignature(r, sigInfo, testSecretKey)
		require.Error(t, err)
		assert.Equal(t, "signature mismatch", err.Error())
	})
}

// TestMwBuildCanonicalRequestPayloadHash pins which payload hash lands in the
// canonical request, because getting it wrong turns every upload into an opaque
// SignatureDoesNotMatch.
func TestMwBuildCanonicalRequestPayloadHash(t *testing.T) {
	svc, _ := MwauthService(t, 900)
	explicit := strings.Repeat("ab", 32)

	tests := []struct {
		name        string
		body        string
		contentHash string
		wantHash    string
	}{
		{name: "explicit hash is used verbatim", body: "payload", contentHash: explicit, wantHash: explicit},
		{name: "unsigned payload is honoured", body: "payload", contentHash: UnsignedPayload, wantHash: UnsignedPayload},
		{name: "body without a hash header falls back to UNSIGNED-PAYLOAD", body: "payload", wantHash: UnsignedPayload},
		{name: "empty body without a hash header uses the empty digest", wantHash: MwemptySHA256},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var r *http.Request
			if tt.body == "" {
				r = httptest.NewRequest(http.MethodPut, "/bucket/key", nil)
			} else {
				r = httptest.NewRequest(http.MethodPut, "/bucket/key", strings.NewReader(tt.body))
			}
			r.Host = testHost
			if tt.contentHash != "" {
				r.Header.Set(XAmzContentSha256, tt.contentHash)
			}

			canonical, err := svc.buildCanonicalRequest(r, []string{"host"})
			require.NoError(t, err)

			lines := strings.Split(canonical, "\n")
			assert.Equal(t, http.MethodPut, lines[0])
			assert.Equal(t, "/bucket/key", lines[1])
			assert.Equal(t, tt.wantHash, lines[len(lines)-1])
		})
	}
}

// TestMwBuildCanonicalHeaders covers header collection, including the Host
// fallback that HTTP/1.1 clients depend on.
func TestMwBuildCanonicalHeaders(t *testing.T) {
	svc, _ := MwauthService(t, 900)

	t.Run("host is taken from r.Host when the header map has none", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/bucket/key", nil)
		r.Host = testHost
		r.Header.Del("Host")

		got, err := svc.buildCanonicalHeaders(r, []string{"host"})
		require.NoError(t, err)
		assert.Equal(t, "host:"+testHost+"\n", got)
	})

	t.Run("values are trimmed, joined and lower-cased by name", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/bucket/key", nil)
		r.Host = testHost
		r.Header.Add("X-Amz-Meta-Tag", "  first  ")
		r.Header.Add("X-Amz-Meta-Tag", " second ")

		got, err := svc.buildCanonicalHeaders(r, []string{"Host", "X-Amz-Meta-Tag"})
		require.NoError(t, err)
		assert.Equal(t, "host:"+testHost+"\nx-amz-meta-tag:first,second\n", got)
	})

	// SigV4 collapses every run of spaces inside a value. The proxy only trimmed,
	// so a correctly signed request whose header carried repeated spaces was
	// answered 403 - and Content-Disposition with a filename, which is what a
	// pre-signed download URL carries, is exactly where that shows up.
	t.Run("sequential spaces inside a value are collapsed", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/bucket/key", nil)
		r.Host = testHost
		r.Header.Set("Content-Disposition", `  attachment;   filename="my   report.txt"  `)

		got, err := svc.buildCanonicalHeaders(r, []string{"Host", "Content-Disposition"})
		require.NoError(t, err)
		assert.Equal(t,
			"host:"+testHost+"\ncontent-disposition:attachment; filename=\"my report.txt\"\n", got,
			"a quoted string is not exempt, which is what aws-sdk-go-v2 does too")
	})

	// What the SDK's own canonicalisation does not do, mirrored deliberately:
	// only the space character is collapsed, never a tab.
	t.Run("tabs are not collapsed", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/bucket/key", nil)
		r.Host = testHost
		r.Header.Set("X-Amz-Meta-Tag", "a\t\tb")

		got, err := svc.buildCanonicalHeaders(r, []string{"X-Amz-Meta-Tag"})
		require.NoError(t, err)
		assert.Equal(t, "x-amz-meta-tag:a\t\tb\n", got)
	})

	t.Run("a signed header that was not sent is an error", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/bucket/key", nil)
		r.Host = testHost

		_, err := svc.buildCanonicalHeaders(r, []string{"host", "x-amz-missing"})
		require.Error(t, err)
		assert.Equal(t, "signed header x-amz-missing not found in request", err.Error())
	})
}

func TestMwMaxClockSkewSeconds(t *testing.T) {
	tests := []struct {
		name string
		svc  *S3AuthenticationService
		want int
	}{
		{name: "no config falls back to the AWS default", svc: &S3AuthenticationService{}, want: MaxClockSkewSeconds},
		{name: "unset value falls back to the AWS default", svc: &S3AuthenticationService{config: &config.Config{}}, want: MaxClockSkewSeconds},
		{
			name: "configured value wins",
			svc:  &S3AuthenticationService{config: &config.Config{S3Security: config.S3SecurityConfig{MaxClockSkewSeconds: 60}}},
			want: 60,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.svc.maxClockSkewSeconds())
		})
	}
}

// TestMwAuthErrorsCarryTheS3ErrorCodeMarkers pins the wording the proxy's
// determineErrorCode matches on. Rewording an error here silently downgrades
// the S3 error code a client sees, which S3 SDKs branch on.
func TestMwAuthErrorsCarryTheS3ErrorCodeMarkers(t *testing.T) {
	svc, _ := MwauthService(t, 900)
	signedAt := time.Now().UTC().Truncate(time.Second)

	tests := []struct {
		name   string
		build  func() *http.Request
		marker string
	}{
		{
			name: "unknown key maps to InvalidAccessKeyId",
			build: func() *http.Request {
				r := MwsignDateHeaderRequest(t, testSecretKey, signedAt, "/bucket/key.txt")
				auth := r.Header.Get(AuthorizationHeader)
				r.Header.Set(AuthorizationHeader, strings.Replace(auth, testAccessKey, "ghost", 1))
				return r
			},
			marker: "access key not found",
		},
		{
			name: "bad signature maps to SignatureDoesNotMatch",
			build: func() *http.Request {
				return MwsignDateHeaderRequest(t, "wrong-secret-key-32-characters!!", signedAt, "/bucket/key.txt")
			},
			marker: "signature",
		},
		{
			name: "skewed clock maps to RequestTimeTooSkewed",
			build: func() *http.Request {
				return MwsignDateHeaderRequest(t, testSecretKey, signedAt.Add(-40*time.Minute), "/bucket/key.txt")
			},
			marker: "timestamp",
		},
		{
			name: "broken header maps to an authorization header code",
			build: func() *http.Request {
				r := MwsignDateHeaderRequest(t, testSecretKey, signedAt, "/bucket/key.txt")
				r.Header.Set(AuthorizationHeader, "Basic dXNlcjpwYXNz")
				return r
			},
			marker: "authorization header",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := svc.AuthenticateRequest(tt.build())
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.marker)
		})
	}
}

// TestMwPresignedRejections covers the pre-signed guard clauses that the SDK
// round-trip tests cannot reach.
func TestMwPresignedRejections(t *testing.T) {
	svc := presignTestService(t)

	// MwpresignedRequest re-signs nothing: it takes a valid SDK URL and edits a
	// single query parameter, so each case isolates one guard.
	MwpresignedRequest := func(t *testing.T, mutate func(q url.Values)) *http.Request {
		t.Helper()
		raw := presignWithSDK(t, "velero-backups", "backups/one/velero-backup.json", 15*time.Minute)
		parsed, err := url.Parse(raw)
		require.NoError(t, err)
		q := parsed.Query()
		mutate(q)
		parsed.RawQuery = q.Encode()
		return requestFromPresignedURL(t, http.MethodGet, parsed.String())
	}

	tests := []struct {
		name    string
		mutate  func(q url.Values)
		wantErr string
	}{
		{
			name:    "unsupported algorithm",
			mutate:  func(q url.Values) { q.Set(QueryAlgorithm, "AWS4-HMAC-SHA512") },
			wantErr: "unsupported presigned algorithm",
		},
		{
			name:    "missing signature",
			mutate:  func(q url.Values) { q.Del(QuerySignature) },
			wantErr: "incomplete presigned request",
		},
		{
			name:    "missing signed headers",
			mutate:  func(q url.Values) { q.Del(QuerySignedHeaders) },
			wantErr: "incomplete presigned request",
		},
		{
			name:    "malformed credential",
			mutate:  func(q url.Values) { q.Set(QueryCredential, "only/three/parts") },
			wantErr: "malformed presigned credential",
		},
		{
			name:    "credential for another service",
			mutate:  func(q url.Values) { q.Set(QueryCredential, testAccessKey+"/20250101/us-east-1/sts/aws4_request") },
			wantErr: "malformed presigned credential",
		},
		{
			name:    "unparsable date",
			mutate:  func(q url.Values) { q.Set(QueryDate, "2025-01-01") },
			wantErr: "invalid X-Amz-Date",
		},
		{
			name:    "missing expiry",
			mutate:  func(q url.Values) { q.Del(QueryExpires) },
			wantErr: "missing " + QueryExpires,
		},
		{
			name:    "non-numeric expiry",
			mutate:  func(q url.Values) { q.Set(QueryExpires, "soon") },
			wantErr: "invalid " + QueryExpires,
		},
		{
			name:    "zero expiry",
			mutate:  func(q url.Values) { q.Set(QueryExpires, "0") },
			wantErr: "invalid " + QueryExpires,
		},
		{
			name:    "negative expiry",
			mutate:  func(q url.Values) { q.Set(QueryExpires, "-1") },
			wantErr: "invalid " + QueryExpires,
		},
		{
			name:    "expiry beyond the AWS maximum of seven days",
			mutate:  func(q url.Values) { q.Set(QueryExpires, fmt.Sprint(defaultPresignExpirySeconds+1)) },
			wantErr: "exceeds the maximum",
		},
		{
			name: "credential scope date does not match the signing date",
			mutate: func(q url.Values) {
				cred := q.Get(QueryCredential)
				parts := strings.SplitN(cred, "/", 2)
				rest := strings.SplitN(parts[1], "/", 2)
				q.Set(QueryCredential, parts[0]+"/19990101/"+rest[1])
			},
			wantErr: "credential date does not match the signing date",
		},
		{
			name: "unknown access key",
			mutate: func(q url.Values) {
				cred := q.Get(QueryCredential)
				q.Set(QueryCredential, strings.Replace(cred, testAccessKey, "ghost", 1))
			},
			wantErr: "access key not found: ghost",
		},
		{
			name: "signed header that was never sent",
			mutate: func(q url.Values) {
				q.Set(QuerySignedHeaders, q.Get(QuerySignedHeaders)+";x-amz-not-sent")
			},
			wantErr: "failed to build canonical request",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := svc.authenticatePresigned(MwpresignedRequest(t, tt.mutate))
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

// TestMwPresignedSigningTimeInTheFuture guards against a URL that dates itself
// forward to extend its own lifetime.
func TestMwPresignedSigningTimeInTheFuture(t *testing.T) {
	svc := presignTestService(t)

	err := svc.validatePresignExpiry(time.Now().UTC().Add(time.Hour), "900")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "signing time is in the future")

	// Inside the configured skew the same URL is accepted.
	assert.NoError(t, svc.validatePresignExpiry(time.Now().UTC().Add(2*time.Minute), "900"))
}

// The configured clock-skew window governs both authentication forms (ADR 0014
// D4). The header-signed path used to compare against the package constant, so a
// deployment that tightened the window — every shipped example sets 300 — kept a
// replay window three times wider on exactly the path most requests take.
func TestMwHeaderAuthHonoursTheConfiguredClockSkew(t *testing.T) {
	const requestAge = 400 * time.Second

	tests := []struct {
		name    string
		skew    int
		wantErr bool
	}{
		{name: "inside a 900 second window", skew: 900, wantErr: false},
		{name: "outside a 300 second window", skew: 300, wantErr: true},
		{name: "a Config with no value falls back to the AWS default", skew: 0, wantErr: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc, _ := MwauthService(t, tt.skew)

			requestTime := time.Now().UTC().Add(-requestAge)
			r := httptest.NewRequest(http.MethodGet, "/bucket/key", nil)
			r.Header.Set(XAmzDateHeader, requestTime.Format(ISO8601BasicFormat))

			credentialTime, err := time.Parse(ISO8601DateFormat, requestTime.Format(ISO8601DateFormat))
			require.NoError(t, err)

			err = svc.validateTimestamp(credentialTime, r)
			if !tt.wantErr {
				assert.NoError(t, err, "a request %s old must be accepted under a %ds window", requestAge, tt.skew)
				return
			}
			require.Error(t, err, "a request %s old must be refused under a %ds window", requestAge, tt.skew)
			assert.Contains(t, err.Error(), "too far from current time")
		})
	}
}

// The pre-signed ceiling is a configuration key, and the hard cap is enforced in
// the middleware as well as in validation: a Config built in code never passes
// through validate().
func TestMwMaxPresignExpirySeconds(t *testing.T) {
	tests := []struct {
		name       string
		configured int
		want       int
	}{
		{name: "unset falls back to one hour", configured: 0, want: defaultPresignExpirySeconds},
		{name: "a configured value is used", configured: 120, want: 120},
		{name: "above the S3 maximum is clamped", configured: presignExpiryHardCapSeconds + 1, want: presignExpiryHardCapSeconds},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := NewS3AuthenticationService(&config.Config{
				S3Security: config.S3SecurityConfig{MaxPresignExpirySeconds: tt.configured},
			}, logrus.New())

			assert.Equal(t, tt.want, svc.maxPresignExpirySeconds())
		})
	}
}

// A service built from a Config that sets neither budget must still answer both
// rather than returning zero, because zero would refuse every request. (A nil
// Config is not a case: the constructor dereferences it, so the `s.config != nil`
// guards in the accessors defend against a state that cannot be reached.)
func TestMwBudgetsWithoutConfiguredValues(t *testing.T) {
	svc := NewS3AuthenticationService(&config.Config{}, logrus.New())

	assert.Equal(t, MaxClockSkewSeconds, svc.maxClockSkewSeconds())
	assert.Equal(t, defaultPresignExpirySeconds, svc.maxPresignExpirySeconds())
}
