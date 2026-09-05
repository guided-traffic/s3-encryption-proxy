package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/guided-traffic/s3-encryption-proxy/internal/config"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testAccessKey = "velero-e2e"
	testSecretKey = "velero-secret-key-32-characters"
	testHost      = "s3ep-proxy.s3ep.svc.cluster.local:8443"
)

func presignTestService(t *testing.T) *S3AuthenticationService {
	t.Helper()
	logger := logrus.New()
	logger.SetOutput(discardWriter{})
	return NewS3AuthenticationService(&config.Config{
		S3Clients: []config.S3ClientCredentials{
			{Type: "static", AccessKeyID: testAccessKey, SecretKey: testSecretKey, Description: "test client"},
		},
		S3Security: config.S3SecurityConfig{MaxClockSkewSeconds: 900},
	}, logger)
}

type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }

// presignWithSDK produces a pre-signed URL exactly the way the Velero AWS plugin
// does, so the validator is tested against a real signer rather than against our
// own idea of one.
func presignWithSDK(t *testing.T, bucket, key string, expires time.Duration) string {
	t.Helper()
	client := s3.New(s3.Options{
		Region:       "us-east-1",
		Credentials:  credentials.NewStaticCredentialsProvider(testAccessKey, testSecretKey, ""),
		BaseEndpoint: aws.String("https://" + testHost),
		UsePathStyle: true,
	})
	req, err := s3.NewPresignClient(client, func(o *s3.PresignOptions) {
		o.Expires = expires
	}).PresignGetObject(context.Background(), &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	require.NoError(t, err)
	return req.URL
}

// requestFromPresignedURL turns a pre-signed URL into the server-side request
// the proxy would see.
func requestFromPresignedURL(t *testing.T, method, rawURL string) *http.Request {
	t.Helper()
	parsed, err := url.Parse(rawURL)
	require.NoError(t, err)

	r := httptest.NewRequest(method, parsed.RequestURI(), nil)
	r.Host = parsed.Host
	r.Header.Set("Host", parsed.Host)
	return r
}

// TestAuthenticateRequest_SDKPresignedURL is the regression test for the
// Velero download path: backup logs, restore logs and backup download are all
// pre-signed GETs, and before this they were rejected with 403.
func TestAuthenticateRequest_SDKPresignedURL(t *testing.T) {
	service := presignTestService(t)

	cases := map[string]string{
		"simple_key":        "backups/mybackup/velero-backup.json",
		"gz_key":            "backups/mybackup/mybackup-logs.gz",
		"key_with_spaces":   "backups/my backup/velero backup.json",
		"key_with_tilde":    "backups/my~backup/data~1.json",
		"key_with_plus":     "backups/my+backup/data+1.json",
		"key_with_unicode":  "backups/münchen/backup.json",
		"deeply_nested_key": "backups/a/b/c/d/e/f/g/h/velero-backup.json",
	}

	for name, key := range cases {
		t.Run(name, func(t *testing.T) {
			signed := presignWithSDK(t, "velero", key, 10*time.Minute)
			r := requestFromPresignedURL(t, http.MethodGet, signed)

			require.NoError(t, service.AuthenticateRequest(r),
				"a URL signed by the AWS SDK must validate")
		})
	}
}

// Any change to the signed material must invalidate the URL.
func TestAuthenticateRequest_PresignedTampering(t *testing.T) {
	service := presignTestService(t)
	signed := presignWithSDK(t, "velero", "backups/b1/velero-backup.json", 10*time.Minute)

	t.Run("different_key", func(t *testing.T) {
		tampered := strings.Replace(signed, "velero-backup.json", "velero-secret.json", 1)
		require.Error(t, service.AuthenticateRequest(requestFromPresignedURL(t, http.MethodGet, tampered)),
			"repointing a signed URL at another object must fail")
	})

	t.Run("different_bucket", func(t *testing.T) {
		tampered := strings.Replace(signed, "/velero/", "/other-bucket/", 1)
		require.Error(t, service.AuthenticateRequest(requestFromPresignedURL(t, http.MethodGet, tampered)),
			"repointing a signed URL at another bucket must fail")
	})

	t.Run("different_method", func(t *testing.T) {
		require.Error(t, service.AuthenticateRequest(requestFromPresignedURL(t, http.MethodDelete, signed)),
			"a GET URL must not authorise a DELETE")
	})

	t.Run("modified_signature", func(t *testing.T) {
		parsed, err := url.Parse(signed)
		require.NoError(t, err)
		q := parsed.Query()
		sig := q.Get(QuerySignature)
		q.Set(QuerySignature, flipLastHexDigit(sig))
		parsed.RawQuery = q.Encode()
		require.Error(t, service.AuthenticateRequest(requestFromPresignedURL(t, http.MethodGet, parsed.String())))
	})

	t.Run("extra_query_parameter", func(t *testing.T) {
		tampered := signed + "&versionId=deadbeef"
		require.Error(t, service.AuthenticateRequest(requestFromPresignedURL(t, http.MethodGet, tampered)),
			"adding an unsigned query parameter must invalidate the signature")
	})

	t.Run("unknown_access_key", func(t *testing.T) {
		parsed, err := url.Parse(signed)
		require.NoError(t, err)
		q := parsed.Query()
		q.Set(QueryCredential, strings.Replace(q.Get(QueryCredential), testAccessKey, "someone-else", 1))
		parsed.RawQuery = q.Encode()
		err = service.AuthenticateRequest(requestFromPresignedURL(t, http.MethodGet, parsed.String()))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "access key not found")
	})

	t.Run("different_host", func(t *testing.T) {
		r := requestFromPresignedURL(t, http.MethodGet, signed)
		r.Host = "attacker.example.com"
		r.Header.Set("Host", "attacker.example.com")
		require.Error(t, service.AuthenticateRequest(r),
			"host is a signed header, so replaying against another host must fail")
	})
}

// Expiry has to be enforced, otherwise a leaked URL is permanent.
func TestAuthenticateRequest_PresignedExpiry(t *testing.T) {
	service := presignTestService(t)

	t.Run("expired_url_is_rejected", func(t *testing.T) {
		signed := presignWithSDK(t, "velero", "backups/b1/velero-backup.json", 1*time.Second)
		r := requestFromPresignedURL(t, http.MethodGet, signed)
		// Move the signing time far enough back that even the clock-skew
		// tolerance cannot keep the URL alive.
		rewindSigningTime(t, r, 2*time.Hour)

		err := service.AuthenticateRequest(r)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "expired")
	})

	t.Run("missing_expires_is_rejected", func(t *testing.T) {
		signed := presignWithSDK(t, "velero", "backups/b1/velero-backup.json", 10*time.Minute)
		parsed, err := url.Parse(signed)
		require.NoError(t, err)
		q := parsed.Query()
		q.Del(QueryExpires)
		parsed.RawQuery = q.Encode()

		err = service.AuthenticateRequest(requestFromPresignedURL(t, http.MethodGet, parsed.String()))
		require.Error(t, err)
		assert.Contains(t, err.Error(), QueryExpires)
	})

	t.Run("oversized_expires_is_rejected", func(t *testing.T) {
		signed := presignWithSDK(t, "velero", "backups/b1/velero-backup.json", 10*time.Minute)
		parsed, err := url.Parse(signed)
		require.NoError(t, err)
		q := parsed.Query()
		q.Set(QueryExpires, strconv.Itoa(maxPresignExpirySeconds+1))
		parsed.RawQuery = q.Encode()

		err = service.AuthenticateRequest(requestFromPresignedURL(t, http.MethodGet, parsed.String()))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "maximum")
	})

	t.Run("future_signing_time_is_rejected", func(t *testing.T) {
		signed := presignWithSDK(t, "velero", "backups/b1/velero-backup.json", 10*time.Minute)
		r := requestFromPresignedURL(t, http.MethodGet, signed)
		rewindSigningTime(t, r, -48*time.Hour) // 2 days into the future

		err := service.AuthenticateRequest(r)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "future")
	})
}

func TestAuthenticateRequest_PresignedMalformed(t *testing.T) {
	service := presignTestService(t)

	cases := map[string]string{
		"wrong_algorithm":      "/velero/k?X-Amz-Algorithm=AWS3-HMAC-SHA1&X-Amz-Signature=aa",
		"missing_signature":    "/velero/k?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=a/20260101/us-east-1/s3/aws4_request&X-Amz-SignedHeaders=host",
		"bad_credential_scope": "/velero/k?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=only-two/parts&X-Amz-Signature=aa&X-Amz-SignedHeaders=host&X-Amz-Date=20260101T000000Z&X-Amz-Expires=60",
		"wrong_service":        "/velero/k?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=velero-e2e/20260101/us-east-1/sqs/aws4_request&X-Amz-Signature=aa&X-Amz-SignedHeaders=host&X-Amz-Date=20260101T000000Z&X-Amz-Expires=60",
		"invalid_date":         "/velero/k?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=velero-e2e/20260101/us-east-1/s3/aws4_request&X-Amz-Signature=aa&X-Amz-SignedHeaders=host&X-Amz-Date=not-a-date&X-Amz-Expires=60",
	}

	for name, target := range cases {
		t.Run(name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, target, nil)
			r.Host = testHost
			require.Error(t, service.AuthenticateRequest(r))
		})
	}
}

// A request without a query signature must still take the header path.
func TestAuthenticateRequest_HeaderPathUnaffected(t *testing.T) {
	service := presignTestService(t)
	r := httptest.NewRequest(http.MethodGet, "/velero/k", nil)
	r.Host = testHost

	err := service.AuthenticateRequest(r)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "authorization header",
		"a request with neither form must fail on the header path, not the presigned one")
}

// uriEncode has to match the AWS canonicalisation rules exactly: net/url does
// not, which is why it is not used.
func TestURIEncode(t *testing.T) {
	cases := []struct {
		in          string
		encodeSlash bool
		want        string
	}{
		{"simple", true, "simple"},
		{"with space", true, "with%20space"},
		{"tilde~kept", true, "tilde~kept"},
		{"plus+encoded", true, "plus%2Bencoded"},
		{"a/b", true, "a%2Fb"},
		{"a/b", false, "a/b"},
		{"unreserved-._~", true, "unreserved-._~"},
		{"münchen", true, "m%C3%BCnchen"},
		{"100%", true, "100%25"},
		{"", true, ""},
	}
	for _, tc := range cases {
		t.Run(tc.in+"/"+strconv.FormatBool(tc.encodeSlash), func(t *testing.T) {
			assert.Equal(t, tc.want, uriEncode(tc.in, tc.encodeSlash))
		})
	}
}

func TestCanonicalQueryString(t *testing.T) {
	// Sorted by encoded name, then encoded value; values URI-encoded.
	values := url.Values{
		"prefix":     {"backups/name/"},
		"delimiter":  {"/"},
		"max-keys":   {"1000"},
		"list-type":  {"2"},
		"empty":      {""},
		"multivalue": {"b", "a"},
	}
	assert.Equal(t,
		"delimiter=%2F&empty=&list-type=2&max-keys=1000&multivalue=a&multivalue=b&prefix=backups%2Fname%2F",
		canonicalQueryString(values))
}

func TestCanonicalURI(t *testing.T) {
	assert.Equal(t, "/", canonicalURI(""))
	assert.Equal(t, "/bucket/key", canonicalURI("/bucket/key"))
	assert.Equal(t, "/bucket/a%20b", canonicalURI("/bucket/a b"))
	assert.Equal(t, "/bucket/a~b", canonicalURI("/bucket/a~b"))
}

// flipLastHexDigit changes a signature by one character.
func flipLastHexDigit(sig string) string {
	if sig == "" {
		return "0"
	}
	last := sig[len(sig)-1]
	if last == '0' {
		return sig[:len(sig)-1] + "1"
	}
	return sig[:len(sig)-1] + "0"
}

// rewindSigningTime moves X-Amz-Date back by d without re-signing, so the
// signature stays valid while the expiry window moves.
func rewindSigningTime(t *testing.T, r *http.Request, d time.Duration) {
	t.Helper()
	q := r.URL.Query()
	signedAt, err := time.Parse(ISO8601BasicFormat, q.Get(QueryDate))
	require.NoError(t, err)
	q.Set(QueryDate, signedAt.Add(-d).UTC().Format(ISO8601BasicFormat))
	r.URL.RawQuery = q.Encode()
}
