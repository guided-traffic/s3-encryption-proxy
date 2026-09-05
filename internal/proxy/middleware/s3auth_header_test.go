package middleware

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// signWithSDK signs a request the way an AWS SDK client does, so the header path
// is tested against a real signer rather than against our own idea of one.
//
// The middleware had no test file at all before this; every SigV4 code path was
// at 0 % coverage while being the only thing standing between a client and the
// backend.
func signWithSDK(t *testing.T, method, target string, body []byte, payloadHash string) *http.Request {
	t.Helper()

	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, "https://"+testHost+target, reader) // #nosec G107
	require.NoError(t, err)
	req.Host = testHost
	req.Header.Set("Host", testHost)
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)

	creds, err := credentials.NewStaticCredentialsProvider(testAccessKey, testSecretKey, "").
		Retrieve(context.Background())
	require.NoError(t, err)

	// S3 signs the already-escaped path exactly once. Without this the signer
	// escapes it a second time ("%20" becomes "%2520"), which is not what any
	// S3 client sends.
	signer := v4.NewSigner(func(o *v4.SignerOptions) { o.DisableURIPathEscaping = true })
	require.NoError(t, signer.SignHTTP(context.Background(), creds, req,
		payloadHash, "s3", "us-east-1", time.Now().UTC()))

	// The server sees a request whose URL carries only the path and query.
	serverReq := httptest.NewRequest(method, target, reader)
	serverReq.Host = testHost
	for name, values := range req.Header {
		for _, v := range values {
			serverReq.Header.Add(name, v)
		}
	}
	if body != nil {
		serverReq.ContentLength = int64(len(body))
	}
	return serverReq
}

func TestAuthenticateRequest_SDKSignedHeaders(t *testing.T) {
	service := presignTestService(t)

	cases := []struct {
		name    string
		method  string
		target  string
		payload string
	}{
		{"simple_get", http.MethodGet, "/velero/backups/b1/velero-backup.json", UnsignedPayload},
		{"get_with_query", http.MethodGet, "/velero?list-type=2&prefix=backups%2F&delimiter=%2F", UnsignedPayload},
		{"key_with_space", http.MethodGet, "/velero/backups/my%20backup/file.json", UnsignedPayload},
		{"key_with_tilde", http.MethodGet, "/velero/backups/my~backup/file.json", UnsignedPayload},
		{"streaming_upload", http.MethodPut, "/velero/backups/b1/data", "STREAMING-UNSIGNED-PAYLOAD-TRAILER"},
		{"multipart_part", http.MethodPut, "/velero/big?partNumber=3&uploadId=abc~def", UnsignedPayload},
		{"delete", http.MethodDelete, "/velero/backups/b1/velero-backup.json", UnsignedPayload},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := signWithSDK(t, tc.method, tc.target, nil, tc.payload)
			require.NoError(t, service.AuthenticateRequest(r),
				"a request signed by the AWS SDK signer must validate")
		})
	}
}

func TestAuthenticateRequest_HeaderTampering(t *testing.T) {
	service := presignTestService(t)

	t.Run("changed_path", func(t *testing.T) {
		r := signWithSDK(t, http.MethodGet, "/velero/a", nil, UnsignedPayload)
		r.URL.Path = "/velero/b"
		require.Error(t, service.AuthenticateRequest(r))
	})

	t.Run("changed_query", func(t *testing.T) {
		r := signWithSDK(t, http.MethodGet, "/velero?list-type=2", nil, UnsignedPayload)
		r.URL.RawQuery = "list-type=2&prefix=secret"
		require.Error(t, service.AuthenticateRequest(r))
	})

	t.Run("changed_host", func(t *testing.T) {
		r := signWithSDK(t, http.MethodGet, "/velero/a", nil, UnsignedPayload)
		r.Host = "attacker.example.com"
		r.Header.Set("Host", "attacker.example.com")
		require.Error(t, service.AuthenticateRequest(r))
	})

	t.Run("changed_payload_hash", func(t *testing.T) {
		r := signWithSDK(t, http.MethodPut, "/velero/a", nil, UnsignedPayload)
		r.Header.Set("X-Amz-Content-Sha256", "STREAMING-UNSIGNED-PAYLOAD-TRAILER")
		require.Error(t, service.AuthenticateRequest(r),
			"the payload hash is part of the canonical request")
	})

	t.Run("unknown_access_key", func(t *testing.T) {
		r := signWithSDK(t, http.MethodGet, "/velero/a", nil, UnsignedPayload)
		auth := r.Header.Get(AuthorizationHeader)
		r.Header.Set(AuthorizationHeader, strings.Replace(auth, testAccessKey, "nobody-here", 1))
		err := service.AuthenticateRequest(r)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "access key not found")
	})
}

func TestAuthenticateRequest_MalformedHeaders(t *testing.T) {
	service := presignTestService(t)

	cases := map[string]string{
		"empty":            "",
		"wrong_algorithm":  "AWS3-HMAC-SHA1 Credential=a/20260101/us-east-1/s3/aws4_request, SignedHeaders=host, Signature=aa",
		"missing_pieces":   "AWS4-HMAC-SHA256 Credential=a/20260101/us-east-1/s3/aws4_request",
		"bad_scope_length": "AWS4-HMAC-SHA256 Credential=a/b, SignedHeaders=host, Signature=aa",
		"wrong_service":    "AWS4-HMAC-SHA256 Credential=velero-e2e/20260101/us-east-1/sqs/aws4_request, SignedHeaders=host, Signature=aa",
		"bad_date":         "AWS4-HMAC-SHA256 Credential=velero-e2e/notadate/us-east-1/s3/aws4_request, SignedHeaders=host, Signature=aa",
	}

	for name, header := range cases {
		t.Run(name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/velero/a", nil)
			r.Host = testHost
			if header != "" {
				r.Header.Set(AuthorizationHeader, header)
			}
			require.Error(t, service.AuthenticateRequest(r))
		})
	}

	t.Run("oversized_header", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/velero/a", nil)
		r.Host = testHost
		r.Header.Set(AuthorizationHeader, strings.Repeat("A", MaxAuthHeaderSize+1))
		err := service.AuthenticateRequest(r)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "too large")
	})
}

// A signature that is valid but stale must be refused: otherwise a captured
// request can be replayed indefinitely.
func TestAuthenticateRequest_ClockSkew(t *testing.T) {
	service := presignTestService(t)

	r := signWithSDK(t, http.MethodGet, "/velero/a", nil, UnsignedPayload)
	// Move the request date well outside the configured 900-second window while
	// leaving the signature intact.
	stale := time.Now().UTC().Add(-2 * time.Hour).Format(ISO8601BasicFormat)
	r.Header.Set(XAmzDateHeader, stale)

	err := service.AuthenticateRequest(r)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "timestamp validation failed")
}
