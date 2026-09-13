//go:build integration
// +build integration

package integration

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	. "github.com/guided-traffic/s3-encryption-proxy/test/integration"
)

// proxyHost is the authority of ProxyEndpoint, for the Host header of a request
// signed by hand.
func proxyHost(t *testing.T) string {
	t.Helper()
	u, err := url.Parse(ProxyEndpoint)
	require.NoError(t, err, "S3EP_TEST_PROXY_ENDPOINT is not a URL")
	return u.Host
}

// SimpleTestContext holds basic test utilities for authentication tests
type SimpleTestContext struct {
	TestBucket string
	T          *testing.T
	Ctx        context.Context
}

// NewSimpleTestContext creates a simple test context for authentication tests
func NewSimpleTestContext(t *testing.T) *SimpleTestContext {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)

	// Generate unique bucket name for this test
	testBucket := fmt.Sprintf("auth-test-bucket-%d", time.Now().UnixNano())

	return &SimpleTestContext{
		TestBucket: testBucket,
		T:          t,
		Ctx:        ctx,
	}
}

// CleanupTestBucket is a no-op for simple context (used for compatibility)
func (tc *SimpleTestContext) CleanupTestBucket() {
	// No-op for authentication tests
}

// TestAuthentication is the main authentication test suite
func TestAuthentication(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping authentication tests in short mode")
	}

	// Run all authentication-related tests as subtests
	t.Run("S3ClientAuthentication", func(t *testing.T) {
		testS3ClientAuthentication(t)
	})

	t.Run("RobustS3Authentication", func(t *testing.T) {
		testRobustS3Authentication(t)
	})

	t.Run("EnterpriseSecurityConfiguration", func(t *testing.T) {
		testEnterpriseSecurityConfiguration(t)
	})
}

// testS3ClientAuthentication tests basic S3 client authentication
func testS3ClientAuthentication(t *testing.T) {
	t.Run("InvalidCredentials", func(t *testing.T) {
		// Test that the proxy rejects invalid credentials when authentication is enabled
		ctx := NewSimpleTestContext(t)
		defer ctx.CleanupTestBucket()

		customConfig, err := config.LoadDefaultConfig(context.Background(),
			config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
				"anycredentials", // invalid access_key_id should NOT work
				"anypassword",    // invalid secret should NOT work
				"",
			)),
			config.WithRegion("us-east-1"),
			config.WithHTTPClient(TLSHTTPClient()),
		)
		require.NoError(t, err)

		customClient := s3.NewFromConfig(customConfig, func(o *s3.Options) {
			o.BaseEndpoint = aws.String(ProxyEndpoint)
			o.UsePathStyle = true
		})

		// Should NOT be able to list buckets with invalid credentials
		_, err = customClient.ListBuckets(context.Background(), &s3.ListBucketsInput{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "InvalidAccessKeyId")
	})

	t.Run("ValidCredentials", func(t *testing.T) {
		// Test with valid credentials from aes-example.yaml
		validConfig, err := config.LoadDefaultConfig(context.Background(),
			config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
				"username0", "this-is-not-very-secure", "")),
			config.WithRegion("us-east-1"),
			config.WithHTTPClient(TLSHTTPClient()),
		)
		require.NoError(t, err)

		validClient := s3.NewFromConfig(validConfig, func(o *s3.Options) {
			o.BaseEndpoint = aws.String(ProxyEndpoint)
			o.UsePathStyle = true
		})

		// Should be able to list buckets with valid credentials
		result, err := validClient.ListBuckets(context.Background(), &s3.ListBucketsInput{})
		require.NoError(t, err)
		assert.NotNil(t, result)
		t.Logf("✅ Authentication successful with valid credentials")
	})
}

// testRobustS3Authentication tests AWS Signature V4 validation and security features
func testRobustS3Authentication(t *testing.T) {
	t.Run("SecurityValidation", func(t *testing.T) {
		testSecurityFeatures(t)
	})

	t.Run("SignatureValidation", func(t *testing.T) {
		testSignatureValidation(t)
	})

	t.Run("ClockSkewProtection", func(t *testing.T) {
		testClockSkewProtection(t)
	})

	t.Run("SecurityMetrics", func(t *testing.T) {
		testSecurityMetrics(t)
	})
}

// testEnterpriseSecurityConfiguration tests enterprise security features
func testEnterpriseSecurityConfiguration(t *testing.T) {
	t.Run("HealthEndpointAccessible", func(t *testing.T) {
		// Health endpoint should be accessible without authentication
		resp, err := TLSHTTPClient().Get(ProxyEndpoint + "/health")
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		t.Logf("Health endpoint accessible: %d", resp.StatusCode)
	})

	t.Run("S3EndpointProtected", func(t *testing.T) {
		// S3 endpoint should require authentication
		resp, err := TLSHTTPClient().Get(ProxyEndpoint + "/")
		require.NoError(t, err)
		defer resp.Body.Close()

		// Mandatory authentication: an unsigned S3 request is refused. Logging
		// the status instead of asserting it made this subtest green against a
		// proxy that served the request.
		require.Equal(t, http.StatusForbidden, resp.StatusCode,
			"an unsigned request must not be served")
	})

	t.Run("S3ClientCredentials", func(t *testing.T) {
		// Test with specific S3 client credentials
		testCredentials := []struct {
			accessKey string
			secretKey string
			expected  bool // true if should work, false if should fail
		}{
			{"username0", "this-is-not-very-secure", true}, // Valid from aes-example.yaml config
			{"username1", "this-is-even-worse", true},      // Valid from aes-example.yaml config
			{"invalidkey", "invalidsecret", false},         // Invalid credentials
		}

		for _, tc := range testCredentials {
			t.Run(tc.accessKey, func(t *testing.T) {
				// Create S3 client with test credentials
				cfg, err := config.LoadDefaultConfig(context.TODO(),
					config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
						tc.accessKey, tc.secretKey, "")),
					config.WithRegion("us-east-1"),
					config.WithEndpointResolverWithOptions(aws.EndpointResolverWithOptionsFunc(
						func(_, _ string, _ ...interface{}) (aws.Endpoint, error) {
							return aws.Endpoint{
								URL:           ProxyEndpoint,
								SigningRegion: "us-east-1",
							}, nil
						})),
					config.WithHTTPClient(TLSHTTPClient()),
				)
				require.NoError(t, err)

				client := s3.NewFromConfig(cfg)

				// Try to list buckets
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()

				_, err = client.ListBuckets(ctx, &s3.ListBucketsInput{})

				if tc.expected {
					require.NoError(t, err, "a configured client must be able to authenticate: %s", tc.accessKey)
					return
				}
				require.Error(t, err, "an unknown access key must be refused: %s", tc.accessKey)
				assert.Contains(t, err.Error(), "InvalidAccessKeyId",
					"an unknown access key is refused as InvalidAccessKeyId, not as something else")
			})
		}
	})

	t.Run("SecurityHeaders", func(t *testing.T) {
		// The headers ride on the authentication refusal, which is the response
		// the proxy writes itself. This used to read /health - a response that
		// carries none of them - and log whatever it found, so it passed either
		// way and named a header the proxy deliberately does not set.
		resp, err := TLSHTTPClient().Get(ProxyEndpoint + "/")
		require.NoError(t, err)
		defer resp.Body.Close()

		require.Equal(t, http.StatusForbidden, resp.StatusCode)
		assert.Equal(t, "nosniff", resp.Header.Get("X-Content-Type-Options"))
		assert.Equal(t, "DENY", resp.Header.Get("X-Frame-Options"))
		assert.Equal(t, "no-cache, no-store, must-revalidate", resp.Header.Get("Cache-Control"))
		assert.Empty(t, resp.Header.Get("X-XSS-Protection"),
			"a deprecated header browsers ignore is not set; asserting it would pin a promise nothing keeps")
	})
}

// Security validation helper functions

func testSecurityFeatures(t *testing.T) {
	t.Log("Testing security features of S3 authentication")

	// The status follows the code (ADR 0014 D13): a header the proxy cannot use
	// makes the request itself unusable, which is 400, while a request that was
	// understood and refused is 403. A blanket status tells a client to fix the
	// wrong thing.
	t.Run("OversizedAuthHeader", func(t *testing.T) {
		// Test with oversized authorization header
		req, err := http.NewRequest("GET", ProxyEndpoint+"/", nil)
		require.NoError(t, err)

		// Create a very large authorization header
		largeAuth := "AWS4-HMAC-SHA256 " + strings.Repeat("x", 10000)
		req.Header.Set("Authorization", largeAuth)

		resp, err := TLSHTTPClient().Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		assert.Equal(t, "InvalidRequest", authErrorCode(t, resp))
	})

	t.Run("MalformedAuthHeader", func(t *testing.T) {
		// Test with malformed authorization header
		req, err := http.NewRequest("GET", ProxyEndpoint+"/", nil)
		require.NoError(t, err)

		req.Header.Set("Authorization", "Invalid-Header-Format")

		resp, err := TLSHTTPClient().Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		assert.Equal(t, "InvalidRequest", authErrorCode(t, resp),
			"a scheme this proxy does not implement is InvalidRequest, not a parse failure")
	})

	t.Run("MissingHeaders", func(t *testing.T) {
		// Test with missing required headers
		req, err := http.NewRequest("GET", ProxyEndpoint+"/", nil)
		require.NoError(t, err)

		// No authorization header at all
		resp, err := TLSHTTPClient().Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		// An anonymous request, which S3 and MinIO both answer AccessDenied.
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
		assert.Equal(t, "AccessDenied", authErrorCode(t, resp))
	})
}

// authErrorCode reads the S3 error code out of a refusal, and asserts on the way
// that the refusal is an S3 <Error> document at all (ADR 0008 D7) carrying the
// proxy's own request id (ADR 0008 D12a).
func authErrorCode(t *testing.T, resp *http.Response) string {
	t.Helper()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var doc struct {
		XMLName   xml.Name `xml:"Error"`
		Code      string   `xml:"Code"`
		RequestID string   `xml:"RequestId"`
	}
	require.NoError(t, xml.Unmarshal(body, &doc), "body: %s", body)

	id := resp.Header.Get("x-amz-request-id")
	assert.NotEmpty(t, id, "every answer states the proxy's own request id")
	assert.Equal(t, id, doc.RequestID, "the document and the header state one id")

	return doc.Code
}

// sendWellFormedAuthHeader issues a request whose Authorization header is a
// syntactically valid AWS4-HMAC-SHA256 header for accessKey, carrying a
// signature the proxy cannot have computed. It returns the status and body.
func sendWellFormedAuthHeader(t *testing.T, accessKey string) (int, string) {
	t.Helper()

	req, err := http.NewRequest("GET", ProxyEndpoint+"/", nil)
	require.NoError(t, err)

	now := time.Now().UTC()
	req.Header.Set("Host", proxyHost(t))
	req.Header.Set("X-Amz-Date", now.Format("20060102T150405Z"))
	req.Header.Set("X-Amz-Content-Sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")

	credential := fmt.Sprintf("%s/%s/us-east-1/s3/aws4_request", accessKey, now.Format("20060102"))
	req.Header.Set("Authorization", fmt.Sprintf(
		"AWS4-HMAC-SHA256 Credential=%s, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=%s",
		credential, "dummysignaturefortestingpurposes1234567890abcdef"))

	resp, err := TLSHTTPClient().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, string(body)
}

func testSignatureValidation(t *testing.T) {
	t.Log("Testing AWS Signature V4 validation")

	// Both refusals are 403 and both reject the request; which code comes back
	// says which check failed, and S3 clients branch on that. Asserting only the
	// status let this subtest pass against a proxy that served the request to a
	// caller holding no secret key at all.
	t.Run("KnownKeyBadSignature", func(t *testing.T) {
		status, body := sendWellFormedAuthHeader(t, "username0")

		require.Equal(t, http.StatusForbidden, status)
		assert.Contains(t, body, "SignatureDoesNotMatch",
			"a configured key with a signature the proxy did not compute is refused for the signature")
	})

	t.Run("UnknownKey", func(t *testing.T) {
		status, body := sendWellFormedAuthHeader(t, "testclient123")

		require.Equal(t, http.StatusForbidden, status)
		assert.Contains(t, body, "InvalidAccessKeyId",
			"a key no s3_clients entry declares is refused for the key, not for the signature")
	})
}

func testClockSkewProtection(t *testing.T) {
	t.Log("Testing clock skew protection")

	t.Run("OldTimestamp", func(t *testing.T) {
		req, err := http.NewRequest("GET", ProxyEndpoint+"/", nil)
		require.NoError(t, err)

		// Use a timestamp that's too old (>15 minutes)
		oldTime := time.Now().UTC().Add(-20 * time.Minute)
		amzDate := oldTime.Format("20060102T150405Z")
		dateStamp := oldTime.Format("20060102")

		req.Header.Set("Host", proxyHost(t))
		req.Header.Set("X-Amz-Date", amzDate)

		credential := fmt.Sprintf("testkey/%s/us-east-1/s3/aws4_request", dateStamp)
		authHeader := fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s, SignedHeaders=host;x-amz-date, Signature=dummy",
			credential)

		req.Header.Set("Authorization", authHeader)

		resp, err := TLSHTTPClient().Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		// 20 minutes against a 900-second window: refused for the skew, and named
		// as such. The subtest is the only thing that covers the clock-skew
		// boundary end to end, and it used to log the status and pass.
		require.Equal(t, http.StatusForbidden, resp.StatusCode)
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.Contains(t, string(body), "RequestTimeTooSkewed",
			"a stale request is refused for its timestamp, not for its signature")
	})
}

func testSecurityMetrics(t *testing.T) {
	t.Log("Testing security metrics and monitoring")

	t.Run("MetricsCollection", func(t *testing.T) {
		// A metrics endpoint that cannot be reached is a broken listener, not a
		// reason to pass: skipping here green-lit exactly the failure the
		// assertions below exist to catch (ADR 0019 D2).
		resp, err := http.Get("http://localhost:9090/metrics")
		require.NoError(t, err, "the monitoring listener must be reachable for this suite")
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		buf := new(bytes.Buffer)
		_, err = buf.ReadFrom(resp.Body)
		require.NoError(t, err)
		metricsContent := buf.String()

		// The two series the request middleware exists to produce. They reached
		// no scrape at all until 5.0.0: they were registered on the proxy's own
		// registry while /metrics served prometheus.DefaultGatherer, and this
		// test only checked that the endpoint answered 200 — which it did, with
		// a document that never contained them.
		assert.Contains(t, metricsContent, "s3ep_requests_total",
			"the request counter must reach a scrape")
		assert.Contains(t, metricsContent, "s3ep_request_duration_seconds",
			"the latency histogram must reach a scrape")
		assert.Contains(t, metricsContent, "s3ep_active_connections",
			"and the collectors that were already exported stayed exported")
	})
}
