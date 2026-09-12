//go:build integration
// +build integration

package integration

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
		)
		require.NoError(t, err)

		customClient := s3.NewFromConfig(customConfig, func(o *s3.Options) {
			o.BaseEndpoint = aws.String("http://localhost:8080")
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
		)
		require.NoError(t, err)

		validClient := s3.NewFromConfig(validConfig, func(o *s3.Options) {
			o.BaseEndpoint = aws.String("http://localhost:8080")
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
		resp, err := http.Get("http://localhost:8080/health")
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		t.Logf("Health endpoint accessible: %d", resp.StatusCode)
	})

	t.Run("S3EndpointProtected", func(t *testing.T) {
		// S3 endpoint should require authentication
		resp, err := http.Get("http://localhost:8080/")
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
						func(service, region string, options ...interface{}) (aws.Endpoint, error) {
							return aws.Endpoint{
								URL:           "http://localhost:8080",
								SigningRegion: "us-east-1",
							}, nil
						})),
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
		resp, err := http.Get("http://localhost:8080/")
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

	t.Run("OversizedAuthHeader", func(t *testing.T) {
		// Test with oversized authorization header
		req, err := http.NewRequest("GET", "http://localhost:8080/", nil)
		require.NoError(t, err)

		// Create a very large authorization header
		largeAuth := "AWS4-HMAC-SHA256 " + strings.Repeat("x", 10000)
		req.Header.Set("Authorization", largeAuth)

		client := &http.Client{Timeout: 5 * time.Second}
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	})

	t.Run("MalformedAuthHeader", func(t *testing.T) {
		// Test with malformed authorization header
		req, err := http.NewRequest("GET", "http://localhost:8080/", nil)
		require.NoError(t, err)

		req.Header.Set("Authorization", "Invalid-Header-Format")

		client := &http.Client{Timeout: 5 * time.Second}
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	})

	t.Run("MissingHeaders", func(t *testing.T) {
		// Test with missing required headers
		req, err := http.NewRequest("GET", "http://localhost:8080/", nil)
		require.NoError(t, err)

		// No authorization header at all
		client := &http.Client{Timeout: 5 * time.Second}
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	})
}

func testSignatureValidation(t *testing.T) {
	t.Log("Testing AWS Signature V4 validation")

	t.Run("ValidSignatureFormat", func(t *testing.T) {
		// Create a properly formatted AWS4 signature
		accessKey := "testclient123"
		region := "us-east-1"
		service := "s3"

		// Create request
		req, err := http.NewRequest("GET", "http://localhost:8080/", nil)
		require.NoError(t, err)

		// Add required headers
		now := time.Now().UTC()
		amzDate := now.Format("20060102T150405Z")
		dateStamp := now.Format("20060102")

		req.Header.Set("Host", "localhost:8080")
		req.Header.Set("X-Amz-Date", amzDate)
		req.Header.Set("X-Amz-Content-Sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")

		// Build authorization header
		credential := fmt.Sprintf("%s/%s/%s/%s/aws4_request", accessKey, dateStamp, region, service)
		signedHeaders := "host;x-amz-content-sha256;x-amz-date"

		// For this test, we'll use a dummy signature since we're testing the format validation
		signature := "dummysignaturefortestingpurposes1234567890abcdef"

		authHeader := fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s, SignedHeaders=%s, Signature=%s",
			credential, signedHeaders, signature)

		req.Header.Set("Authorization", authHeader)

		client := &http.Client{Timeout: 5 * time.Second}
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		// A well-formed header with a signature that is not the one the proxy
		// computes is refused as SignatureDoesNotMatch. Logging the status let
		// this subtest pass against a proxy that served the request to a caller
		// holding no secret key at all.
		require.Equal(t, http.StatusForbidden, resp.StatusCode)
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.Contains(t, string(body), "SignatureDoesNotMatch",
			"a bad signature is refused for being a bad signature")
	})
}

func testClockSkewProtection(t *testing.T) {
	t.Log("Testing clock skew protection")

	t.Run("OldTimestamp", func(t *testing.T) {
		req, err := http.NewRequest("GET", "http://localhost:8080/", nil)
		require.NoError(t, err)

		// Use a timestamp that's too old (>15 minutes)
		oldTime := time.Now().UTC().Add(-20 * time.Minute)
		amzDate := oldTime.Format("20060102T150405Z")
		dateStamp := oldTime.Format("20060102")

		req.Header.Set("Host", "localhost:8080")
		req.Header.Set("X-Amz-Date", amzDate)

		credential := fmt.Sprintf("testkey/%s/us-east-1/s3/aws4_request", dateStamp)
		authHeader := fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s, SignedHeaders=host;x-amz-date, Signature=dummy",
			credential)

		req.Header.Set("Authorization", authHeader)

		client := &http.Client{Timeout: 5 * time.Second}
		resp, err := client.Do(req)
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

// Helper functions for AWS signature calculation

func createValidAWS4Signature(accessKey, secretKey, region, service string, req *http.Request) string {
	// This is a simplified helper - in practice, you'd use the full AWS SDK signing process
	now := time.Now().UTC()
	dateStamp := now.Format("20060102")

	// Build string to sign (simplified)
	stringToSign := fmt.Sprintf("AWS4-HMAC-SHA256\n%s\n%s/%s/%s/aws4_request\n%s",
		now.Format("20060102T150405Z"),
		dateStamp, region, service,
		"dummy_canonical_request_hash")

	// Calculate signature
	kDate := hmacSHA256([]byte("AWS4"+secretKey), []byte(dateStamp))
	kRegion := hmacSHA256(kDate, []byte(region))
	kService := hmacSHA256(kRegion, []byte(service))
	kSigning := hmacSHA256(kService, []byte("aws4_request"))
	signature := hmacSHA256(kSigning, []byte(stringToSign))

	return hex.EncodeToString(signature)
}

func hmacSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}
