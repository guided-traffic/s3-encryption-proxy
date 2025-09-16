//go:build integration
// +build integration

package integration

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRobustS3Authentication(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping robust authentication tests in short mode")
	}

	t.Run("SecurityValidation", func(t *testing.T) {
		// Test security features of the authentication system
		testSecurityFeatures(t)
	})

	t.Run("SignatureValidation", func(t *testing.T) {
		// Test AWS Signature V4 validation
		testSignatureValidation(t)
	})

	t.Run("ClockSkewProtection", func(t *testing.T) {
		// Test clock skew protection
		testClockSkewProtection(t)
	})

	t.Run("RateLimiting", func(t *testing.T) {
		// Test rate limiting functionality
		testRateLimiting(t)
	})
}

func testSecurityFeatures(t *testing.T) {
	t.Log("Testing security features of S3 authentication")

	// Test 1: Oversized authorization header
	t.Run("OversizedAuthHeader", func(t *testing.T) {
		req, err := http.NewRequest("GET", "http://localhost:8080/", nil)
		require.NoError(t, err)

		// Create an oversized authorization header (>8KB)
		oversizedAuth := "AWS4-HMAC-SHA256 " + strings.Repeat("x", 9000)
		req.Header.Set("Authorization", oversizedAuth)

		client := &http.Client{Timeout: 5 * time.Second}
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Should be rejected for security reasons
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	})

	// Test 2: Malformed authorization header
	t.Run("MalformedAuthHeader", func(t *testing.T) {
		req, err := http.NewRequest("GET", "http://localhost:8080/", nil)
		require.NoError(t, err)

		req.Header.Set("Authorization", "MALFORMED-HEADER")

		client := &http.Client{Timeout: 5 * time.Second}
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	})

	// Test 3: Missing required headers
	t.Run("MissingHeaders", func(t *testing.T) {
		req, err := http.NewRequest("GET", "http://localhost:8080/", nil)
		require.NoError(t, err)

		// Valid format but missing required headers
		req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=test/20240915/us-east-1/s3/aws4_request, SignedHeaders=host, Signature=abc123")

		client := &http.Client{Timeout: 5 * time.Second}
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	})
}

func testSignatureValidation(t *testing.T) {
	t.Log("Testing AWS Signature V4 validation")

	// Note: This test assumes the current demo environment has authentication disabled
	// For a real test, we would need a test environment with specific credentials configured

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

		// The response depends on whether authentication is enabled in the test environment
		// We're mainly testing that the request is properly formatted
		t.Logf("Response status: %d", resp.StatusCode)
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

		// Should be rejected due to clock skew (if authentication is enabled)
		t.Logf("Response status for old timestamp: %d", resp.StatusCode)
	})
}

func testRateLimiting(t *testing.T) {
	t.Log("Testing rate limiting (if enabled)")

	// Note: Rate limiting tests would need to be configured specifically
	// This is a placeholder for demonstrating the test structure

	t.Run("RapidRequests", func(t *testing.T) {
		// Send multiple requests rapidly to test rate limiting
		const numRequests = 10
		const rapidInterval = 100 * time.Millisecond

		client := &http.Client{Timeout: 2 * time.Second}

		var responses []int
		for i := 0; i < numRequests; i++ {
			req, err := http.NewRequest("GET", "http://localhost:8080/health", nil)
			require.NoError(t, err)

			resp, err := client.Do(req)
			if err != nil {
				t.Logf("Request %d failed: %v", i, err)
				continue
			}
			responses = append(responses, resp.StatusCode)
			resp.Body.Close()

			time.Sleep(rapidInterval)
		}

		t.Logf("Rapid request responses: %v", responses)

		// Verify that health endpoint is accessible (rate limiting may not apply to health)
		healthRequests := 0
		for _, status := range responses {
			if status == http.StatusOK {
				healthRequests++
			}
		}

		// Health endpoint should remain accessible
		assert.Greater(t, healthRequests, 0, "Health endpoint should remain accessible")
	})
}

func TestSecurityMetrics(t *testing.T) {
	t.Log("Testing security metrics and monitoring")

	// This would test the security metrics functionality
	// For now, it's a placeholder demonstrating the test structure

	t.Run("MetricsCollection", func(t *testing.T) {
		// Test that security metrics are being collected
		// This would require access to the proxy's metrics endpoint

		resp, err := http.Get("http://localhost:9090/metrics")
		if err != nil {
			t.Skip("Metrics endpoint not available")
			return
		}
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		// Read metrics content
		buf := new(bytes.Buffer)
		buf.ReadFrom(resp.Body)
		metricsContent := buf.String()

		t.Logf("Metrics endpoint accessible, content length: %d", len(metricsContent))

		// In a real implementation, we would check for specific security metrics
		// such as failed authentication attempts, rate limiting events, etc.
	})
}

// Test helper functions

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
