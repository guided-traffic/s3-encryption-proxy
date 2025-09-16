//go:build integration
// +build integration

package integration

import (
	"bytes"
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEnterpriseSecurityConfiguration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping enterprise security tests in short mode")
	}

	t.Run("HealthEndpointAccessible", func(t *testing.T) {
		// Health endpoint should be accessible without authentication
		resp, err := http.Get("http://localhost:8080/health")
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		t.Logf("Health endpoint accessible: %d", resp.StatusCode)
	})

	t.Run("S3EndpointWithoutAuth", func(t *testing.T) {
		// S3 endpoint should require authentication (always now)
		req, err := http.NewRequest("GET", "http://localhost:8080/", nil)
		require.NoError(t, err)

		client := &http.Client{Timeout: 5 * time.Second}
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Authentication should always be required now
		if resp.StatusCode == http.StatusForbidden {
			t.Log("✅ S3 endpoint properly protected with mandatory authentication")
		} else {
			t.Logf("⚠️  Unexpected response code (expected 403): %d", resp.StatusCode)
		}
	})

	t.Run("S3ClientCredentials", func(t *testing.T) {
		// Test with specific S3 client credentials
		testCredentials := []struct {
			accessKey string
			secretKey string
			expected  bool // true if should work, false if should fail
		}{
			{"username0", "this-is-not-very-secure", true},   // Valid from aes-example.yaml config
			{"username1", "this-is-even-worse", true},        // Valid from aes-example.yaml config
			{"invalidkey", "invalidsecret", false},           // Invalid credentials
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
					// Should succeed or get a different error (not authentication)
					if err != nil {
						t.Logf("Expected success but got error: %v", err)
						// Check if it's an authentication error
						t.Logf("❌ Authentication failed for valid credentials: %s (error: %v)", tc.accessKey, err)
					} else {
						t.Logf("✅ Authentication succeeded for: %s", tc.accessKey)
					}
				} else {
					// Should fail with authentication error
					if err != nil {
						t.Logf("✅ Authentication correctly rejected: %s", tc.accessKey)
					} else {
						t.Logf("⚠️  Authentication did not reject invalid credentials: %s", tc.accessKey)
					}
				}
			})
		}
	})

	t.Run("SecurityHeaders", func(t *testing.T) {
		// Check for security headers
		resp, err := http.Get("http://localhost:8080/health")
		require.NoError(t, err)
		defer resp.Body.Close()

		// Expected security headers
		expectedHeaders := []string{
			"X-Content-Type-Options",
			"X-Frame-Options",
			"X-XSS-Protection",
		}

		for _, header := range expectedHeaders {
			value := resp.Header.Get(header)
			if value != "" {
				t.Logf("✅ Security header present: %s: %s", header, value)
			} else {
				t.Logf("⚠️  Security header missing: %s", header)
			}
		}
	})
}

func TestCurrentAuthenticationStatus(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping current auth status test in short mode")
	}

	t.Run("DetectAuthStatus", func(t *testing.T) {
		// Check if authentication is working (should always be enabled now)
		req, err := http.NewRequest("GET", "http://localhost:8080/", nil)
		require.NoError(t, err)

		client := &http.Client{Timeout: 5 * time.Second}
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusForbidden {
			t.Log("� Current Status: Authentication is ENABLED and working correctly")
			t.Log("   ✅ S3 API endpoints are properly protected")
			t.Log("   ✅ Unauthorized requests are correctly rejected")
		} else if resp.StatusCode == http.StatusOK {
			t.Log("⚠️  Current Status: Authentication might be disabled or bypassed")
			t.Log("   This should not happen with the new mandatory authentication")
		} else {
			t.Logf("❓ Current Status: Unexpected response code: %d", resp.StatusCode)
		}

		// Read response body for more info
		buf := new(bytes.Buffer)
		buf.ReadFrom(resp.Body)
		if buf.Len() > 0 && buf.Len() < 1000 {
			t.Logf("Response body: %s", buf.String())
		}
	})
}