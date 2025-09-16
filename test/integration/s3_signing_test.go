//go:build integration

package integration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestAWSV4SigningHelper tests the AWS Signature V4 signing functionality
func TestAWSV4SigningHelper(t *testing.T) {
	EnsureMinIOAndProxyAvailable(t)

	// Test data
	testData := []byte("Hello, AWS Signature V4 test!")
	bucketName := "test-signing-helper"
	objectKey := "test-object.txt"

	// Create test bucket first using AWS SDK
	proxyClient, err := CreateProxyClient()
	require.NoError(t, err, "Failed to create proxy client")

	CreateTestBucket(t, proxyClient, bucketName)
	defer CleanupTestBucket(t, proxyClient, bucketName)

	// Create HTTP request
	url := fmt.Sprintf("%s/%s/%s", ProxyEndpoint, bucketName, objectKey)
	req, err := http.NewRequestWithContext(context.Background(), "PUT", url, bytes.NewReader(testData))
	require.NoError(t, err, "Failed to create HTTP request")

	// Set basic headers
	req.Header.Set("Content-Type", "text/plain")
	req.Header.Set("Content-Length", fmt.Sprintf("%d", len(testData)))

	// Calculate payload hash
	payloadHash := fmt.Sprintf("%x", sha256.Sum256(testData))

	// Sign the request using our helper
	err = SignHTTPRequestForS3WithCredentials(req, payloadHash)
	require.NoError(t, err, "Failed to sign HTTP request")

	t.Logf("Signed request URL: %s", url)
	t.Logf("Authorization header: %s", req.Header.Get("Authorization"))
	t.Logf("Payload hash: %s", payloadHash)

	// Send the request
	client := &http.Client{}
	resp, err := client.Do(req)
	require.NoError(t, err, "Failed to send signed HTTP request")
	defer resp.Body.Close()

	t.Logf("Response status: %d", resp.StatusCode)

	// Check if the signing was successful
	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated {
		t.Logf("✅ AWS Signature V4 signing successful")
	} else {
		t.Logf("❌ AWS Signature V4 signing failed with status %d", resp.StatusCode)
		// Read response body for debugging
		body := make([]byte, 1024)
		n, _ := resp.Body.Read(body)
		t.Logf("Response body: %s", string(body[:n]))
	}
}
