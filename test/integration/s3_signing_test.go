//go:build integration

package integration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
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
	// Trusts the local test CA, so this works against both the HTTP and the
	// HTTPS proxy endpoint.
	client := TLSHTTPClient()
	resp, err := client.Do(req)
	require.NoError(t, err, "Failed to send signed HTTP request")
	defer resp.Body.Close()

	// The helper's whole job is to produce a signature the proxy accepts, so a
	// refusal is the result this test exists to catch. Reporting the status
	// through t.Logf passed on every status the proxy could answer with,
	// including the 403 that means the helper signs nothing the proxy accepts -
	// and every other test in the tree signs its requests with this helper.
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err, "Failed to read response body")
	require.Equalf(t, http.StatusOK, resp.StatusCode,
		"a request signed by the helper must be accepted, got: %s", string(body))
}
