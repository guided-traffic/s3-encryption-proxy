//go:build integration
// +build integration

package integration

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/guided-traffic/s3-encryption-proxy/internal/config"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy"
	. "github.com/guided-traffic/s3-encryption-proxy/test/integration"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ExitProxyTestInstance represents a test instance of the S3 encryption proxy
type ExitProxyTestInstance struct {
	server   *proxy.Server
	ctx      context.Context
	cancel   context.CancelFunc
	endpoint string
	client   *s3.Client
	// segmentSize is what this instance routes on: a PUT above it goes to the
	// multipart producer instead of a single request.
	segmentSize int64
}

// StartExitProviderProxyInstance starts a new proxy instance with exit-example.yaml config
func StartExitProviderProxyInstance(t *testing.T) *ExitProxyTestInstance {
	t.Helper()

	// Find available port
	listener, err := net.Listen("tcp", ":0")
	require.NoError(t, err, "Failed to find available port")
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()

	endpoint := fmt.Sprintf("http://localhost:%d", port)

	// Load exit-example.yaml config manually
	configPath := filepath.Join("..", "..", "..", "config", "exit-example.yaml")

	// Use viper to load the specific config file
	require.NoError(t, config.InitConfig(configPath), "Failed to read exit-example.yaml")
	cfg, err := config.Load()
	require.NoError(t, err, "Failed to load exit-example.yaml config")

	// Override bind address to use our available port
	cfg.BindAddress = fmt.Sprintf("0.0.0.0:%d", port)

	// Set log level to error to reduce noise during tests
	cfg.LogLevel = "error"

	// Override target endpoint to use localhost (should already be correct in exit-example.yaml)
	cfg.S3Backend.TargetEndpoint = "https://localhost:9000"

	// Create proxy server
	server, err := proxy.NewServer(cfg)
	require.NoError(t, err, "Failed to create proxy server")

	// Create context for the server
	ctx, cancel := context.WithCancel(context.Background())

	// Start server in background
	go func() {
		if err := server.Start(ctx); err != nil && err != context.Canceled {
			t.Logf("Proxy server failed: %v", err)
		}
	}()

	// Wait for server to be ready
	WaitForHealthCheck(t, endpoint)

	// Create S3 client for this proxy instance
	client, err := CreateProxyClientWithEndpoint(endpoint)
	require.NoError(t, err, "Failed to create proxy client")

	return &ExitProxyTestInstance{
		server:      server,
		ctx:         ctx,
		cancel:      cancel,
		endpoint:    endpoint,
		client:      client,
		segmentSize: cfg.GetStreamingSegmentSize(),
	}
}

// Stop stops the proxy test instance
func (p *ExitProxyTestInstance) Stop() {
	if p.cancel != nil {
		p.cancel()
	}
}

// IsExitProviderActive reports whether writes through this proxy instance land
// at the backend as the client sent them, which is what the exit provider does
// and no encrypting provider does.
func IsExitProviderActive(t *testing.T, proxyInstance *ExitProxyTestInstance) bool {
	t.Helper()

	// Create a test client
	proxyClient := proxyInstance.client

	// Try to upload a small test object
	ctx := context.Background()
	bucketName := "exit-provider-check"
	objectKey := "test-check.txt"
	testData := []byte("test")

	// Create test bucket
	minioClient, err := CreateMinIOClient()
	if err != nil {
		t.Logf("Failed to create MinIO client: %v", err)
		return false
	}

	CreateTestBucket(t, minioClient, bucketName)
	defer CleanupTestBucket(t, minioClient, bucketName)

	// Upload via proxy with custom metadata to test pass-through
	clientMetadata := map[string]string{
		"x-amz-meta-test": "passthrough-check",
	}

	_, err = proxyClient.PutObject(ctx, &s3.PutObjectInput{
		Bucket:   aws.String(bucketName),
		Key:      aws.String(objectKey),
		Body:     bytes.NewReader(testData),
		Metadata: clientMetadata,
	})
	if err != nil {
		t.Logf("Failed to upload test object via proxy: %v", err)
		return false
	}

	// Check if data is unencrypted in MinIO (exit provider should pass through)
	directResp, err := minioClient.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(objectKey),
	})
	if err != nil {
		t.Logf("Failed to get object from MinIO directly: %v", err)
		return false
	}

	directData, err := io.ReadAll(directResp.Body)
	if err != nil {
		directResp.Body.Close()
		t.Logf("Failed to read object data: %v", err)
		return false
	}
	directResp.Body.Close()

	// If data matches, exit provider is active
	return bytes.Equal(testData, directData)
}

// TestExitProviderWithMinIO tests the exit provider with real MinIO using a dedicated proxy instance
func TestExitProviderWithMinIO(t *testing.T) {
	// Set log level to reduce noise during tests
	logrus.SetLevel(logrus.ErrorLevel)

	// Skip if MinIO is not available
	EnsureMinIOAvailable(t)

	// Start our own proxy instance with exit-example.yaml config
	t.Log("Starting dedicated proxy instance with exit provider configuration...")
	proxyInstance := StartExitProviderProxyInstance(t)
	defer proxyInstance.Stop()

	// Verify that the exit provider is indeed active
	if !IsExitProviderActive(t, proxyInstance) {
		t.Fatal("Exit provider should be active but isn't - check the exit-example.yaml configuration")
	}

	// Create MinIO client
	minioClient, err := CreateMinIOClient()
	require.NoError(t, err, "MinIO client creation failed")

	// Use the proxy client from our instance
	proxyClient := proxyInstance.client

	bucketName := "exit-provider-test"
	objectKey := "test-object.txt"
	testData := []byte("Hello, World! This is test data for the exit provider.")

	// Setup: Create test bucket
	CreateTestBucket(t, minioClient, bucketName)
	defer CleanupTestBucket(t, minioClient, bucketName)

	ctx := context.Background()

	// Step 1: Upload via proxy (should pass through with exit provider)
	t.Log("Step 1: Uploading via S3 Encryption Proxy with exit provider...")
	_, err = proxyClient.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(objectKey),
		Body:   bytes.NewReader(testData),
		Metadata: map[string]string{
			"test-metadata": "exit-provider-test",
		},
	})
	require.NoError(t, err, "Failed to upload object via proxy")

	// Step 2: Verify direct MinIO access shows unencrypted data
	t.Log("Step 2: Verifying data is NOT encrypted in MinIO...")
	directResp, err := minioClient.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(objectKey),
	})
	require.NoError(t, err, "Failed to get object directly from MinIO")

	directData, err := io.ReadAll(directResp.Body)
	require.NoError(t, err, "Failed to read object data from MinIO")
	directResp.Body.Close()

	// With exit provider, data should be identical (not encrypted)
	assert.Equal(t, testData, directData, "Data should not be encrypted with exit provider")

	// Step 3: Download via proxy and verify it's the same
	t.Log("Step 3: Downloading via S3 Encryption Proxy...")
	proxyResp, err := proxyClient.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(objectKey),
	})
	require.NoError(t, err, "Failed to get object via proxy")

	proxyData, err := io.ReadAll(proxyResp.Body)
	require.NoError(t, err, "Failed to read object data via proxy")
	proxyResp.Body.Close()

	// Data should be identical when downloaded via proxy
	assert.Equal(t, testData, proxyData, "Downloaded data should match original")

	// Step 4: Verify metadata was preserved
	headResp, err := proxyClient.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(objectKey),
	})
	require.NoError(t, err, "Failed to get object metadata via proxy")

	assert.Contains(t, headResp.Metadata, "test-metadata", "Custom metadata should be preserved")
	assert.Equal(t, "exit-provider-test", headResp.Metadata["test-metadata"], "Metadata value should be preserved")

	t.Log("✅ Exit provider test completed successfully!")
}

// TestExitProviderMultipleObjects tests the exit provider with multiple objects using a dedicated proxy instance
func TestExitProviderMultipleObjects(t *testing.T) {
	// Set log level to reduce noise during tests
	logrus.SetLevel(logrus.ErrorLevel)

	// Skip if MinIO is not available
	EnsureMinIOAvailable(t)

	// Start our own proxy instance with exit-example.yaml config
	t.Log("Starting dedicated proxy instance with exit provider configuration...")
	proxyInstance := StartExitProviderProxyInstance(t)
	defer proxyInstance.Stop()

	// Verify that the exit provider is indeed active
	if !IsExitProviderActive(t, proxyInstance) {
		t.Fatal("Exit provider should be active but isn't - check the exit-example.yaml configuration")
	}

	// Create MinIO client
	minioClient, err := CreateMinIOClient()
	require.NoError(t, err, "MinIO client creation failed")

	// Use the proxy client from our instance
	proxyClient := proxyInstance.client

	bucketName := "exit-provider-multi-test"

	// Setup: Create test bucket
	CreateTestBucket(t, minioClient, bucketName)
	defer CleanupTestBucket(t, minioClient, bucketName)

	ctx := context.Background()

	// Test data for multiple objects
	testObjects := map[string][]byte{
		"object1.txt": []byte("This is test object number 1"),
		"object2.txt": []byte("This is test object number 2 with different content"),
		"object3.txt": []byte("Third object with even more different content for testing"),
	}

	// Step 1: Upload multiple objects via proxy
	t.Log("Step 1: Uploading multiple objects via proxy...")
	for key, data := range testObjects {
		_, err = proxyClient.PutObject(ctx, &s3.PutObjectInput{
			Bucket: aws.String(bucketName),
			Key:    aws.String(key),
			Body:   bytes.NewReader(data),
			Metadata: map[string]string{
				"object-number": key,
				"test-type":     "multiple-objects",
			},
		})
		require.NoError(t, err, "Failed to upload object %s via proxy", key)
	}

	// Step 2: Verify all objects are unencrypted in MinIO
	t.Log("Step 2: Verifying all objects are NOT encrypted in MinIO...")
	for key, originalData := range testObjects {
		directResp, err := minioClient.GetObject(ctx, &s3.GetObjectInput{
			Bucket: aws.String(bucketName),
			Key:    aws.String(key),
		})
		require.NoError(t, err, "Failed to get object %s directly from MinIO", key)

		directData, err := io.ReadAll(directResp.Body)
		require.NoError(t, err, "Failed to read object %s data from MinIO", key)
		directResp.Body.Close()

		// With exit provider, data should be identical (not encrypted)
		assert.Equal(t, originalData, directData, "Object %s should not be encrypted with exit provider", key)
	}

	// Step 3: Verify all objects can be downloaded via proxy
	t.Log("Step 3: Downloading all objects via proxy...")
	for key, originalData := range testObjects {
		proxyResp, err := proxyClient.GetObject(ctx, &s3.GetObjectInput{
			Bucket: aws.String(bucketName),
			Key:    aws.String(key),
		})
		require.NoError(t, err, "Failed to get object %s via proxy", key)

		proxyData, err := io.ReadAll(proxyResp.Body)
		require.NoError(t, err, "Failed to read object %s data via proxy", key)
		proxyResp.Body.Close()

		// Data should be identical when downloaded via proxy
		assert.Equal(t, originalData, proxyData, "Object %s downloaded data should match original", key)

		// Verify metadata was preserved
		assert.Contains(t, proxyResp.Metadata, "object-number", "Object %s should have preserved metadata", key)
		assert.Equal(t, key, proxyResp.Metadata["object-number"], "Object %s metadata should match", key)
	}

	t.Log("✅ Multiple objects exit provider test completed successfully!")
}

// exitTestConfig builds a complete, loadable configuration around one provider
// block. Everything outside `encryption` is the minimum the loader insists on.
func exitTestConfig(activeAlias, providers string) string {
	return fmt.Sprintf(`---
bind_address: "127.0.0.1:0"
s3_backend:
  target_endpoint: %q
  region: "us-east-1"
  access_key_id: %q
  secret_key: %q
  insecure_skip_verify: true
s3_clients:
  - type: "static"
    access_key_id: %q
    secret_key: %q
    description: "config validation"
encryption:
  encryption_method_alias: %q
  providers:
%s`, MinIOEndpoint, MinIOAccessKey, MinIOSecretKey, ProxyTestAccessKey, ProxyTestSecretKey, activeAlias, providers)
}

// loadTestConfig runs a configuration through the real loader. Provider types
// and the licence gate are checked there and nowhere else - GetActiveProvider
// only looks up an alias, so a test that calls it proves nothing about which
// types the product admits.
func loadTestConfig(t *testing.T, yaml string) error {
	t.Helper()

	path := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte(yaml), 0o600))

	if err := config.InitConfig(path); err != nil {
		return err
	}
	_, err := config.Load()
	return err
}

// TestConfigValidationWithExitProvider covers the shape of an exit
// configuration: which of them the loader accepts and which it refuses.
func TestConfigValidationWithExitProvider(t *testing.T) {
	logrus.SetLevel(logrus.ErrorLevel)

	const exitOnly = `    - alias: "exit-test"
      type: "exit"
      description: "Test exit provider"
`
	// What the exit provider is for: it is active, and the key that wrapped the
	// objects already in the bucket stays registered next to it.
	const exitWithPreviousKey = exitOnly + `    - alias: "aes-previous"
      type: "aes"
      config:
        aes_key: "ZEsubBlmU+Pr61y+JOwO09c0LOrHs5LITaO0D4JzSZE="
`

	tests := []struct {
		name        string
		yaml        string
		expectError string
	}{
		{
			name: "exit provider alone",
			yaml: exitTestConfig("exit-test", exitOnly),
		},
		{
			name: "exit provider with the previous key registered alongside",
			yaml: exitTestConfig("exit-test", exitWithPreviousKey),
		},
		{
			name:        "missing encryption method alias",
			yaml:        exitTestConfig("", exitOnly),
			expectError: "encryption_method_alias is required",
		},
		{
			name:        "active alias names no provider",
			yaml:        exitTestConfig("not-configured", exitOnly),
			expectError: "does not match any provider alias",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			err := loadTestConfig(t, tt.yaml)
			if tt.expectError == "" {
				require.NoError(t, err, "this configuration must load")
				return
			}
			require.Error(t, err, "this configuration must be refused")
			assert.Contains(t, err.Error(), tt.expectError)
		})
	}
}

// TestProviderTypesSupported pins the provider types the loader admits.
// "none" is refused by name rather than by falling into the unknown-type arm:
// an operator who wrote it before the rename has to be told that the successor
// still decrypts, and that the provider holding the old key has to stay
// configured next to it.
//
// The licence is cleared so the outcomes do not depend on one being present.
// The type check runs before the licence gate, so for `aes` reaching that gate
// is what proves the type is admitted.
func TestProviderTypesSupported(t *testing.T) {
	logrus.SetLevel(logrus.ErrorLevel)

	for _, name := range []string{"S3EP_LICENSE", "S3EP_LICENSE_TOKEN", "S3_ENCRYPTION_PROXY_LICENSE"} {
		t.Setenv(name, "")
	}

	tests := []struct {
		name        string
		provider    string
		expectError string
		// forbidError is what the refusal must not say - the wording a row pins
		// negatively, where the positive wording is not decided.
		forbidError []string
	}{
		{
			name: "exit",
			provider: `    - alias: "test-provider"
      type: "exit"
`,
		},
		{
			name: "aes reaches the licence gate, so its type is admitted",
			provider: `    - alias: "test-provider"
      type: "aes"
      config:
        aes_key: "ZEsubBlmU+Pr61y+JOwO09c0LOrHs5LITaO0D4JzSZE="
`,
			expectError: "license required for encryption provider type 'aes'",
		},
		{
			name: "none is refused by name and pointed at exit",
			provider: `    - alias: "test-provider"
      type: "none"
`,
			expectError: "'none' is now 'exit'",
		},
		{
			// ADR 0005 keeps the by-name refusal of the removed `tink` type but
			// lists its wording as a residual risk: it must name the type and
			// promise nothing - D4 replaced tink with Vault Transit, and open
			// question 1 leaves that provider's name undecided. The replacement
			// wording itself is still the owner's decision.
			name: "tink is refused by name, and the refusal promises nothing",
			provider: `    - alias: "test-provider"
      type: "tink"
`,
			expectError: "tink",
			forbidError: []string{"not yet implemented", "unsupported encryption type"},
		},
		{
			name: "unsupported",
			provider: `    - alias: "test-provider"
      type: "unsupported"
`,
			expectError: "unsupported encryption type",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			err := loadTestConfig(t, exitTestConfig("test-provider", tt.provider))
			if tt.expectError == "" {
				require.NoError(t, err, "type %s must be admitted", tt.name)
				return
			}
			require.Error(t, err, "type %s must be refused", tt.name)
			assert.Contains(t, err.Error(), tt.expectError)
			for _, forbidden := range tt.forbidError {
				assert.NotContains(t, err.Error(), forbidden, "type %s: refusal must not say this", tt.name)
			}
		})
	}
}

// TestExitProvider_NeedsNoLicense is the property that makes the exit provider
// an exit: the licence gate looks at the active provider only, so a proxy whose
// active alias is the exit provider starts with no licence at all, while the
// aes provider registered next to it - the one that unwraps what is already in
// the bucket - does not make the start conditional on one.
//
// The three environment variables the validator reads are cleared for this
// test; a licence file at one of its absolute fallback paths (/etc/s3ep,
// /opt/s3ep, /app) would still be found and would make the negative case fail.
func TestExitProvider_NeedsNoLicense(t *testing.T) {
	logrus.SetLevel(logrus.ErrorLevel)

	for _, name := range []string{"S3EP_LICENSE", "S3EP_LICENSE_TOKEN", "S3_ENCRYPTION_PROXY_LICENSE"} {
		t.Setenv(name, "")
	}

	const bothProviders = `    - alias: "exit-test"
      type: "exit"
    - alias: "aes-previous"
      type: "aes"
      config:
        aes_key: "ZEsubBlmU+Pr61y+JOwO09c0LOrHs5LITaO0D4JzSZE="
`

	t.Run("exit active", func(t *testing.T) {
		require.NoError(t, loadTestConfig(t, exitTestConfig("exit-test", bothProviders)),
			"the exit provider must start without a licence")
	})

	t.Run("aes active", func(t *testing.T) {
		err := loadTestConfig(t, exitTestConfig("aes-previous", bothProviders))
		require.Error(t, err, "an encrypting provider must not start without a licence")
		assert.Contains(t, err.Error(), "license required")
	})
}

// TestExitProvider_PurePassthrough verifies that a write through the exit
// provider is a pure pass-through: the object is stored as the client sent it,
// with the client metadata intact and no s3ep-* key added. In a bucket that
// holds no object this proxy encrypted, that is the whole of its behaviour.
func TestExitProvider_PurePassthrough(t *testing.T) {
	// Set log level to reduce noise during tests
	logrus.SetLevel(logrus.ErrorLevel)

	// Skip if MinIO is not available
	EnsureMinIOAvailable(t)

	// Start our own proxy instance with exit-example.yaml config
	t.Log("Starting dedicated proxy instance with exit provider configuration...")
	proxyInstance := StartExitProviderProxyInstance(t)
	defer proxyInstance.Stop()

	// Verify that the exit provider is indeed active
	if !IsExitProviderActive(t, proxyInstance) {
		t.Fatal("Exit provider should be active but isn't - check the exit-example.yaml configuration")
	}

	// Create MinIO client
	minioClient, err := CreateMinIOClient()
	require.NoError(t, err, "MinIO client creation failed")

	// Use the proxy client from our instance
	proxyClient := proxyInstance.client

	bucketName := "exit-passthrough-test"
	objectKey := "passthrough-object.txt"
	testData := []byte("This is test data for pure pass-through verification!")

	// Client metadata to verify pass-through
	clientMetadata := map[string]string{
		"x-amz-meta-custom-key":    "custom-value",
		"x-amz-meta-application":   "test-app",
		"x-amz-meta-version":       "1.0.0",
		"x-amz-meta-special-chars": "special!@#$%^&*()",
	}

	// Setup: Create test bucket
	CreateTestBucket(t, minioClient, bucketName)
	defer CleanupTestBucket(t, minioClient, bucketName)

	ctx := context.Background()

	// Step 1: Upload via proxy with client metadata
	t.Log("Step 1: Uploading via proxy with client metadata...")
	_, err = proxyClient.PutObject(ctx, &s3.PutObjectInput{
		Bucket:   aws.String(bucketName),
		Key:      aws.String(objectKey),
		Body:     bytes.NewReader(testData),
		Metadata: clientMetadata,
	})
	require.NoError(t, err, "Failed to upload object via proxy")

	// Step 2: Verify NO S3EP metadata exists in MinIO
	t.Log("Step 2: Verifying NO S3EP metadata exists in MinIO...")
	headResult, err := minioClient.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(objectKey),
	})
	require.NoError(t, err, "Failed to head object in MinIO")

	// Check that NO S3EP metadata exists
	for key := range headResult.Metadata {
		if strings.HasPrefix(key, "s3ep-") {
			t.Errorf("Found S3EP metadata in MinIO that should not exist with exit provider: %s=%s",
				key, headResult.Metadata[key])
		}
	}

	// Step 3: Verify all client metadata is preserved exactly
	t.Log("Step 3: Verifying all client metadata is preserved...")
	for expectedKey, expectedValue := range clientMetadata {
		actualValue, exists := headResult.Metadata[expectedKey]
		assert.True(t, exists, "Client metadata key %s should exist in MinIO", expectedKey)
		assert.Equal(t, expectedValue, actualValue, "Client metadata value mismatch for key %s", expectedKey)
	}

	// Step 4: Verify data is completely unencrypted in MinIO
	t.Log("Step 4: Verifying data is unencrypted in MinIO...")
	directResp, err := minioClient.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(objectKey),
	})
	require.NoError(t, err, "Failed to get object directly from MinIO")

	directData, err := io.ReadAll(directResp.Body)
	require.NoError(t, err, "Failed to read object data from MinIO")
	directResp.Body.Close()

	assert.Equal(t, testData, directData, "Data in MinIO should be identical to original (not encrypted)")

	// Step 5: Verify proxy returns same data and metadata
	t.Log("Step 5: Verifying proxy returns identical data and metadata...")
	proxyResp, err := proxyClient.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(objectKey),
	})
	require.NoError(t, err, "Failed to get object via proxy")

	proxyData, err := io.ReadAll(proxyResp.Body)
	require.NoError(t, err, "Failed to read object data via proxy")
	proxyResp.Body.Close()

	assert.Equal(t, testData, proxyData, "Data via proxy should match original")

	// Verify proxy returns client metadata
	for expectedKey, expectedValue := range clientMetadata {
		actualValue, exists := proxyResp.Metadata[expectedKey]
		assert.True(t, exists, "Client metadata key %s should be returned by proxy", expectedKey)
		assert.Equal(t, expectedValue, actualValue, "Client metadata via proxy should match for key %s", expectedKey)
	}

	t.Log("✅ Pure pass-through test completed successfully!")
}

// TestUnauthenticatedEndpoints: /health and /version answer ahead of the
// authentication middleware, which is what lets a load balancer probe the proxy
// without a credential (ADR 0014 D11). This ran as a table that skipped its only
// case and therefore asserted nothing; it now talks to the running proxy.
func TestUnauthenticatedEndpoints(t *testing.T) {
	EnsureMinIOAndProxyAvailable(t)
	logrus.SetLevel(logrus.ErrorLevel)

	for _, path := range []string{"/health", "/version"} {
		path := path
		t.Run(path, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, ProxyEndpoint+path, nil)
			require.NoError(t, err)

			resp, err := TLSHTTPClient().Do(req)
			require.NoErrorf(t, err, "GET %s", path)
			defer resp.Body.Close()

			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)

			assert.Equalf(t, http.StatusOK, resp.StatusCode,
				"%s must answer without a credential: %s", path, string(body))
			assert.NotEmptyf(t, body, "%s answered an empty body", path)
		})
	}
}
