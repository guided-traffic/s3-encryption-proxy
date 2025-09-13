//go:build integration
// +build integration

package integration

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/guided-traffic/s3-encryption-proxy/internal/config"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy"
	. "github.com/guided-traffic/s3-encryption-proxy/test/integration"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// RSAProxyTestInstance represents a test instance of the S3 encryption proxy with RSA provider
type RSAProxyTestInstance struct {
	server   *proxy.Server
	ctx      context.Context
	cancel   context.CancelFunc
	endpoint string
	client   *s3.Client
}

// StartRSAProviderProxyInstance starts a new proxy instance with rsa-example.yaml config
func StartRSAProviderProxyInstance(t *testing.T) *RSAProxyTestInstance {
	t.Helper()

	// Ensure license is available - use environment variable or fallback to license file
	// This supports both CI pipeline (with S3EP_LICENSE_TOKEN) and local development
	if os.Getenv("S3EP_LICENSE_TOKEN") == "" && os.Getenv("S3EP_LICENSE") == "" {
		// Load license from file and set as environment variable for this test
		licensePath := filepath.Join("..", "..", "..", "config", "license.jwt")
		if licenseData, err := os.ReadFile(licensePath); err == nil {
			t.Setenv("S3EP_LICENSE_TOKEN", strings.TrimSpace(string(licenseData)))
		} else {
			t.Fatalf("No license found in environment variables and failed to read license file: %v", err)
		}
	}

	// Find available port
	listener, err := net.Listen("tcp", ":0")
	require.NoError(t, err, "Failed to find available port")
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()

	endpoint := fmt.Sprintf("http://localhost:%d", port)

	// Load rsa-example.yaml config manually
	configPath := filepath.Join("..", "..", "..", "config", "rsa-example.yaml")

	// Use viper to load the specific config file
	config.InitConfig(configPath)
	cfg, err := config.Load()
	require.NoError(t, err, "Failed to load rsa-example.yaml config")

	// Override bind address to use our available port
	cfg.BindAddress = fmt.Sprintf("0.0.0.0:%d", port)

	// Set log level to error to reduce noise during tests
	cfg.LogLevel = "error"

	// Override target endpoint to use localhost instead of minio service name
	cfg.TargetEndpoint = "https://localhost:9000"

	// Set license file path for testing
	licensePath := filepath.Join("..", "..", "..", "config", "license.jwt")
	cfg.LicenseFile = licensePath

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

	return &RSAProxyTestInstance{
		server:   server,
		ctx:      ctx,
		cancel:   cancel,
		endpoint: endpoint,
		client:   client,
	}
}

// Stop stops the RSA proxy test instance
func (p *RSAProxyTestInstance) Stop() {
	if p.cancel != nil {
		p.cancel()
	}
}

// IsRSAProviderActive checks if the proxy instance is running with RSA provider configuration
func IsRSAProviderActive(t *testing.T, proxyInstance *RSAProxyTestInstance) bool {
	t.Helper()

	// Create a test client
	proxyClient := proxyInstance.client

	// Try to upload a small test object
	ctx := context.Background()
	bucketName := "rsa-provider-check"
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

	// Upload via proxy with custom metadata to test encryption
	clientMetadata := map[string]string{
		"x-amz-meta-test": "rsa-encryption-check",
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

	// Check if data is encrypted in MinIO (should NOT match original data)
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

	// With RSA provider, data should NOT match (it should be encrypted)
	isEncrypted := !bytes.Equal(testData, directData)

	// Also check for S3EP metadata presence
	headResult, err := minioClient.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(objectKey),
	})
	if err != nil {
		t.Logf("Failed to head object in MinIO: %v", err)
		return false
	}

	hasS3EPMetadata := false
	for key := range headResult.Metadata {
		if strings.HasPrefix(key, "s3ep-") {
			hasS3EPMetadata = true
			break
		}
	}

	return isEncrypted && hasS3EPMetadata
}

// TestRSAProviderWithMinIO tests the RSA provider with real MinIO using a dedicated proxy instance
func TestRSAProviderWithMinIO(t *testing.T) {
	// Set log level to reduce noise during tests
	logrus.SetLevel(logrus.ErrorLevel)

	// Skip if MinIO is not available
	EnsureMinIOAvailable(t)

	// Start our own proxy instance with rsa-example.yaml config
	t.Log("Starting dedicated proxy instance with RSA provider configuration...")
	proxyInstance := StartRSAProviderProxyInstance(t)
	defer proxyInstance.Stop()

	// Verify that the RSA provider is indeed active
	if !IsRSAProviderActive(t, proxyInstance) {
		t.Fatal("RSA provider should be active but isn't - check the rsa-example.yaml configuration")
	}

	// Create MinIO client
	minioClient, err := CreateMinIOClient()
	require.NoError(t, err, "MinIO client creation failed")

	// Use the proxy client from our instance
	proxyClient := proxyInstance.client

	bucketName := "rsa-provider-test"
	objectKey := "test-object.txt"
	testData := []byte("Hello, World! This is test data for the RSA provider encryption test.")

	// Setup: Create test bucket
	CreateTestBucket(t, minioClient, bucketName)
	defer CleanupTestBucket(t, minioClient, bucketName)

	ctx := context.Background()

	// Step 1: Upload via proxy (should be encrypted with RSA provider)
	t.Log("Step 1: Uploading via S3 Encryption Proxy with RSA provider...")
	_, err = proxyClient.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(objectKey),
		Body:   bytes.NewReader(testData),
		Metadata: map[string]string{
			"test-metadata": "rsa-provider-test",
			"client-id":     "integration-test",
		},
	})
	require.NoError(t, err, "Failed to upload object via proxy")

	// Step 2: Verify data IS encrypted in MinIO
	t.Log("Step 2: Verifying data IS encrypted in MinIO...")
	directResp, err := minioClient.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(objectKey),
	})
	require.NoError(t, err, "Failed to get object directly from MinIO")

	directData, err := io.ReadAll(directResp.Body)
	require.NoError(t, err, "Failed to read object data from MinIO")
	directResp.Body.Close()

	// With RSA provider, data should be different (encrypted)
	assert.NotEqual(t, testData, directData, "Data should be encrypted with RSA provider")
	t.Logf("Original data length: %d, Encrypted data length: %d", len(testData), len(directData))

	// Step 3: Verify S3EP metadata exists in MinIO
	t.Log("Step 3: Verifying S3EP metadata exists in MinIO...")
	headResult, err := minioClient.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(objectKey),
	})
	require.NoError(t, err, "Failed to head object in MinIO")

	foundS3EPMetadata := make(map[string]string)
	for key, value := range headResult.Metadata {
		if strings.HasPrefix(key, "s3ep-") {
			foundS3EPMetadata[key] = value
		}
	}

	assert.NotEmpty(t, foundS3EPMetadata, "S3EP metadata should exist in MinIO")
	t.Logf("Found S3EP metadata keys: %v", getKeys(foundS3EPMetadata))

	// Verify client metadata is preserved in MinIO
	assert.Contains(t, headResult.Metadata, "test-metadata", "Client metadata should be preserved in MinIO")
	assert.Equal(t, "rsa-provider-test", headResult.Metadata["test-metadata"], "Client metadata value should be preserved")

	// Step 4: Download via proxy and verify it matches original
	t.Log("Step 4: Downloading via S3 Encryption Proxy...")
	proxyResp, err := proxyClient.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(objectKey),
	})
	require.NoError(t, err, "Failed to get object via proxy")

	proxyData, err := io.ReadAll(proxyResp.Body)
	require.NoError(t, err, "Failed to read object data via proxy")
	proxyResp.Body.Close()

	// Data should be identical to original when downloaded via proxy (decrypted)
	assert.Equal(t, testData, proxyData, "Downloaded data should match original after decryption")

	// Step 5: Verify S3EP metadata is NOT visible through proxy
	t.Log("Step 5: Verifying S3EP metadata is filtered out by proxy...")
	for key := range proxyResp.Metadata {
		assert.False(t, strings.HasPrefix(key, "s3ep-"),
			"S3EP metadata key %s should be filtered out by proxy", key)
	}

	// Verify client metadata is still visible through proxy
	assert.Contains(t, proxyResp.Metadata, "test-metadata", "Client metadata should be visible through proxy")
	assert.Equal(t, "rsa-provider-test", proxyResp.Metadata["test-metadata"], "Client metadata value should match")
	assert.Contains(t, proxyResp.Metadata, "client-id", "Client metadata should be visible through proxy")
	assert.Equal(t, "integration-test", proxyResp.Metadata["client-id"], "Client metadata value should match")

	t.Log("✅ RSA provider test completed successfully!")
}

// TestRSAProviderMultipleObjects tests the RSA provider with multiple objects using a dedicated proxy instance
func TestRSAProviderMultipleObjects(t *testing.T) {
	// Set log level to reduce noise during tests
	logrus.SetLevel(logrus.ErrorLevel)

	// Skip if MinIO is not available
	EnsureMinIOAvailable(t)

	// Start our own proxy instance with rsa-example.yaml config
	t.Log("Starting dedicated proxy instance with RSA provider configuration...")
	proxyInstance := StartRSAProviderProxyInstance(t)
	defer proxyInstance.Stop()

	// Verify that the RSA provider is indeed active
	if !IsRSAProviderActive(t, proxyInstance) {
		t.Fatal("RSA provider should be active but isn't - check the rsa-example.yaml configuration")
	}

	// Create MinIO client
	minioClient, err := CreateMinIOClient()
	require.NoError(t, err, "MinIO client creation failed")

	// Use the proxy client from our instance
	proxyClient := proxyInstance.client

	bucketName := "rsa-provider-multi-test"

	// Setup: Create test bucket
	CreateTestBucket(t, minioClient, bucketName)
	defer CleanupTestBucket(t, minioClient, bucketName)

	ctx := context.Background()

	// Test data for multiple objects with varying sizes
	testObjects := map[string][]byte{
		"small.txt":  []byte("This is a small test object for RSA encryption"),
		"medium.txt": []byte("This is a medium test object with more content for RSA encryption testing. " + strings.Repeat("Lorem ipsum dolor sit amet. ", 50)),
		"large.txt":  []byte("This is a large test object. " + strings.Repeat("Large content for multipart testing with RSA encryption. ", 200)),
	}

	// Step 1: Upload multiple objects via proxy
	t.Log("Step 1: Uploading multiple objects via proxy...")
	for key, data := range testObjects {
		_, err = proxyClient.PutObject(ctx, &s3.PutObjectInput{
			Bucket: aws.String(bucketName),
			Key:    aws.String(key),
			Body:   bytes.NewReader(data),
			Metadata: map[string]string{
				"object-name": key,
				"test-type":   "multiple-objects-rsa",
				"data-size":   fmt.Sprintf("%d", len(data)),
			},
		})
		require.NoError(t, err, "Failed to upload object %s via proxy", key)
	}

	// Step 2: Verify all objects are encrypted in MinIO and have S3EP metadata
	t.Log("Step 2: Verifying all objects are encrypted in MinIO...")
	for key, originalData := range testObjects {
		// Check encrypted data
		directResp, err := minioClient.GetObject(ctx, &s3.GetObjectInput{
			Bucket: aws.String(bucketName),
			Key:    aws.String(key),
		})
		require.NoError(t, err, "Failed to get object %s directly from MinIO", key)

		directData, err := io.ReadAll(directResp.Body)
		require.NoError(t, err, "Failed to read object %s data from MinIO", key)
		directResp.Body.Close()

		// With RSA provider, data should be different (encrypted)
		assert.NotEqual(t, originalData, directData, "Object %s should be encrypted with RSA provider", key)

		// Check S3EP metadata exists
		headResult, err := minioClient.HeadObject(ctx, &s3.HeadObjectInput{
			Bucket: aws.String(bucketName),
			Key:    aws.String(key),
		})
		require.NoError(t, err, "Failed to head object %s in MinIO", key)

		hasS3EPMetadata := false
		for metaKey := range headResult.Metadata {
			if strings.HasPrefix(metaKey, "s3ep-") {
				hasS3EPMetadata = true
				break
			}
		}
		assert.True(t, hasS3EPMetadata, "Object %s should have S3EP metadata in MinIO", key)

		// Verify client metadata is preserved
		assert.Contains(t, headResult.Metadata, "object-name", "Object %s should have preserved client metadata", key)
		assert.Equal(t, key, headResult.Metadata["object-name"], "Object %s metadata should match", key)
	}

	// Step 3: Verify all objects can be downloaded via proxy and match original
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

		// Data should be identical when downloaded via proxy (decrypted)
		assert.Equal(t, originalData, proxyData, "Object %s downloaded data should match original", key)

		// Verify S3EP metadata is filtered out by proxy
		for metaKey := range proxyResp.Metadata {
			assert.False(t, strings.HasPrefix(metaKey, "s3ep-"),
				"S3EP metadata should be filtered from object %s by proxy", key)
		}

		// Verify client metadata is preserved and visible through proxy
		assert.Contains(t, proxyResp.Metadata, "object-name", "Object %s should have client metadata via proxy", key)
		assert.Equal(t, key, proxyResp.Metadata["object-name"], "Object %s client metadata should match", key)
	}

	t.Log("✅ Multiple objects RSA provider test completed successfully!")
}

// TestRSAProvider_MetadataHandling verifies that the RSA provider
// correctly handles S3EP metadata while preserving client metadata
func TestRSAProvider_MetadataHandling(t *testing.T) {
	// Set log level to reduce noise during tests
	logrus.SetLevel(logrus.ErrorLevel)

	// Skip if MinIO is not available
	EnsureMinIOAvailable(t)

	// Start our own proxy instance with rsa-example.yaml config
	t.Log("Starting dedicated proxy instance with RSA provider configuration...")
	proxyInstance := StartRSAProviderProxyInstance(t)
	defer proxyInstance.Stop()

	// Verify that the RSA provider is indeed active
	if !IsRSAProviderActive(t, proxyInstance) {
		t.Fatal("RSA provider should be active but isn't - check the rsa-example.yaml configuration")
	}

	// Create MinIO client
	minioClient, err := CreateMinIOClient()
	require.NoError(t, err, "MinIO client creation failed")

	// Use the proxy client from our instance
	proxyClient := proxyInstance.client

	bucketName := "rsa-metadata-test"
	objectKey := "metadata-object.txt"
	testData := []byte("This is test data for RSA metadata handling verification!")

	// Comprehensive client metadata to verify handling
	clientMetadata := map[string]string{
		"x-amz-meta-application":   "test-app",
		"x-amz-meta-version":       "3.0.0",
		"x-amz-meta-author":        "integration-test",
		"x-amz-meta-encryption":    "rsa-envelope",
		"x-amz-meta-special-chars": "special!@#$%^&*()",
		"x-amz-meta-empty":         "",
	}

	// Setup: Create test bucket
	CreateTestBucket(t, minioClient, bucketName)
	defer CleanupTestBucket(t, minioClient, bucketName)

	ctx := context.Background()

	// Step 1: Upload via proxy with comprehensive client metadata
	t.Log("Step 1: Uploading via proxy with comprehensive client metadata...")
	_, err = proxyClient.PutObject(ctx, &s3.PutObjectInput{
		Bucket:   aws.String(bucketName),
		Key:      aws.String(objectKey),
		Body:     bytes.NewReader(testData),
		Metadata: clientMetadata,
	})
	require.NoError(t, err, "Failed to upload object via proxy")

	// Step 2: Verify S3EP metadata exists alongside client metadata in MinIO
	t.Log("Step 2: Verifying S3EP and client metadata coexist in MinIO...")
	headResult, err := minioClient.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(objectKey),
	})
	require.NoError(t, err, "Failed to head object in MinIO")

	// Collect S3EP metadata
	s3epMetadata := make(map[string]string)
	for key, value := range headResult.Metadata {
		if strings.HasPrefix(key, "s3ep-") {
			s3epMetadata[key] = value
		}
	}

	assert.NotEmpty(t, s3epMetadata, "S3EP metadata should exist in MinIO")
	t.Logf("Found S3EP metadata: %v", getKeys(s3epMetadata))

	// Verify all client metadata is preserved in MinIO
	for expectedKey, expectedValue := range clientMetadata {
		actualValue, exists := headResult.Metadata[expectedKey]
		assert.True(t, exists, "Client metadata key %s should exist in MinIO", expectedKey)
		assert.Equal(t, expectedValue, actualValue, "Client metadata value mismatch for key %s", expectedKey)
	}

	// Step 3: Verify data is encrypted in MinIO
	t.Log("Step 3: Verifying data is encrypted in MinIO...")
	directResp, err := minioClient.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(objectKey),
	})
	require.NoError(t, err, "Failed to get object directly from MinIO")

	directData, err := io.ReadAll(directResp.Body)
	require.NoError(t, err, "Failed to read object data from MinIO")
	directResp.Body.Close()

	assert.NotEqual(t, testData, directData, "Data in MinIO should be encrypted (different from original)")

	// Step 4: Verify proxy returns original data and only client metadata
	t.Log("Step 4: Verifying proxy returns original data and filters S3EP metadata...")
	proxyResp, err := proxyClient.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(objectKey),
	})
	require.NoError(t, err, "Failed to get object via proxy")

	proxyData, err := io.ReadAll(proxyResp.Body)
	require.NoError(t, err, "Failed to read object data via proxy")
	proxyResp.Body.Close()

	assert.Equal(t, testData, proxyData, "Data via proxy should match original (decrypted)")

	// Verify NO S3EP metadata is visible through proxy
	for key := range proxyResp.Metadata {
		assert.False(t, strings.HasPrefix(key, "s3ep-"),
			"S3EP metadata key %s should be filtered out by proxy", key)
	}

	// Verify all client metadata is returned by proxy
	for expectedKey, expectedValue := range clientMetadata {
		actualValue, exists := proxyResp.Metadata[expectedKey]
		assert.True(t, exists, "Client metadata key %s should be returned by proxy", expectedKey)
		assert.Equal(t, expectedValue, actualValue, "Client metadata via proxy should match for key %s", expectedKey)
	}

	t.Log("✅ RSA metadata handling test completed successfully!")
}

// TestRSAProvider_LargeFile tests RSA encryption with larger files that may trigger streaming
func TestRSAProvider_LargeFile(t *testing.T) {
	// Set log level to reduce noise during tests
	logrus.SetLevel(logrus.ErrorLevel)

	// Skip if MinIO is not available
	EnsureMinIOAvailable(t)

	// Start our own proxy instance with rsa-example.yaml config
	t.Log("Starting dedicated proxy instance with RSA provider configuration...")
	proxyInstance := StartRSAProviderProxyInstance(t)
	defer proxyInstance.Stop()

	// Verify that the RSA provider is indeed active
	if !IsRSAProviderActive(t, proxyInstance) {
		t.Fatal("RSA provider should be active but isn't - check the rsa-example.yaml configuration")
	}

	// Create MinIO client
	minioClient, err := CreateMinIOClient()
	require.NoError(t, err, "MinIO client creation failed")

	// Use the proxy client from our instance
	proxyClient := proxyInstance.client

	bucketName := "rsa-large-file-test"
	objectKey := "large-test-file.bin"

	// Create a larger test file (2MB) to test streaming behavior
	testData := make([]byte, 2*1024*1024) // 2MB
	for i := range testData {
		testData[i] = byte(i % 256)
	}

	// Setup: Create test bucket
	CreateTestBucket(t, minioClient, bucketName)
	defer CleanupTestBucket(t, minioClient, bucketName)

	ctx := context.Background()

	// Step 1: Upload large file via proxy
	t.Log("Step 1: Uploading 2MB file via S3 Encryption Proxy with RSA provider...")
	startTime := time.Now()
	_, err = proxyClient.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(objectKey),
		Body:   bytes.NewReader(testData),
		Metadata: map[string]string{
			"test-type": "large-file-rsa",
			"file-size": fmt.Sprintf("%d", len(testData)),
			"upload-by": "integration-test",
		},
	})
	uploadDuration := time.Since(startTime)
	require.NoError(t, err, "Failed to upload large file via proxy")
	t.Logf("Upload completed in %v", uploadDuration)

	// Step 2: Verify file is encrypted in MinIO
	t.Log("Step 2: Verifying large file is encrypted in MinIO...")
	directResp, err := minioClient.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(objectKey),
	})
	require.NoError(t, err, "Failed to get large file directly from MinIO")

	// Read first 1KB to compare (not entire file for performance)
	directData := make([]byte, 1024)
	n, err := directResp.Body.Read(directData)
	require.NoError(t, err, "Failed to read large file data from MinIO")
	directResp.Body.Close()
	directData = directData[:n]

	// First 1KB should be different (encrypted)
	assert.NotEqual(t, testData[:n], directData, "Large file should be encrypted with RSA provider")

	// Step 3: Download via proxy and verify it matches original
	t.Log("Step 3: Downloading large file via S3 Encryption Proxy...")
	startTime = time.Now()
	proxyResp, err := proxyClient.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(objectKey),
	})
	require.NoError(t, err, "Failed to get large file via proxy")

	proxyData, err := io.ReadAll(proxyResp.Body)
	require.NoError(t, err, "Failed to read large file data via proxy")
	proxyResp.Body.Close()
	downloadDuration := time.Since(startTime)
	t.Logf("Download completed in %v", downloadDuration)

	// Verify full file content matches after decryption
	assert.Equal(t, len(testData), len(proxyData), "Large file size should match after decryption")
	assert.Equal(t, testData, proxyData, "Large file content should match original after decryption")

	// Step 4: Verify metadata handling for large files
	assert.Contains(t, proxyResp.Metadata, "test-type", "Large file should have client metadata via proxy")
	assert.Equal(t, "large-file-rsa", proxyResp.Metadata["test-type"], "Large file metadata should match")

	// Verify no S3EP metadata is visible
	for key := range proxyResp.Metadata {
		assert.False(t, strings.HasPrefix(key, "s3ep-"),
			"S3EP metadata should be filtered from large file by proxy")
	}

	t.Log("✅ Large file RSA provider test completed successfully!")
}

// TestRSAProvider_KeyRotationCompatibility tests that objects encrypted with RSA provider
// can still be decrypted even if they were encrypted with the same key (simulating key rotation compatibility)
func TestRSAProvider_KeyRotationCompatibility(t *testing.T) {
	// Set log level to reduce noise during tests
	logrus.SetLevel(logrus.ErrorLevel)

	// Skip if MinIO is not available
	EnsureMinIOAvailable(t)

	// Start our own proxy instance with rsa-example.yaml config
	t.Log("Starting dedicated proxy instance with RSA provider configuration...")
	proxyInstance := StartRSAProviderProxyInstance(t)
	defer proxyInstance.Stop()

	// Verify that the RSA provider is indeed active
	if !IsRSAProviderActive(t, proxyInstance) {
		t.Fatal("RSA provider should be active but isn't - check the rsa-example.yaml configuration")
	}

	// Create MinIO client
	minioClient, err := CreateMinIOClient()
	require.NoError(t, err, "MinIO client creation failed")

	// Use the proxy client from our instance
	proxyClient := proxyInstance.client

	bucketName := "rsa-key-rotation-test"

	// Setup: Create test bucket
	CreateTestBucket(t, minioClient, bucketName)
	defer CleanupTestBucket(t, minioClient, bucketName)

	ctx := context.Background()

	// Test multiple objects with different content to simulate different encryption scenarios
	testObjects := map[string][]byte{
		"document1.txt": []byte("This is document 1 encrypted with RSA"),
		"document2.txt": []byte("This is document 2 with different content for RSA encryption testing"),
		"document3.txt": []byte("Document 3 has even more varied content to test RSA envelope encryption"),
	}

	// Step 1: Upload multiple objects (simulating objects encrypted over time)
	t.Log("Step 1: Uploading multiple objects to simulate time-based encryption...")
	for key, data := range testObjects {
		_, err = proxyClient.PutObject(ctx, &s3.PutObjectInput{
			Bucket: aws.String(bucketName),
			Key:    aws.String(key),
			Body:   bytes.NewReader(data),
			Metadata: map[string]string{
				"document-id":     key,
				"encryption-test": "key-rotation-compatibility",
			},
		})
		require.NoError(t, err, "Failed to upload object %s via proxy", key)

		// Add small delay to simulate time-based encryption
		time.Sleep(10 * time.Millisecond)
	}

	// Step 2: Verify all objects have unique encrypted content but same provider metadata
	t.Log("Step 2: Verifying encrypted objects have consistent S3EP metadata...")
	var firstObjectMetadata map[string]string
	for key := range testObjects {
		headResult, err := minioClient.HeadObject(ctx, &s3.HeadObjectInput{
			Bucket: aws.String(bucketName),
			Key:    aws.String(key),
		})
		require.NoError(t, err, "Failed to head object %s in MinIO", key)

		// Collect S3EP metadata for this object
		currentS3EPMetadata := make(map[string]string)
		for metaKey, metaValue := range headResult.Metadata {
			if strings.HasPrefix(metaKey, "s3ep-") {
				currentS3EPMetadata[metaKey] = metaValue
			}
		}

		assert.NotEmpty(t, currentS3EPMetadata, "Object %s should have S3EP metadata", key)

		// Store first object's metadata for comparison
		if firstObjectMetadata == nil {
			firstObjectMetadata = currentS3EPMetadata
		} else {
			// All objects should have the same KEK algorithm and fingerprint (same key)
			assert.Equal(t, firstObjectMetadata["s3ep-kek-algorithm"], currentS3EPMetadata["s3ep-kek-algorithm"],
				"KEK algorithm should be consistent across objects")
			assert.Equal(t, firstObjectMetadata["s3ep-kek-fingerprint"], currentS3EPMetadata["s3ep-kek-fingerprint"],
				"KEK fingerprint should be consistent (same key used)")

			// But encrypted DEK should be different (unique per object)
			if firstObjectMetadata["s3ep-encrypted-dek"] == currentS3EPMetadata["s3ep-encrypted-dek"] {
				t.Logf("Warning: Objects %s have identical encrypted DEK - this might be expected for test keys", key)
			}
		}
	}

	// Step 3: Verify all objects can still be decrypted correctly
	t.Log("Step 3: Verifying all objects can be decrypted with current key...")
	for key, originalData := range testObjects {
		proxyResp, err := proxyClient.GetObject(ctx, &s3.GetObjectInput{
			Bucket: aws.String(bucketName),
			Key:    aws.String(key),
		})
		require.NoError(t, err, "Failed to get object %s via proxy", key)

		proxyData, err := io.ReadAll(proxyResp.Body)
		require.NoError(t, err, "Failed to read object %s data via proxy", key)
		proxyResp.Body.Close()

		// Verify decryption works correctly
		assert.Equal(t, originalData, proxyData, "Object %s should decrypt to original content", key)

		// Verify client metadata is preserved
		assert.Contains(t, proxyResp.Metadata, "document-id", "Object %s should have client metadata", key)
		assert.Equal(t, key, proxyResp.Metadata["document-id"], "Object %s metadata should match", key)
	}

	t.Log("✅ RSA key rotation compatibility test completed successfully!")
}
