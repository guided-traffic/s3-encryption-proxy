//go:build integration
// +build integration

package variants

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/guided-traffic/s3-encryption-proxy/test/integration"
)

const (
	TestFileSize20MB = 20 * 1024 * 1024 // 20MB for multipart upload
	HMACTestBucket   = "hmac-validation-test"
)

// TestHMACValidation tests HMAC integrity verification during download
func TestHMACValidation(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping HMAC validation test in short mode")
	}

	// Ensure services are available
	integration.EnsureMinIOAndProxyAvailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	// Setup S3 clients
	s3ProxyClient, err := integration.CreateProxyClient()
	require.NoError(t, err, "Failed to create proxy S3 client")

	s3DirectClient, err := integration.CreateMinIOClient()
	require.NoError(t, err, "Failed to create direct MinIO client")

	// Setup test bucket
	integration.SetupTestBucket(t, ctx, s3ProxyClient, HMACTestBucket)
	defer func() {
		t.Logf("📁 Test data will remain in bucket '%s' for manual inspection", HMACTestBucket)
	}()

	t.Run("Valid_HMAC_Download", func(t *testing.T) {
		testValidHMACDownload(t, ctx, s3ProxyClient, s3DirectClient)
	})

	t.Run("Invalid_HMAC_Download", func(t *testing.T) {
		testInvalidHMACDownload(t, ctx, s3ProxyClient, s3DirectClient)
	})
}

// testValidHMACDownload tests that a correctly uploaded file can be downloaded successfully
func testValidHMACDownload(t *testing.T, ctx context.Context, s3ProxyClient *s3.Client, s3DirectClient *s3.Client) {
	objectKey := fmt.Sprintf("valid-hmac-test-seq-%d.bin", time.Now().Unix())

	t.Logf("🔍 Testing valid HMAC download for 20MB file")

	// Generate 20MB of random test data
	originalData := make([]byte, TestFileSize20MB)
	_, err := rand.Read(originalData)
	require.NoError(t, err, "Failed to generate random test data")

	// Calculate hash of original data for verification
	originalHash := sha256.Sum256(originalData)

	t.Logf("📤 Uploading 20MB file via multipart upload...")
	startTime := time.Now()

	// Upload via streaming multipart upload (should use AES-CTR with HMAC)
	uploader := manager.NewUploader(s3ProxyClient, func(u *manager.Uploader) {
		u.PartSize = 5 * 1024 * 1024 // 5MB parts
	})

	uploadResult, err := uploader.Upload(ctx, &s3.PutObjectInput{
		Bucket: aws.String(HMACTestBucket),
		Key:    aws.String(objectKey),
		Body:   bytes.NewReader(originalData),
	})
	require.NoError(t, err, "Failed to upload file")
	require.NotEmpty(t, uploadResult.Location, "Upload location should not be empty")

	uploadDuration := time.Since(startTime)
	t.Logf("✅ Upload completed: Location=%s, Duration=%v", uploadResult.Location, uploadDuration)

	// Verify object exists and get metadata directly from MinIO (bypasses proxy filtering)
	headResult, err := s3DirectClient.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(HMACTestBucket),
		Key:    aws.String(objectKey),
	})
	require.NoError(t, err, "Failed to get object metadata from MinIO")

	// Verify encryption metadata is present in MinIO
	dekAlgorithm := headResult.Metadata["s3ep-dek-algorithm"]
	hmacValue := headResult.Metadata["s3ep-hmac"]
	assert.NotEmpty(t, dekAlgorithm, "DEK algorithm metadata should be present in MinIO")
	assert.NotEmpty(t, hmacValue, "HMAC metadata should be present in MinIO")
	assert.Equal(t, "aes-ctr", dekAlgorithm, "Should use AES-CTR for multipart")

	t.Logf("🔐 Encryption metadata verified - DEK: %s, HMAC present: %t",
		dekAlgorithm, hmacValue != "")

	// Download and verify
	t.Logf("📥 Downloading file for HMAC verification...")
	downloadStart := time.Now()

	getResult, err := s3ProxyClient.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(HMACTestBucket),
		Key:    aws.String(objectKey),
	})
	require.NoError(t, err, "Failed to download object")
	defer getResult.Body.Close()

	// Read all data and verify
	downloadedData, err := io.ReadAll(getResult.Body)
	require.NoError(t, err, "Failed to read downloaded data")

	downloadDuration := time.Since(downloadStart)
	t.Logf("✅ Download completed: Size=%d bytes, Duration=%v", len(downloadedData), downloadDuration)

	// Verify data integrity
	assert.Equal(t, len(originalData), len(downloadedData), "Downloaded data size should match original")

	downloadedHash := sha256.Sum256(downloadedData)
	assert.Equal(t, originalHash[:], downloadedHash[:], "Downloaded data hash should match original")

	t.Logf("✅ HMAC validation successful - data integrity verified")
}

// testInvalidHMACDownload tests that tampering with the encrypted data causes HMAC validation to fail
func testInvalidHMACDownload(t *testing.T, ctx context.Context, s3ProxyClient *s3.Client, s3DirectClient *s3.Client) {
	objectKey := fmt.Sprintf("invalid-hmac-test-seq-%d.bin", time.Now().Unix())

	t.Logf("🔍 Testing invalid HMAC download (tampered data)")

	// Generate 20MB of random test data
	originalData := make([]byte, TestFileSize20MB)
	_, err := rand.Read(originalData)
	require.NoError(t, err, "Failed to generate random test data")

	t.Logf("📤 Uploading 20MB file via multipart upload...")

	// Upload via streaming multipart upload
	uploader := manager.NewUploader(s3ProxyClient, func(u *manager.Uploader) {
		u.PartSize = 5 * 1024 * 1024 // 5MB parts
	})

	uploadResult, err := uploader.Upload(ctx, &s3.PutObjectInput{
		Bucket: aws.String(HMACTestBucket),
		Key:    aws.String(objectKey),
		Body:   bytes.NewReader(originalData),
	})
	require.NoError(t, err, "Failed to upload file")
	t.Logf("✅ Upload completed: %s", uploadResult.Location)

	// Now tamper with the encrypted data directly in MinIO
	t.Logf("🔧 Tampering with encrypted data in MinIO...")

	// Get the encrypted data directly from MinIO
	encryptedResult, err := s3DirectClient.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(HMACTestBucket),
		Key:    aws.String(objectKey),
	})
	require.NoError(t, err, "Failed to get encrypted data from MinIO")

	encryptedData, err := io.ReadAll(encryptedResult.Body)
	encryptedResult.Body.Close()
	require.NoError(t, err, "Failed to read encrypted data")

	t.Logf("📊 Original encrypted size: %d bytes", len(encryptedData))

	// Tamper with the data (flip some bits in the middle)
	tamperedData := make([]byte, len(encryptedData))
	copy(tamperedData, encryptedData)

	// Flip bits at multiple locations to ensure HMAC fails
	tamperPositions := []int{
		len(tamperedData) / 4,     // 25% through
		len(tamperedData) / 2,     // 50% through
		3 * len(tamperedData) / 4, // 75% through
	}

	for _, pos := range tamperPositions {
		if pos < len(tamperedData) {
			tamperedData[pos] ^= 0xFF // Flip all bits in this byte
		}
	}

	t.Logf("🔧 Tampered with %d positions in encrypted data", len(tamperPositions))

	// Write tampered data back to MinIO using multipart upload for large files
	if len(tamperedData) > 5*1024*1024 { // If larger than 5MB, use multipart
		// Use MinIO uploader for large files
		uploader := manager.NewUploader(s3DirectClient, func(u *manager.Uploader) {
			u.PartSize = 5 * 1024 * 1024 // 5MB parts to avoid chunk size limits
			u.Concurrency = 1
		})

		_, err = uploader.Upload(ctx, &s3.PutObjectInput{
			Bucket:   aws.String(HMACTestBucket),
			Key:      aws.String(objectKey),
			Body:     bytes.NewReader(tamperedData),
			Metadata: encryptedResult.Metadata, // Preserve original metadata including HMAC
		})
	} else {
		// For smaller files, use regular PutObject
		_, err = s3DirectClient.PutObject(ctx, &s3.PutObjectInput{
			Bucket:        aws.String(HMACTestBucket),
			Key:           aws.String(objectKey),
			Body:          bytes.NewReader(tamperedData),
			ContentLength: aws.Int64(int64(len(tamperedData))),
			Metadata:      encryptedResult.Metadata, // Preserve original metadata including HMAC
		})
	}
	require.NoError(t, err, "Failed to write tampered data back to MinIO")

	t.Logf("✅ Tampered data written back to MinIO")

	// Now try to download via proxy - this should fail HMAC validation
	t.Logf("📥 Attempting to download tampered file (should fail HMAC validation)...")

	getResult, err := s3ProxyClient.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(HMACTestBucket),
		Key:    aws.String(objectKey),
	})

	if err != nil {
		// HMAC validation might fail immediately
		t.Logf("✅ Download failed immediately with error: %v", err)
		assert.Contains(t, err.Error(), "HMAC", "Error should mention HMAC validation failure")
		return
	}

	// If GetObject succeeds, the HMAC validation should fail when reading the stream
	defer getResult.Body.Close()

	// Read all data
	_, readErr := io.ReadAll(getResult.Body)

	// Force close to trigger HMAC verification - this is critical!
	closeErr := getResult.Body.Close()

	// Either reading should fail OR closing should fail due to HMAC validation
	// Note: Due to HTTP streaming limitations, the error may manifest as "unexpected EOF"
	// when HMAC validation fails after HTTP headers have been sent
	if readErr != nil {
		t.Logf("✅ HMAC validation failed during read: %v", readErr)

		// Accept either explicit "HMAC" error or "unexpected EOF" (which indicates stream abortion)
		if !assert.Condition(t, func() bool {
			errStr := readErr.Error()
			return strings.Contains(errStr, "HMAC") || strings.Contains(errStr, "unexpected EOF")
		}, "Read error should indicate HMAC validation failure (got: %v)", readErr) {
			return
		}

		t.Logf("✅ Download correctly aborted due to HMAC validation failure")
		return
	}

	if closeErr != nil {
		t.Logf("✅ HMAC validation failed during close: %v", closeErr)
		assert.Condition(t, func() bool {
			errStr := closeErr.Error()
			return strings.Contains(errStr, "HMAC") || strings.Contains(errStr, "unexpected EOF")
		}, "Close error should indicate HMAC validation failure (got: %v)", closeErr)
		return
	}

	// This should not happen - one of the above should have failed
	t.Fatalf("❌ HMAC validation did not detect tampered data! This is a security vulnerability.")
}
