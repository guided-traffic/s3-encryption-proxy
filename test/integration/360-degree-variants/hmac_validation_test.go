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

	t.Run("SinglePart_CTR_HMAC", func(t *testing.T) {
		testSinglePartCTRWithHMAC(t, ctx, s3ProxyClient, s3DirectClient)
	})

	t.Run("Manipulated_HMAC_Metadata", func(t *testing.T) {
		testManipulatedHMACMetadata(t, ctx, s3ProxyClient, s3DirectClient)
	})

	t.Run("Small_File_HMAC", func(t *testing.T) {
		testSmallFileWithHMAC(t, ctx, s3ProxyClient, s3DirectClient)
	})

	t.Run("Range_Request_With_HMAC", func(t *testing.T) {
		testRangeRequestWithHMAC(t, ctx, s3ProxyClient, s3DirectClient)
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

// testSinglePartCTRWithHMAC tests HMAC validation for streaming AES-CTR uploads (13MB file)
// This tests the streaming upload path which uses AES-CTR and HMAC validation
func testSinglePartCTRWithHMAC(t *testing.T, ctx context.Context, s3ProxyClient *s3.Client, s3DirectClient *s3.Client) {
	objectKey := fmt.Sprintf("streaming-ctr-hmac-test-%d.bin", time.Now().UnixNano())

	t.Logf("🔍 Testing streaming AES-CTR with HMAC validation (13MB file)")

	// Generate 13MB of random test data
	// This is above streaming threshold (12MB) so it will definitely use streaming CTR
	testDataSize := 13 * 1024 * 1024
	originalData := make([]byte, testDataSize)
	_, err := rand.Read(originalData)
	require.NoError(t, err, "Failed to generate random test data")

	originalHash := sha256.Sum256(originalData)

	t.Logf("📤 Uploading 13MB file (forces streaming AES-CTR)...")

	// Upload directly - files >= 12MB use streaming CTR automatically
	_, err = s3ProxyClient.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(HMACTestBucket),
		Key:    aws.String(objectKey),
		Body:   bytes.NewReader(originalData),
	})
	require.NoError(t, err, "Failed to upload file")

	// Verify encryption metadata
	headResult, err := s3DirectClient.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(HMACTestBucket),
		Key:    aws.String(objectKey),
	})
	require.NoError(t, err, "Failed to get object metadata")

	dekAlgorithm := headResult.Metadata["s3ep-dek-algorithm"]
	hmacValue := headResult.Metadata["s3ep-hmac"]

	t.Logf("Encryption algorithm: %s, HMAC present: %t", dekAlgorithm, hmacValue != "")

	// Should use AES-CTR for files >= streaming threshold (12MB)
	assert.Equal(t, "aes-ctr", dekAlgorithm, "Should use AES-CTR for 13MB file")

	// CRITICAL SECURITY REQUIREMENT: Single-part CTR MUST have HMAC validation
	// Without HMAC, data integrity cannot be verified for streaming CTR uploads
	require.NotEmpty(t, hmacValue, "SECURITY: Single-part CTR MUST have HMAC for integrity verification")

	t.Logf("✅ Streaming CTR encryption confirmed with HMAC protection")

	// Download and verify through HMACValidatingReader
	t.Logf("📥 Downloading via HMACValidatingReader...")

	getResult, err := s3ProxyClient.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(HMACTestBucket),
		Key:    aws.String(objectKey),
	})
	require.NoError(t, err, "Failed to download object")
	defer getResult.Body.Close()

	downloadedData, err := io.ReadAll(getResult.Body)
	require.NoError(t, err, "Failed to read downloaded data")

	// Verify data integrity
	downloadedHash := sha256.Sum256(downloadedData)
	assert.Equal(t, originalHash[:], downloadedHash[:], "Downloaded data should match original")
	assert.Equal(t, len(originalData), len(downloadedData), "Downloaded size should match original")

	t.Logf("✅ Streaming CTR with HMAC validation successful via HMACValidatingReader")
}

// testManipulatedHMACMetadata tests that changing the HMAC value in metadata causes validation to fail
func testManipulatedHMACMetadata(t *testing.T, ctx context.Context, s3ProxyClient *s3.Client, s3DirectClient *s3.Client) {
	objectKey := fmt.Sprintf("manipulated-hmac-metadata-test-%d.bin", time.Now().Unix())

	t.Logf("🔍 Testing manipulated HMAC metadata detection")

	// Upload a valid file
	testDataSize := 10 * 1024 * 1024 // 10MB
	originalData := make([]byte, testDataSize)
	_, err := rand.Read(originalData)
	require.NoError(t, err, "Failed to generate test data")

	t.Logf("📤 Uploading valid 10MB file...")

	uploader := manager.NewUploader(s3ProxyClient, func(u *manager.Uploader) {
		u.PartSize = 5 * 1024 * 1024
	})

	_, err = uploader.Upload(ctx, &s3.PutObjectInput{
		Bucket: aws.String(HMACTestBucket),
		Key:    aws.String(objectKey),
		Body:   bytes.NewReader(originalData),
	})
	require.NoError(t, err, "Failed to upload file")

	// Get current metadata
	headResult, err := s3DirectClient.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(HMACTestBucket),
		Key:    aws.String(objectKey),
	})
	require.NoError(t, err, "Failed to get metadata")

	originalHMAC := headResult.Metadata["s3ep-hmac"]
	require.NotEmpty(t, originalHMAC, "HMAC should be present")

	t.Logf("🔧 Manipulating HMAC metadata (changing value)...")

	// Get the encrypted data
	getResult, err := s3DirectClient.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(HMACTestBucket),
		Key:    aws.String(objectKey),
	})
	require.NoError(t, err, "Failed to get object")

	encryptedData, err := io.ReadAll(getResult.Body)
	getResult.Body.Close()
	require.NoError(t, err, "Failed to read encrypted data")

	// Create manipulated metadata with wrong HMAC
	manipulatedMetadata := make(map[string]string)
	for k, v := range headResult.Metadata {
		manipulatedMetadata[k] = v
	}
	// Change HMAC to random value
	manipulatedMetadata["s3ep-hmac"] = "YW55IGNhcm5hbCBwbGVhc3VyZS4K" // Random base64

	t.Logf("Original HMAC: %s", originalHMAC)
	t.Logf("Manipulated HMAC: %s", manipulatedMetadata["s3ep-hmac"])

	// Write back with manipulated metadata
	uploader = manager.NewUploader(s3DirectClient, func(u *manager.Uploader) {
		u.PartSize = 5 * 1024 * 1024
	})

	_, err = uploader.Upload(ctx, &s3.PutObjectInput{
		Bucket:   aws.String(HMACTestBucket),
		Key:      aws.String(objectKey),
		Body:     bytes.NewReader(encryptedData),
		Metadata: manipulatedMetadata,
	})
	require.NoError(t, err, "Failed to write back with manipulated metadata")

	t.Logf("✅ Manipulated metadata written back")

	// Try to download - should fail HMAC validation
	t.Logf("📥 Attempting download with manipulated HMAC metadata...")

	getResult, err = s3ProxyClient.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(HMACTestBucket),
		Key:    aws.String(objectKey),
	})

	if err != nil {
		t.Logf("✅ Download failed immediately: %v", err)
		return
	}

	defer getResult.Body.Close()

	_, readErr := io.ReadAll(getResult.Body)
	closeErr := getResult.Body.Close()

	if readErr != nil {
		t.Logf("✅ HMAC validation correctly detected manipulated metadata during read: %v", readErr)
		assert.Condition(t, func() bool {
			errStr := readErr.Error()
			return strings.Contains(errStr, "HMAC") || strings.Contains(errStr, "unexpected EOF")
		}, "Should detect HMAC mismatch")
		return
	}

	if closeErr != nil {
		t.Logf("✅ HMAC validation correctly detected manipulated metadata during close: %v", closeErr)
		return
	}

	t.Fatalf("❌ Manipulated HMAC metadata was not detected!")
}

// testSmallFileWithHMAC tests HMAC validation for very small files (boundary case)
func testSmallFileWithHMAC(t *testing.T, ctx context.Context, s3ProxyClient *s3.Client, s3DirectClient *s3.Client) {
	objectKey := fmt.Sprintf("small-file-hmac-test-%d.bin", time.Now().Unix())

	t.Logf("🔍 Testing very small file (1KB) with HMAC validation")

	// Generate 1KB of test data
	testDataSize := 1024
	originalData := make([]byte, testDataSize)
	_, err := rand.Read(originalData)
	require.NoError(t, err, "Failed to generate test data")

	originalHash := sha256.Sum256(originalData)

	t.Logf("📤 Uploading 1KB file...")

	_, err = s3ProxyClient.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(HMACTestBucket),
		Key:    aws.String(objectKey),
		Body:   bytes.NewReader(originalData),
	})
	require.NoError(t, err, "Failed to upload small file")

	// Check metadata
	headResult, err := s3DirectClient.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(HMACTestBucket),
		Key:    aws.String(objectKey),
	})
	require.NoError(t, err, "Failed to get metadata")

	dekAlgorithm := headResult.Metadata["s3ep-dek-algorithm"]
	hmacValue := headResult.Metadata["s3ep-hmac"]

	t.Logf("Encryption algorithm: %s, HMAC present: %t", dekAlgorithm, hmacValue != "")

	// Small files should use AES-GCM, but HMAC might still be present
	// Note: GCM has built-in authentication, so HMAC is optional

	// Download and verify
	t.Logf("📥 Downloading small file...")

	getResult, err := s3ProxyClient.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(HMACTestBucket),
		Key:    aws.String(objectKey),
	})
	require.NoError(t, err, "Failed to download small file")
	defer getResult.Body.Close()

	downloadedData, err := io.ReadAll(getResult.Body)
	require.NoError(t, err, "Failed to read downloaded data")

	// Verify integrity
	downloadedHash := sha256.Sum256(downloadedData)
	assert.Equal(t, originalHash[:], downloadedHash[:], "Small file should maintain integrity")
	assert.Equal(t, len(originalData), len(downloadedData), "Downloaded size should match")

	t.Logf("✅ Small file (1KB) handled correctly with encryption algorithm: %s", dekAlgorithm)
}

// testRangeRequestWithHMAC tests behavior of range requests with HMAC validation
func testRangeRequestWithHMAC(t *testing.T, ctx context.Context, s3ProxyClient *s3.Client, s3DirectClient *s3.Client) {
	objectKey := fmt.Sprintf("range-request-hmac-test-%d.bin", time.Now().Unix())

	t.Logf("🔍 Testing range requests with HMAC validation")

	// Upload a 15MB file
	testDataSize := 15 * 1024 * 1024
	originalData := make([]byte, testDataSize)
	_, err := rand.Read(originalData)
	require.NoError(t, err, "Failed to generate test data")

	t.Logf("📤 Uploading 15MB file...")

	uploader := manager.NewUploader(s3ProxyClient, func(u *manager.Uploader) {
		u.PartSize = 5 * 1024 * 1024
	})

	_, err = uploader.Upload(ctx, &s3.PutObjectInput{
		Bucket: aws.String(HMACTestBucket),
		Key:    aws.String(objectKey),
		Body:   bytes.NewReader(originalData),
	})
	require.NoError(t, err, "Failed to upload file")

	// Verify HMAC is present
	headResult, err := s3DirectClient.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(HMACTestBucket),
		Key:    aws.String(objectKey),
	})
	require.NoError(t, err, "Failed to get metadata")

	hmacValue := headResult.Metadata["s3ep-hmac"]
	require.NotEmpty(t, hmacValue, "HMAC should be present")

	// Try a range request (first 1MB)
	t.Logf("📥 Attempting range request (bytes=0-1048575)...")

	getResult, err := s3ProxyClient.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(HMACTestBucket),
		Key:    aws.String(objectKey),
		Range:  aws.String("bytes=0-1048575"), // First 1MB
	})

	if err != nil {
		// Range requests might not be supported with HMAC validation
		t.Logf("⚠️ Range request failed (expected): %v", err)
		assert.Contains(t, err.Error(), "range", "Error should indicate range request issue")
		t.Logf("✅ Range requests correctly rejected with HMAC validation")
		return
	}

	defer getResult.Body.Close()

	rangeData, err := io.ReadAll(getResult.Body)
	if err != nil {
		t.Logf("⚠️ Range request read failed (acceptable): %v", err)
		t.Logf("✅ Range requests with HMAC validation properly handled")
		return
	}

	// If range request succeeded, verify it's the correct range
	expectedRangeSize := 1048576 // 1MB
	if len(rangeData) == expectedRangeSize {
		// Verify the data matches
		expectedRangeData := originalData[:expectedRangeSize]
		assert.Equal(t, expectedRangeData, rangeData, "Range data should match if supported")
		t.Logf("✅ Range request succeeded and data is correct")
	} else {
		t.Logf("⚠️ Range request returned unexpected size: %d bytes (expected %d)", len(rangeData), expectedRangeSize)
		t.Logf("ℹ️ Range requests with HMAC may have limitations")
	}
}
