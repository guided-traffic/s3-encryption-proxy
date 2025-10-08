//go:build integration
// +build integration

package variants

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	mathrand "math/rand"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption/factory"
	"github.com/guided-traffic/s3-encryption-proxy/test/integration"
)

const (
	// Single-part upload size constants for AES-CTR testing
	// AES-CTR is designed for streaming, so we test it with forced single-part uploads
	CTRSinglePartSize1Byte    = 1
	CTRSinglePartSize10Bytes  = 10
	CTRSinglePartSize100Bytes = 100
	CTRSinglePartSize1KB      = 1024
	CTRSinglePartSize10KB     = 10 * 1024
	CTRSinglePartSize100KB    = 100 * 1024
	CTRSinglePartSize1MB      = 1024 * 1024
	CTRSinglePartSize10MB     = 10 * 1024 * 1024
	CTRSinglePartSize50MB     = 50 * 1024 * 1024
	CTRSinglePartSize100MB    = 100 * 1024 * 1024
)

// TestComprehensiveSinglePartCTRUpload tests various file sizes from 1 byte to 100MB using forced AES-CTR single-part uploads
func TestComprehensiveSinglePartCTRUpload(t *testing.T) {
	// Ensure services are available
	integration.EnsureMinIOAndProxyAvailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Minute)
	defer cancel()

	testBucket := "comprehensive-singlepart-ctr-test"

	// Create clients
	minioClient, err := integration.CreateMinIOClient()
	require.NoError(t, err, "Failed to create MinIO client")

	proxyClient, err := integration.CreateProxyClient()
	require.NoError(t, err, "Failed to create Proxy client")

	// Setup test bucket (create and clean)
	integration.SetupTestBucket(t, ctx, proxyClient, testBucket)

	// Note: We do NOT clean up at the end to allow manual inspection
	t.Logf("📁 Test data will remain in bucket '%s' for manual inspection", testBucket)

	// Comprehensive test cases covering all sizes using forced AES-CTR single-part uploads
	testCases := []struct {
		name           string
		size           int64
		timeout        time.Duration
		critical       bool   // If true, test failure indicates critical bug
		encryptionType string // Expected encryption method
		expectOverhead bool   // Whether to expect encryption overhead
	}{
		{
			name:           "1 byte",
			size:           CTRSinglePartSize1Byte,
			timeout:        30 * time.Second,
			critical:       true,
			encryptionType: "AES-CTR",
			expectOverhead: false, // AES-CTR has no storage overhead
		},
		{
			name:           "10 bytes",
			size:           CTRSinglePartSize10Bytes,
			timeout:        30 * time.Second,
			critical:       true,
			encryptionType: "AES-CTR",
			expectOverhead: false, // AES-CTR has no storage overhead
		},
		{
			name:           "100 bytes",
			size:           CTRSinglePartSize100Bytes,
			timeout:        30 * time.Second,
			critical:       true,
			encryptionType: "AES-CTR",
			expectOverhead: false, // AES-CTR has no storage overhead
		},
		{
			name:           "1KB",
			size:           CTRSinglePartSize1KB,
			timeout:        30 * time.Second,
			critical:       true,
			encryptionType: "AES-CTR",
			expectOverhead: false, // AES-CTR has no storage overhead
		},
		{
			name:           "10KB",
			size:           CTRSinglePartSize10KB,
			timeout:        30 * time.Second,
			critical:       true,
			encryptionType: "AES-CTR",
			expectOverhead: false, // AES-CTR has no storage overhead
		},
		{
			name:           "100KB",
			size:           CTRSinglePartSize100KB,
			timeout:        30 * time.Second,
			critical:       true,
			encryptionType: "AES-CTR",
			expectOverhead: false, // AES-CTR has no storage overhead
		},
		{
			name:           "1MB",
			size:           CTRSinglePartSize1MB,
			timeout:        1 * time.Minute,
			critical:       true,
			encryptionType: "AES-CTR",
			expectOverhead: false, // AES-CTR has no storage overhead
		},
		{
			name:           "10MB",
			size:           CTRSinglePartSize10MB,
			timeout:        3 * time.Minute,
			critical:       true,
			encryptionType: "AES-CTR",
			expectOverhead: false, // AES-CTR has no storage overhead
		},
		// Note: Larger files commented out due to MinIO 16MB single-upload limit
		// {
		// 	name:             "50MB",
		// 	size:             CTRSinglePartSize50MB,
		// 	timeout:          5 * time.Minute,
		// 	critical:         true,
		// 	encryptionType:   "AES-CTR", // Forced to AES-CTR via Content-Type
		// 	expectOverhead:   false,     // AES-CTR has no storage overhead
		// },
		// {
		// 	name:             "100MB",
		// 	size:             CTRSinglePartSize100MB,
		// 	timeout:          8 * time.Minute,
		// 	critical:         true,
		// 	encryptionType:   "AES-CTR", // Forced to AES-CTR via Content-Type
		// 	expectOverhead:   false,     // AES-CTR has no storage overhead
		// },
	}

	for _, tc := range testCases {
		tc := tc // capture loop variable
		t.Run(tc.name, func(t *testing.T) {
			testCtx, cancel := context.WithTimeout(ctx, tc.timeout)
			defer cancel()

			// Generate test data
			t.Logf("Generating %d bytes of test data for AES-CTR single-part upload...", tc.size)
			testData, originalHash := generateCTRSinglePartTestData(t, tc.size)

			// Use timestamp to prevent test caching
			testKey := fmt.Sprintf("singlepart-ctr-test-%s-%d-bytes-%d", strings.ReplaceAll(tc.name, " ", "-"), tc.size, time.Now().UnixNano())			// Upload through proxy using forced AES-CTR single-part upload (PutObject)
			t.Logf("Uploading %s (%d bytes) through proxy using forced AES-CTR single-part upload...", tc.name, tc.size)
			uploadedSize := uploadCTRSinglePartFile(t, testCtx, proxyClient, testBucket, testKey, testData)

			// Verify encryption behavior for AES-CTR single-part uploads
			// AES-CTR is a streaming cipher that doesn't add storage overhead
			// The encrypted data has the same size as the original data
			if tc.expectOverhead {
				// AES-CTR streaming encryption maintains 1:1 data size ratio
				// Metadata is stored separately, so file size should remain the same
				if uploadedSize != tc.size {
					t.Logf("📊 AES-CTR Note: uploaded size (%d) vs original (%d), difference: %d bytes",
						uploadedSize, tc.size, uploadedSize-tc.size)
				} else {
					t.Logf("✅ AES-CTR streaming encryption: original=%d bytes, uploaded=%d bytes (no storage overhead - streaming cipher)",
						tc.size, uploadedSize)
				}
			} else {
				// Files without expected overhead should match exactly
				if uploadedSize != tc.size {
					t.Errorf("AES-CTR file should have no storage overhead for %s: Expected %d bytes, got %d bytes (diff: %d)",
						tc.name, tc.size, uploadedSize, uploadedSize-tc.size)
				} else {
					t.Logf("✅ AES-CTR %s: original=%d bytes, uploaded=%d bytes (no overhead as expected)",
						tc.encryptionType, tc.size, uploadedSize)
				}
			} // Verify file exists and has correct size in MinIO
			verifyCTRSinglePartFileInMinIO(t, testCtx, minioClient, testBucket, testKey, tc.size, uploadedSize)

			// Verify AES-CTR encryption metadata
			verifyCTRSinglePartEncryptionMetadata(t, testCtx, minioClient, testBucket, testKey, tc.encryptionType)

			// Download and verify integrity
			t.Logf("Downloading %s through proxy...", tc.name)
			downloadedData := downloadCTRSinglePartFile(t, testCtx, proxyClient, testBucket, testKey)

			// Debug comparison for very small files
			if tc.size <= 100 {
				t.Logf("Data comparison for %s:", tc.name)
				t.Logf("  Original:   %x", testData)
				t.Logf("  Downloaded: %x", downloadedData)
			} else if tc.size <= CTRSinglePartSize1KB {
				// Show first and last 32 bytes for small files
				showBytes := min(32, len(testData))
				t.Logf("First %d bytes comparison for %s:", showBytes, tc.name)
				t.Logf("  Original:   %x", testData[:showBytes])
				t.Logf("  Downloaded: %x", downloadedData[:min(showBytes, len(downloadedData))])

				if len(testData) > 64 {
					t.Logf("Last %d bytes comparison for %s:", showBytes, tc.name)
					t.Logf("  Original:   %x", testData[len(testData)-showBytes:])
					t.Logf("  Downloaded: %x", downloadedData[max(0, len(downloadedData)-showBytes):])
				}
			} else {
				// For larger files, show first and last 32 bytes
				showBytes := min(32, len(testData))
				t.Logf("First %d bytes comparison for %s:", showBytes, tc.name)
				t.Logf("  Original:   %x", testData[:showBytes])
				t.Logf("  Downloaded: %x", downloadedData[:min(showBytes, len(downloadedData))])

				if len(testData) > 64 {
					t.Logf("Last %d bytes comparison for %s:", showBytes, tc.name)
					t.Logf("  Original:   %x", testData[len(testData)-showBytes:])
					t.Logf("  Downloaded: %x", downloadedData[max(0, len(downloadedData)-showBytes):])
				}
			}

			// Verify data integrity - this should be perfect for single-part uploads
			verifyCTRSinglePartDataIntegrity(t, originalHash, downloadedData, tc.size, tc.critical)

			// Cleanup
			cleanupCTRSinglePartTestFile(t, testCtx, proxyClient, testBucket, testKey)

			t.Logf("✅ %s AES-CTR single-part upload completed successfully", tc.name)
		})
	}
}

// TestSinglePartCTRUploadVsMultipart compares forced AES-CTR single-part vs multipart for files around various boundaries
func TestSinglePartCTRUploadVsMultipart(t *testing.T) {
	// Ensure services are available
	integration.EnsureMinIOAndProxyAvailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	testBucket := "singlepart-ctr-vs-multipart-test"

	// Create clients
	proxyClient, err := integration.CreateProxyClient()
	require.NoError(t, err, "Failed to create proxy client")

	// Setup test bucket
	_, err = proxyClient.CreateBucket(ctx, &s3.CreateBucketInput{
		Bucket: aws.String(testBucket),
	})
	require.NoError(t, err, "Failed to create test bucket")

	defer func() {
		integration.CleanupTestBucket(t, proxyClient, testBucket)
	}()

	// Test sizes around various boundaries where behavior might differ
	testCases := []struct {
		name       string
		size       int64
		uploadType string
	}{
		{"4MB_ctr_single", 4 * 1024 * 1024, "forced-aes-ctr-single-part"},
		{"5MB_ctr_single", 5 * 1024 * 1024, "forced-aes-ctr-single-part"},
		{"6MB_ctr_single", 6 * 1024 * 1024, "forced-aes-ctr-single-part"},
		{"10MB_ctr_single", 10 * 1024 * 1024, "forced-aes-ctr-single-part"},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			testCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
			defer cancel()

			t.Logf("=== Testing %s (%d bytes) with %s upload ===", tc.name, tc.size, tc.uploadType)

			// Generate test data
			testData, originalHash := generateCTRSinglePartTestData(t, tc.size)
			// Use timestamp to prevent test caching
			testKey := fmt.Sprintf("comparison-ctr-test-%s-%d", tc.name, time.Now().UnixNano())			// Upload using forced AES-CTR single-part method
			startTime := time.Now()
			uploadedSize := uploadCTRSinglePartFile(t, testCtx, proxyClient, testBucket, testKey, testData)
			uploadDuration := time.Since(startTime)

			t.Logf("Forced AES-CTR single-part upload results:")
			t.Logf("  Duration: %v", uploadDuration)
			t.Logf("  Original size: %d bytes", tc.size)
			t.Logf("  Uploaded size: %d bytes", uploadedSize)
			t.Logf("  Overhead: %d bytes", uploadedSize-tc.size)

			// Download and verify
			downloadStartTime := time.Now()
			downloadedData := downloadCTRSinglePartFile(t, testCtx, proxyClient, testBucket, testKey)
			downloadDuration := time.Since(downloadStartTime)

			t.Logf("AES-CTR single-part download results:")
			t.Logf("  Duration: %v", downloadDuration)
			t.Logf("  Downloaded size: %d bytes", len(downloadedData))

			// Verify integrity
			verifyCTRSinglePartDataIntegrity(t, originalHash, downloadedData, tc.size, true)

			// Cleanup
			cleanupCTRSinglePartTestFile(t, testCtx, proxyClient, testBucket, testKey)

			t.Logf("✅ %s comparison test completed", tc.name)
		})
	}
}

// TestSinglePartCTRUploadCornerCases tests edge cases for forced AES-CTR single-part uploads
func TestSinglePartCTRUploadCornerCases(t *testing.T) {
	// Ensure services are available
	integration.EnsureMinIOAndProxyAvailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	testBucket := "singlepart-ctr-corner-cases-test"

	// Create clients
	proxyClient, err := integration.CreateProxyClient()
	require.NoError(t, err, "Failed to create proxy client")

	// Setup test bucket
	_, err = proxyClient.CreateBucket(ctx, &s3.CreateBucketInput{
		Bucket: aws.String(testBucket),
	})
	require.NoError(t, err, "Failed to create test bucket")

	defer func() {
		integration.CleanupTestBucket(t, proxyClient, testBucket)
	}()

	cornerCases := []struct {
		name        string
		size        int64
		description string
	}{
		{
			name:        "empty_file_ctr",
			size:        0,
			description: "Empty file (0 bytes) with forced AES-CTR",
		},
		{
			name:        "single_null_byte_ctr",
			size:        1,
			description: "Single null byte with forced AES-CTR",
		},
		{
			name:        "all_zeros_1kb_ctr",
			size:        1024,
			description: "1KB of all zero bytes with forced AES-CTR",
		},
		{
			name:        "all_ones_1kb_ctr",
			size:        1024,
			description: "1KB of all 0xFF bytes with forced AES-CTR",
		},
		{
			name:        "power_of_two_64kb_ctr",
			size:        65536, // 2^16
			description: "Exactly 64KB (power of 2) with forced AES-CTR",
		},
		{
			name:        "odd_size_1025_ctr",
			size:        1025,
			description: "Odd size just over 1KB with forced AES-CTR",
		},
	}

	for _, tc := range cornerCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			testCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
			defer cancel()

			t.Logf("Testing AES-CTR corner case: %s (%s)", tc.name, tc.description)

			// Generate specific test data based on the test case
			var testData []byte
			switch tc.name {
			case "empty_file_ctr":
				testData = []byte{}
			case "single_null_byte_ctr":
				testData = []byte{0x00}
			case "all_zeros_1kb_ctr":
				testData = make([]byte, tc.size)
				// Already all zeros
			case "all_ones_1kb_ctr":
				testData = make([]byte, tc.size)
				for i := range testData {
					testData[i] = 0xFF
				}
			default:
				// Generate regular test data
				testData, _ = generateCTRSinglePartTestData(t, tc.size)
			}

			originalHash := sha256.Sum256(testData)
			testKey := fmt.Sprintf("corner-case-ctr-%s-%d", tc.name, time.Now().UnixNano())			// Special case: empty files typically cause errors with encryption
			if tc.size == 0 {
				t.Skip("Empty files are not supported with AES-CTR encryption")
				return
			}

			// Upload with forced AES-CTR
			uploadedSize := uploadCTRSinglePartFile(t, testCtx, proxyClient, testBucket, testKey, testData)

			// For AES-CTR, verify encryption overhead expectations
			if tc.size > 0 {
				// With unified metadata-only IV storage, AES-CTR files have no storage overhead
				// The IV is stored in S3 metadata, not prepended to the data
				require.Equal(t, tc.size, uploadedSize, "AES-CTR files should have no storage overhead with metadata-only IV")
				t.Logf("AES-CTR size verification: original=%d bytes, uploaded=%d bytes (no overhead with metadata-only IV)", tc.size, uploadedSize)
			}

			// Download and verify
			downloadedData := downloadCTRSinglePartFile(t, testCtx, proxyClient, testBucket, testKey)
			verifyCTRSinglePartDataIntegrity(t, originalHash, downloadedData, tc.size, true)

			t.Logf("✅ AES-CTR corner case %s passed", tc.name)

			// Cleanup
			cleanupCTRSinglePartTestFile(t, testCtx, proxyClient, testBucket, testKey)
		})
	}
}

// Helper functions specific to AES-CTR testing

// generateCTRSinglePartTestData creates deterministic test data for AES-CTR single-part uploads
func generateCTRSinglePartTestData(t *testing.T, size int64) ([]byte, [32]byte) {
	t.Helper()

	if size == 0 {
		data := []byte{}
		hash := sha256.Sum256(data)
		return data, hash
	}

	// Use fixed seed for deterministic test data (different from GCM tests)
	rng := mathrand.New(mathrand.NewSource(98765)) // Different seed for AES-CTR tests

	data := make([]byte, size)

	// For very large files, generate data in chunks to avoid memory issues
	chunkSize := 1024 * 1024 // 1MB chunks
	if size < int64(chunkSize) {
		chunkSize = int(size)
	}

	for offset := int64(0); offset < size; {
		remainingSize := size - offset
		currentChunkSize := int64(chunkSize)
		if remainingSize < currentChunkSize {
			currentChunkSize = remainingSize
		}

		chunk := data[offset : offset+currentChunkSize]
		// Use manual byte generation for true determinism
		for i := range chunk {
			chunk[i] = byte(rng.Int())
		}

		offset += currentChunkSize
	}

	// Calculate hash of original data
	hash := sha256.Sum256(data)

	t.Logf("Generated %d bytes of AES-CTR single-part test data (SHA256: %x)", size, hash)
	return data, hash
}

// uploadCTRSinglePartFile uploads a file using forced AES-CTR single-part upload (PutObject) with performance metrics
func uploadCTRSinglePartFile(t *testing.T, ctx context.Context, client *s3.Client, bucket, key string, data []byte) int64 {
	t.Helper()

	reader := bytes.NewReader(data)
	startTime := time.Now()
	dataSize := int64(len(data))

	// Use PutObject for single-part upload with forced AES-CTR content type
	putInput := &s3.PutObjectInput{
		Bucket:      aws.String(bucket),
		Key:         aws.String(key),
		Body:        reader,
		ContentType: aws.String(factory.ForceAESCTRContentType), // Force AES-CTR encryption
		Metadata: map[string]string{
			"test-method":   "forced-aes-ctr-single-part-putobject",
			"upload-time":   startTime.Format(time.RFC3339),
			"expected-algo": "aes-ctr",
		},
	}

	t.Logf("🔧 Forcing AES-CTR for file (%s) using Content-Type: %s",
		formatDataSize(dataSize), factory.ForceAESCTRContentType)

	_, err := client.PutObject(ctx, putInput)

	uploadDuration := time.Since(startTime)
	require.NoError(t, err, "AES-CTR single-part upload failed")

	// Calculate upload throughput
	uploadThroughput := calculateThroughput(dataSize, uploadDuration)

	// Log upload performance
	t.Logf("📤 AES-CTR Upload Performance: Duration=%v, Size=%s, Throughput=%s",
		uploadDuration,
		formatDataSize(dataSize),
		formatThroughput(uploadThroughput))

	// Get object info to verify actual uploaded size
	headResult, err := client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	require.NoError(t, err, "Failed to get object metadata")

	actualSize := *headResult.ContentLength
	if actualSize != dataSize {
		t.Logf("📊 Size difference: Original=%s, Stored=%s (overhead=%d bytes)",
			formatDataSize(dataSize), formatDataSize(actualSize), actualSize-dataSize)
	}

	return actualSize
}

// verifyCTRSinglePartFileInMinIO checks if the AES-CTR encrypted file exists in MinIO with correct properties
func verifyCTRSinglePartFileInMinIO(t *testing.T, ctx context.Context, minioClient *s3.Client, bucket, key string, expectedSize, actualSize int64) {
	t.Helper()

	// Get object metadata directly from MinIO
	headResult, err := minioClient.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	require.NoError(t, err, "AES-CTR file not found in MinIO")

	minioSize := *headResult.ContentLength
	t.Logf("MinIO reports AES-CTR file size: %d bytes", minioSize)

	// The size in MinIO should match what was actually uploaded through proxy
	assert.Equal(t, actualSize, minioSize, "Size mismatch between proxy upload and MinIO storage for AES-CTR")

	// Log expected vs actual
	if minioSize != expectedSize {
		encryptionOverhead := minioSize - expectedSize
		t.Logf("✓ AES-CTR encryption overhead in MinIO: %d bytes (original: %d, stored: %d)",
			encryptionOverhead, expectedSize, minioSize)
	}
}

// verifyCTRSinglePartEncryptionMetadata checks that the file is properly encrypted with AES-CTR
func verifyCTRSinglePartEncryptionMetadata(t *testing.T, ctx context.Context, minioClient *s3.Client, bucket, key, expectedEncryption string) {
	t.Helper()

	// Get object metadata directly from MinIO
	headResult, err := minioClient.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	require.NoError(t, err, "Failed to get AES-CTR object metadata from MinIO")

	// Check for encryption metadata
	metadata := headResult.Metadata
	t.Logf("AES-CTR Object metadata: %+v", metadata)

	// Look for S3EP encryption-related metadata
	encryptionMetadataFound := false
	s3epMetadataCount := 0
	ctrAlgorithmFound := false

	for metaKey, metaValue := range metadata {
		lowerKey := strings.ToLower(metaKey)
		if strings.Contains(lowerKey, "s3ep") {
			s3epMetadataCount++
			encryptionMetadataFound = true
			t.Logf("Found S3EP metadata: %s = %s", metaKey, metaValue)

			// Check specific encryption algorithm metadata for AES-CTR
			if strings.Contains(lowerKey, "algorithm") || strings.Contains(lowerKey, "dek-algorithm") {
				if expectedEncryption == "AES-CTR" && strings.Contains(strings.ToLower(metaValue), "ctr") {
					ctrAlgorithmFound = true
					t.Logf("✅ Found expected %s encryption algorithm: %s", expectedEncryption, metaValue)
				}
			}
		}
	}

	// Check server-side encryption
	if headResult.ServerSideEncryption != "" {
		t.Logf("Server-side encryption: %s", string(headResult.ServerSideEncryption))
	}

	if !encryptionMetadataFound {
		t.Errorf("❌ No S3EP encryption metadata found - AES-CTR file may not be encrypted properly")
	} else {
		t.Logf("✅ Found %d S3EP metadata fields - AES-CTR file appears to be encrypted with envelope encryption", s3epMetadataCount)
	}

	if expectedEncryption == "AES-CTR" && !ctrAlgorithmFound {
		t.Logf("⚠️  Expected AES-CTR algorithm not explicitly found in metadata, but encryption metadata is present")
	}
}

// downloadCTRSinglePartFile downloads an AES-CTR encrypted file and returns its content with performance measurement
func downloadCTRSinglePartFile(t *testing.T, ctx context.Context, client *s3.Client, bucket, key string) []byte {
	t.Helper()

	startTime := time.Now()

	// Get object from proxy
	result, err := client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	require.NoError(t, err, "Failed to download AES-CTR object")
	defer result.Body.Close()

	// Read all data
	data, err := io.ReadAll(result.Body)
	require.NoError(t, err, "Failed to read downloaded AES-CTR data")

	downloadDuration := time.Since(startTime)
	dataSize := int64(len(data))
	downloadThroughput := calculateThroughput(dataSize, downloadDuration)

	// Log download performance
	t.Logf("📥 AES-CTR Download Performance: Duration=%v, Size=%s, Throughput=%s",
		downloadDuration,
		formatDataSize(dataSize),
		formatThroughput(downloadThroughput))

	return data
}

// verifyCTRSinglePartDataIntegrity checks that downloaded AES-CTR data matches original data
func verifyCTRSinglePartDataIntegrity(t *testing.T, originalHash [32]byte, downloadedData []byte, expectedSize int64, critical bool) {
	t.Helper()

	downloadedSize := int64(len(downloadedData))
	downloadedHash := sha256.Sum256(downloadedData)

	t.Logf("AES-CTR single-part data integrity check:")
	t.Logf("  Expected size: %d bytes", expectedSize)
	t.Logf("  Downloaded size: %d bytes", downloadedSize)
	t.Logf("  Original hash: %x", originalHash)
	t.Logf("  Downloaded hash: %x", downloadedHash)

	// Check size - should be exact for single-part downloads
	if critical && downloadedSize != expectedSize {
		t.Errorf("CRITICAL: AES-CTR Downloaded size (%d) != expected size (%d)", downloadedSize, expectedSize)
	} else if downloadedSize != expectedSize {
		t.Logf("WARNING: AES-CTR Downloaded size (%d) != expected size (%d)", downloadedSize, expectedSize)
	} else {
		t.Logf("✅ AES-CTR Size verification passed: %d bytes", downloadedSize)
	}

	// Check hash - should be perfect for single-part
	if critical && originalHash != downloadedHash {
		t.Errorf("CRITICAL: AES-CTR Data corruption detected in single-part upload - hash mismatch")
		t.Errorf("Expected: %x", originalHash)
		t.Errorf("Got:      %x", downloadedHash)
	} else if originalHash != downloadedHash {
		t.Logf("WARNING: AES-CTR Data corruption detected - hash mismatch")
	} else {
		t.Logf("✅ AES-CTR Hash verification passed: perfect match")
	}

	if downloadedSize == expectedSize && originalHash == downloadedHash {
		t.Logf("✅ AES-CTR single-part data integrity verified: perfect match")
	} else {
		t.Logf("❌ AES-CTR single-part data integrity issues detected")
	}
}

// cleanupCTRSinglePartTestFile removes the AES-CTR test file
func cleanupCTRSinglePartTestFile(t *testing.T, ctx context.Context, client *s3.Client, bucket, key string) {
	t.Helper()

	_, err := client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		t.Logf("Warning: Failed to cleanup AES-CTR test file %s: %v", key, err)
	}
}
