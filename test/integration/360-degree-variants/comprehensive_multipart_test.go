//go:build integration
// +build integration

package variants

import (
	"bytes"
	"context"
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
	// File sizes for testing
	Size1Byte    = 1
	Size10Bytes  = 10
	Size100Bytes = 100
	Size1KB      = 1024
	Size10KB     = 10 * 1024
	Size100KB    = 100 * 1024
	Size1MB      = 1024 * 1024
	Size10MB     = 10 * 1024 * 1024
	Size50MB     = 50 * 1024 * 1024
	Size100MB    = 100 * 1024 * 1024
	Size1GB      = 1024 * 1024 * 1024

	// Multipart upload settings
	DefaultPartSize = 5 * 1024 * 1024 // 5 MB minimum part size
	MaxParts        = 10000
)

// TestComprehensiveMultipartUpload tests various file sizes from 1 byte to 1GB
func TestComprehensiveMultipartUpload(t *testing.T) {
	// Ensure services are available
	integration.EnsureMinIOAndProxyAvailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	// Use a fixed bucket name for easy identification and manual inspection
	testBucket := "comprehensive-multipart-test"

	// Create clients
	minioClient, err := integration.CreateMinIOClient()
	require.NoError(t, err, "Failed to create MinIO client")

	proxyClient, err := integration.CreateProxyClient()
	require.NoError(t, err, "Failed to create Proxy client")

	// Setup test bucket (create and clean)
	integration.SetupTestBucket(t, ctx, proxyClient, testBucket)

	// Note: We do NOT clean up at the end to allow manual inspection
	t.Logf("📁 Test data will remain in bucket '%s' for manual inspection", testBucket)

	// Comprehensive test cases covering all requested sizes
	testCases := []struct {
		name       string
		size       int64
		timeout    time.Duration
		critical   bool   // If true, test failure indicates critical bug
		uploadType string // "single" for < 5MB, "multipart" for >= 5MB
	}{
		{
			name:       "1 byte",
			size:       Size1Byte,
			timeout:    30 * time.Second,
			critical:   true,
			uploadType: "single",
		},
		{
			name:       "10 bytes",
			size:       Size10Bytes,
			timeout:    30 * time.Second,
			critical:   true,
			uploadType: "single",
		},
		{
			name:       "100 bytes",
			size:       Size100Bytes,
			timeout:    30 * time.Second,
			critical:   true,
			uploadType: "single",
		},
		{
			name:       "1KB",
			size:       Size1KB,
			timeout:    30 * time.Second,
			critical:   true,
			uploadType: "single",
		},
		{
			name:       "10KB",
			size:       Size10KB,
			timeout:    30 * time.Second,
			critical:   true,
			uploadType: "single",
		},
		{
			name:       "100KB",
			size:       Size100KB,
			timeout:    30 * time.Second,
			critical:   true,
			uploadType: "single",
		},
		{
			name:       "1MB",
			size:       Size1MB,
			timeout:    1 * time.Minute,
			critical:   true,
			uploadType: "single",
		},
		{
			name:       "10MB",
			size:       Size10MB,
			timeout:    2 * time.Minute,
			critical:   true,
			uploadType: "multipart",
		},
		{
			name:       "50MB",
			size:       Size50MB,
			timeout:    3 * time.Minute,
			critical:   true,
			uploadType: "multipart",
		},
		{
			name:       "100MB",
			size:       Size100MB,
			timeout:    5 * time.Minute,
			critical:   true,
			uploadType: "multipart",
		},
		{
			name:       "1GB",
			size:       Size1GB,
			timeout:    15 * time.Minute,
			critical:   true,
			uploadType: "multipart",
		},
	}

	for _, tc := range testCases {
		tc := tc // capture loop variable
		t.Run(tc.name, func(t *testing.T) {
			testCtx, cancel := context.WithTimeout(ctx, tc.timeout)
			defer cancel()

			// Generate test data
			t.Logf("Generating %d bytes of test data...", tc.size)
			testData, originalHash := generateLargeFileTestData(t, tc.size)

			// Verify original test data is NOT encrypted (baseline validation)
			integration.AssertDataIsNotEncrypted(t, testData, "Original test data should be unencrypted")

			testKey := fmt.Sprintf("test-%s-%d-bytes", strings.ReplaceAll(tc.name, " ", "-"), tc.size)

			// Upload through proxy
			t.Logf("Uploading %s (%d bytes) through proxy using %s upload...", tc.name, tc.size, tc.uploadType)
			uploadedSize := uploadLargeFileMultipart(t, testCtx, proxyClient, testBucket, testKey, testData)

			// Verify sizes based on upload type
			if tc.uploadType == "single" {
				// Single part uploads (< 5MB) use envelope encryption and may have small overhead
				encryptionOverhead := uploadedSize - tc.size
				require.Greater(t, uploadedSize, tc.size, "Single-part encrypted file should be larger than original for %s", tc.name)
				require.Less(t, encryptionOverhead, int64(1024), "Encryption overhead should be reasonable (< 1KB) for %s, got %d bytes", tc.name, encryptionOverhead)
				t.Logf("✅ Single-part encryption: original=%d bytes, uploaded=%d bytes (overhead=%d bytes)", tc.size, uploadedSize, encryptionOverhead)
			} else {
				// Multipart uploads (>= 5MB) use streaming AES-CTR with no size overhead expected
				if tc.critical && uploadedSize != tc.size {
					t.Errorf("CRITICAL BUG DETECTED for %s: Expected %d bytes, but only %d bytes were uploaded (loss: %d bytes)",
						tc.name, tc.size, uploadedSize, tc.size-uploadedSize)
				} else if uploadedSize != tc.size {
					t.Logf("WARNING for %s: Size mismatch - Expected %d bytes, got %d bytes (diff: %d)",
						tc.name, tc.size, uploadedSize, tc.size-uploadedSize)
				} else {
					t.Logf("✅ Streaming multipart encryption: original=%d bytes, uploaded=%d bytes (no size overhead as expected)", tc.size, uploadedSize)
				}
			}

			// Verify in MinIO
			verifyFileInMinIO(t, testCtx, minioClient, testBucket, testKey, tc.size, uploadedSize)

			// Verify encryption metadata
			verifyLargeFileEncryptionMetadata(t, testCtx, minioClient, testBucket, testKey)

			// Download and verify integrity
			t.Logf("Downloading %s through proxy...", tc.name)
			downloadedData := downloadLargeFile(t, testCtx, proxyClient, testBucket, testKey)

			// Debug comparison for very small files
			if tc.size <= 100 {
				t.Logf("Data comparison for %s:", tc.name)
				t.Logf("  Original:   %x", testData)
				t.Logf("  Downloaded: %x", downloadedData)
			} else if tc.size <= Size1KB {
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
				// For larger files, show first 32 bytes and around 5MB boundary if applicable
				showBytes := min(32, len(testData))
				t.Logf("First %d bytes comparison for %s:", showBytes, tc.name)
				t.Logf("  Original:   %x", testData[:showBytes])
				t.Logf("  Downloaded: %x", downloadedData[:min(showBytes, len(downloadedData))])

				// Check around 5MB boundary for multipart files
				if tc.size >= DefaultPartSize {
					boundary := DefaultPartSize
					if boundary < len(testData) && boundary < len(downloadedData) {
						start := boundary - 16
						end := boundary + 16
						if start >= 0 && end <= len(testData) && end <= len(downloadedData) {
							t.Logf("Around 5MB boundary (bytes %d-%d) for %s:", start, end-1, tc.name)
							t.Logf("  Original:   %x", testData[start:end])
							t.Logf("  Downloaded: %x", downloadedData[start:end])
						}
					}
				}
			}

			// Verify data integrity
			verifyDataIntegrity(t, testCtx, minioClient, testBucket, testKey, originalHash, downloadedData, tc.size, tc.critical)

			// Cleanup
			cleanupTestFile(t, testCtx, proxyClient, testBucket, testKey)

			t.Logf("✅ %s completed successfully", tc.name)
		})
	}
}

// TestStreamingMultipartUpload tests multipart uploads with streaming data (simulating s3-explorer)
func TestStreamingMultipartUpload(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping streaming multipart test in short mode")
	}

	// Ensure services are available
	integration.EnsureMinIOAndProxyAvailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	// Use a fixed bucket name for easy identification and manual inspection
	testBucket := "streaming-multipart-test"

	// Create clients
	proxyClient, err := integration.CreateProxyClient()
	require.NoError(t, err, "Failed to create proxy client")

	// Setup test bucket (create and clean)
	integration.SetupTestBucket(t, ctx, proxyClient, testBucket)

	// Note: We do NOT clean up at the end to allow manual inspection
	t.Logf("📁 Test data will remain in bucket '%s' for manual inspection", testBucket)

	// Test cases for streaming uploads
	testCases := []struct {
		name        string
		size        int64
		description string
	}{
		{"1MB_streaming", Size1MB, "Small streaming test"},
		{"10MB_streaming", Size10MB, "Medium streaming test"},
		{"100MB_streaming", Size100MB, "Large streaming test"},
		{"1GB_streaming", Size1GB, "Very large streaming test"},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			testCtx, cancel := context.WithTimeout(ctx, 20*time.Minute)
			defer cancel()

			t.Logf("=== Starting %s test (%s) ===", tc.name, tc.description)
			t.Logf("File size: %d bytes (%.2f MB)", tc.size, float64(tc.size)/(1024*1024))

			objectKey := fmt.Sprintf("streaming-test-file-%s", tc.name)

			// Upload using streaming multipart
			_, actualSize := uploadLargeFileStreaming(t, testCtx, proxyClient, testBucket, objectKey, tc.size)

			// Verify size - account for encryption overhead on small files
			// Files < 5MB use AES-GCM (via regular PUT) which adds encryption overhead
			// Files >= 5MB use AES-CTR (via multipart) which has no overhead
			isSmallFile := tc.size < DefaultPartSize
			if isSmallFile {
				// For small files, allow reasonable encryption overhead (typically 16-32 bytes for AES-GCM)
				sizeDiff := actualSize - tc.size
				if sizeDiff < 0 || sizeDiff > 64 {
					t.Errorf("Size verification failed for small file: expected %d bytes + encryption overhead (got %d bytes, diff: %d)",
						tc.size, actualSize, sizeDiff)
				} else {
					t.Logf("✓ Size verification passed for small file: %d bytes + %d bytes encryption overhead", tc.size, sizeDiff)
				}
			} else {
				// For large files (multipart), expect exact size match
				if actualSize != tc.size {
					t.Errorf("Size mismatch for large file: expected %d bytes, got %d bytes (loss: %d bytes)",
						tc.size, actualSize, tc.size-actualSize)
				} else {
					t.Logf("✓ Size verification passed for large file: %d bytes", actualSize)
				}
			}

			// Create a FRESH StreamingReader for verification (the uploaded one is already consumed)
			freshStreamingReader := NewStreamingReader(tc.size, 64*1024)

			// Get MinIO client for encryption validation
			minioClient, err := integration.CreateMinIOClient()
			require.NoError(t, err, "Failed to create MinIO client for verification")

			verifyDataIntegrityStreaming(t, testCtx, proxyClient, minioClient, testBucket, objectKey, freshStreamingReader, tc.size)

			// Additional MinIO verification
			verifyMinIODirectAccess(t, testCtx, minioClient, testBucket, objectKey, tc.size, actualSize, isSmallFile)

			t.Logf("=== Completed %s test ===\n", tc.name)
		})
	}
}

// TestMultipartUploadCorruption specifically tests the reported 1GB corruption issue
func TestMultipartUploadCorruption(t *testing.T) {
	// This test specifically reproduces the reported issue
	integration.EnsureMinIOAndProxyAvailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()

	// Use a fixed bucket name for easy identification and manual inspection
	testBucket := "corruption-test"

	// Create clients
	minioClient, err := integration.CreateMinIOClient()
	require.NoError(t, err, "Failed to create MinIO client")

	proxyClient, err := integration.CreateProxyClient()
	require.NoError(t, err, "Failed to create Proxy client")

	// Setup test bucket (create and clean)
	integration.SetupTestBucket(t, ctx, proxyClient, testBucket)

	// Note: We do NOT clean up at the end to allow manual inspection
	t.Logf("📁 Test data will remain in bucket '%s' for manual inspection", testBucket)

	// Test the specific problematic size (1GB)
	testSize := int64(Size1GB)
	testKey := "corruption-test-1gb"

	t.Logf("Testing corruption issue with 1GB file...")

	// Generate test data
	testData, originalHash := generateLargeFileTestData(t, testSize)

	// Upload through proxy
	uploadedSize := uploadLargeFileMultipart(t, ctx, proxyClient, testBucket, testKey, testData)

	// Document the issue
	t.Logf("ISSUE REPRODUCTION:")
	t.Logf("  Expected upload size: %d bytes", testSize)
	t.Logf("  Actual upload size: %d bytes", uploadedSize)
	t.Logf("  Loss: %d bytes (%.2f%%)", testSize-uploadedSize, float64(testSize-uploadedSize)/float64(testSize)*100)

	// Check what MinIO actually received
	headResult, err := minioClient.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(testBucket),
		Key:    aws.String(testKey),
	})
	require.NoError(t, err, "Failed to get object from MinIO")

	minioSize := *headResult.ContentLength
	t.Logf("  MinIO stored size: %d bytes", minioSize)

	// This should demonstrate the bug
	if uploadedSize != testSize {
		t.Logf("🐛 BUG CONFIRMED: Multipart upload lost %d bytes", testSize-uploadedSize)

		// Check if it matches the reported value
		expectedBuggedSize := int64(597346816) // From user report
		if uploadedSize == expectedBuggedSize {
			t.Logf("🎯 EXACT MATCH: Upload size matches reported bug value (%d bytes)", expectedBuggedSize)
		}
	}

	// Download and check what we can recover
	downloadedData := downloadLargeFile(t, ctx, proxyClient, testBucket, testKey)
	downloadedHash := sha256.Sum256(downloadedData)

	t.Logf("RECOVERY TEST:")
	t.Logf("  Downloaded size: %d bytes", len(downloadedData))
	t.Logf("  Hash matches: %t", originalHash == downloadedHash)

	// This test documents the bug but doesn't fail - it's for investigation
	t.Logf("Test completed - bug reproduction documented")
}

// generateLargeFileTestData creates deterministic Lorem Ipsum test data of specified size
// Creates intentionally low-entropy, readable data that should clearly appear unencrypted
func generateLargeFileTestData(t *testing.T, size int64) ([]byte, [32]byte) {
	t.Helper()

	// Use our Lorem Ipsum generator for predictable, readable test data
	return integration.GenerateLoremIpsumData(t, size)
}

// uploadLargeFileMultipart uploads a large file using multipart upload
func uploadLargeFileMultipart(t *testing.T, ctx context.Context, client *s3.Client, bucket, key string, data []byte) int64 {
	t.Helper()

	// Create multipart uploader
	uploader := manager.NewUploader(client, func(u *manager.Uploader) {
		u.PartSize = DefaultPartSize
		u.Concurrency = 3 // Reduce concurrency to avoid overwhelming the proxy
	})

	// Upload the file
	reader := bytes.NewReader(data)
	startTime := time.Now()

	result, err := uploader.Upload(ctx, &s3.PutObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
		Body:   reader,
	})

	uploadDuration := time.Since(startTime)
	require.NoError(t, err, "Multipart upload failed")

	// Log upload details
	expectedSize := int64(len(data))
	t.Logf("Upload completed: Location=%s, Duration=%v, ExpectedSize=%d bytes",
		aws.ToString(&result.Location), uploadDuration, expectedSize)

	// Get object info to verify actual uploaded size
	headResult, err := client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	require.NoError(t, err, "Failed to get object metadata")

	actualSize := *headResult.ContentLength
	t.Logf("Actual uploaded size: %d bytes (Expected: %d bytes)", actualSize, expectedSize)

	return actualSize
}

// StreamingReader simulates a streaming data source that generates data on-demand
type StreamingReader struct {
	totalSize    int64
	currentPos   int64
	chunkSize    int
	originalHash []byte // Pre-calculated hash for verification
}

// NewStreamingReader creates a streaming reader that generates deterministic data
func NewStreamingReader(totalSize int64, chunkSize int) *StreamingReader {
	// Pre-calculate hash by generating the data once
	hasher := sha256.New()
	remaining := totalSize
	pos := int64(0)

	for remaining > 0 {
		currentChunkSize := int64(chunkSize)
		if remaining < currentChunkSize {
			currentChunkSize = remaining
		}

		chunk := integration.GenerateLoremIpsumPattern(pos, int(currentChunkSize))
		hasher.Write(chunk)

		remaining -= currentChunkSize
		pos += currentChunkSize
	}

	return &StreamingReader{
		totalSize:    totalSize,
		currentPos:   0,
		chunkSize:    chunkSize,
		originalHash: hasher.Sum(nil),
	}
}

// Read implements io.Reader - generates data on demand
func (sr *StreamingReader) Read(p []byte) (n int, err error) {
	if sr.currentPos >= sr.totalSize {
		return 0, io.EOF
	}

	// Calculate how much we can read
	remaining := sr.totalSize - sr.currentPos
	readSize := int64(len(p))
	if readSize > remaining {
		readSize = remaining
	}

	// Generate deterministic data for this position
	data := integration.GenerateLoremIpsumPattern(sr.currentPos, int(readSize))
	copy(p, data)

	sr.currentPos += readSize
	return int(readSize), nil
}

// GetOriginalHash returns the pre-calculated hash of all data
func (sr *StreamingReader) GetOriginalHash() []byte {
	return sr.originalHash
}

// uploadLargeFileStreaming uploads a large file using streaming multipart upload (like s3-explorer)
func uploadLargeFileStreaming(t *testing.T, ctx context.Context, client *s3.Client, bucket, key string, size int64) (*StreamingReader, int64) {
	t.Helper()

	// Create streaming reader (generates data on-demand)
	streamingReader := NewStreamingReader(size, 64*1024) // 64KB chunks like typical browsers

	// Create multipart uploader with streaming-friendly settings
	uploader := manager.NewUploader(client, func(u *manager.Uploader) {
		u.PartSize = DefaultPartSize // 5MB parts
		u.Concurrency = 1            // Single-threaded to better simulate browser behavior
		u.LeavePartsOnError = false  // Clean up failed uploads
	})

	startTime := time.Now()
	t.Logf("Starting streaming upload of %d bytes (simulating s3-explorer behavior)...", size)

	result, err := uploader.Upload(ctx, &s3.PutObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
		Body:   streamingReader,
		Metadata: map[string]string{
			"test-method": "streaming-multipart",
			"client-type": "s3-explorer-simulation",
		},
	})

	uploadDuration := time.Since(startTime)
	require.NoError(t, err, "Streaming multipart upload failed")

	// Log upload details
	t.Logf("Streaming upload completed: Location=%s, Duration=%v, ExpectedSize=%d bytes",
		aws.ToString(&result.Location), uploadDuration, size)

	// Get object info to verify actual uploaded size
	headResult, err := client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	require.NoError(t, err, "Failed to get object metadata")

	actualSize := *headResult.ContentLength
	t.Logf("Actual uploaded size: %d bytes (Expected: %d bytes)", actualSize, size)

	return streamingReader, actualSize
}

// verifyDataIntegrityStreaming verifies data integrity for streaming uploads
func verifyDataIntegrityStreaming(t *testing.T, ctx context.Context, client *s3.Client, minioClient *s3.Client, bucket, key string, originalReader *StreamingReader, expectedSize int64) {
	t.Helper()

	t.Logf("Verifying data integrity for streaming upload: %s/%s (expected size: %d bytes)", bucket, key, expectedSize)

	// First check what the proxy reports about object size
	headResult, err := client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	require.NoError(t, err, "Failed to get object metadata")

	proxyReportedSize := *headResult.ContentLength
	t.Logf("📊 SIZE ANALYSIS:")
	t.Logf("   Expected size: %d bytes", expectedSize)
	t.Logf("   Proxy reports: %d bytes", proxyReportedSize)
	t.Logf("   Difference:    %d bytes", expectedSize-proxyReportedSize)

	// Download the object
	startTime := time.Now()
	result, err := client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	require.NoError(t, err, "Failed to download object for verification")
	defer result.Body.Close()

	// Check Content-Length header vs actual downloaded bytes
	downloadContentLength := int64(0)
	if result.ContentLength != nil {
		downloadContentLength = *result.ContentLength
		t.Logf("   Download Content-Length: %d bytes", downloadContentLength)
	}

	// Read and count actual bytes
	hasher := sha256.New()
	downloadedBytes, err := io.Copy(hasher, result.Body)
	require.NoError(t, err, "Failed to read downloaded content")

	downloadDuration := time.Since(startTime)

	t.Logf("📥 DOWNLOAD ANALYSIS:")
	t.Logf("   Content-Length header: %d bytes", downloadContentLength)
	t.Logf("   Actually downloaded:   %d bytes", downloadedBytes)
	t.Logf("   Download duration:     %v", downloadDuration)

	// Calculate the exact byte loss
	byteLoss := expectedSize - downloadedBytes
	if byteLoss != 0 {
		t.Errorf("🚨 BYTE LOSS DETECTED: %d bytes missing (%.3f%%)",
			byteLoss, float64(byteLoss)/float64(expectedSize)*100)

		// Check if it's a consistent pattern
		if byteLoss == 16 {
			t.Errorf("🎯 CONSISTENT 16-BYTE LOSS PATTERN DETECTED")
		}

		// Check if the loss is at the end
		if downloadContentLength == downloadedBytes {
			t.Errorf("📉 Data loss appears to be in stored object, not during download")
		} else {
			t.Errorf("📡 Data loss appears to be during download transmission")
		}
	}

	// Compare hashes
	downloadedHash := hasher.Sum(nil)
	originalHash := originalReader.GetOriginalHash()

	t.Logf("🔐 HASH ANALYSIS:")
	t.Logf("   Original hash:   %x", originalHash)
	t.Logf("   Downloaded hash: %x", downloadedHash)

	if !bytes.Equal(originalHash, downloadedHash) {
		t.Errorf("❌ HASH MISMATCH DETECTED! Data corruption confirmed.")
		t.Errorf("Expected hash: %x", originalHash)
		t.Errorf("Actual hash:   %x", downloadedHash)
		t.Errorf("This indicates data corruption during multipart upload/download")

		// Try to identify where the corruption happens
		if downloadedBytes < expectedSize {
			t.Errorf("💡 HYPOTHESIS: Data truncation during upload/storage (%d bytes missing)", expectedSize-downloadedBytes)
		}
	} else {
		t.Logf("✓ Hash verification successful - no data corruption detected")
	}

	// Verify byte count matches
	assert.Equal(t, expectedSize, downloadedBytes, "Downloaded byte count mismatch")

	// NEW: Since we don't have the actual downloaded data in streaming mode,
	// we'll validate that the original streaming data is unencrypted
	// This serves as a baseline check that our encryption validation works correctly
	if originalReader != nil {
		// Generate sample data matching the streaming reader's pattern
		sampleData := integration.GenerateLoremIpsumPattern(0, 1024) // Get first 1024 bytes for validation
		if len(sampleData) > 0 {
			integration.AssertDataIsNotEncrypted(t, sampleData, "Original streaming data should be unencrypted")
		}
	}

	// NEW: Verify encryption by downloading data directly from MinIO
	t.Logf("🔒 Encryption validation: Downloading data directly from MinIO...")
	minioResult, err := minioClient.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		t.Logf("WARNING: Could not download data directly from MinIO for encryption validation: %v", err)
		return
	}
	defer minioResult.Body.Close()

	minioData, err := io.ReadAll(minioResult.Body)
	if err != nil {
		t.Logf("WARNING: Could not read MinIO data for encryption validation: %v", err)
		return
	}

	minioHasher := sha256.New()
	minioHasher.Write(minioData)
	minioHash := minioHasher.Sum(nil)

	t.Logf("  MinIO data size: %d bytes", len(minioData))
	t.Logf("  MinIO data hash: %x", minioHash)
	t.Logf("  Original hash:   %x", originalHash)

	// MinIO data should be different from original (encrypted)
	if bytes.Equal(originalHash, minioHash) {
		t.Errorf("CRITICAL: Data stored in MinIO is NOT encrypted - hash matches original!")
	} else {
		t.Logf("✅ Data stored in MinIO is encrypted (hash differs from original)")
	}

	// Simple but effective encryption validation:
	// Check that MinIO data doesn't contain obvious unencrypted Lorem Ipsum patterns
	if len(minioData) > 50 {
		sampleData := string(minioData[:50]) // Check first 50 bytes
		if strings.Contains(sampleData, "Lorem ipsum") || strings.Contains(sampleData, "lorem ipsum") {
			t.Errorf("🚨 MinIO data contains recognizable Lorem Ipsum text in first 50 bytes - may not be properly encrypted!")
		} else {
			t.Logf("✅ MinIO data appears encrypted (no recognizable patterns in sample)")
		}
	} else {
		t.Logf("✅ MinIO data is small (%d bytes) - hash validation sufficient", len(minioData))
	}
}

// verifyMinIODirectAccess checks MinIO directly to isolate proxy issues
func verifyMinIODirectAccess(t *testing.T, ctx context.Context, minioClient *s3.Client, bucket, key string, expectedSize, actualSize int64, isSmallFile bool) {
	t.Helper()

	t.Logf("🔍 CHECKING MinIO DIRECTLY:")
	minioResult, err := minioClient.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err == nil {
		minioSize := *minioResult.ContentLength
		t.Logf("   MinIO stored size: %d bytes", minioSize)

		// Account for encryption overhead on small files
		if isSmallFile {
			// For small files, MinIO size should match the proxy's reported size (which includes encryption overhead)
			if minioSize != actualSize {
				t.Errorf("🔴 MinIO STORAGE MISMATCH: Expected %d bytes (proxy size), MinIO has %d bytes",
					actualSize, minioSize)
			} else {
				t.Logf("✅ MinIO storage matches proxy size for small file")
			}
		} else {
			// For large files (multipart), MinIO should store exactly the original size
			if minioSize != expectedSize {
				t.Errorf("🔴 MinIO STORAGE ISSUE: Expected %d bytes, MinIO has %d bytes (loss: %d)",
					expectedSize, minioSize, expectedSize-minioSize)
			} else {
				t.Logf("✅ MinIO storage is correct for large file")

				// CRITICAL TEST: Download directly from MinIO (bypassing proxy)
				t.Logf("🔬 DIRECT MinIO DOWNLOAD TEST:")
				directResult, err := minioClient.GetObject(ctx, &s3.GetObjectInput{
					Bucket: aws.String(bucket),
					Key:    aws.String(key),
				})
				if err == nil {
					defer directResult.Body.Close()

					// Read the actual data for encryption validation
					minioData, err := io.ReadAll(directResult.Body)
					if err == nil {
						directBytes := int64(len(minioData))
						t.Logf("   Direct MinIO download: %d bytes", directBytes)

						if directBytes == expectedSize {
							t.Logf("✅ Direct MinIO download size is correct")
						} else {
							t.Errorf("🔴 Direct MinIO download size mismatch: expected %d, got %d bytes", expectedSize, directBytes)
						}

						// Verify the data stored in MinIO is properly encrypted
						// Simple validation: check that it doesn't contain obvious unencrypted patterns
						if len(minioData) > 50 {
							sampleData := string(minioData[:50])
							if strings.Contains(sampleData, "Lorem ipsum") || strings.Contains(sampleData, "lorem ipsum") {
								t.Errorf("🚨 MinIO data contains recognizable Lorem Ipsum text - may not be properly encrypted!")
							} else {
								t.Logf("✅ MinIO data appears encrypted (no recognizable patterns)")
							}
						} else {
							t.Logf("✅ MinIO data is small (%d bytes) - assuming encrypted", len(minioData))
						}
					} else {
						t.Errorf("🔴 Failed to read MinIO data for encryption validation: %v", err)
					}
				} else {
					t.Errorf("🔴 Failed to download data directly from MinIO: %v", err)
				}
			}
		}
	}
}

// verifyFileInMinIO checks if the file exists in MinIO with correct properties
func verifyFileInMinIO(t *testing.T, ctx context.Context, minioClient *s3.Client, bucket, key string, expectedSize, actualSize int64) {
	t.Helper()

	// Get object metadata directly from MinIO
	headResult, err := minioClient.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	require.NoError(t, err, "File not found in MinIO")

	minioSize := *headResult.ContentLength
	t.Logf("MinIO reports file size: %d bytes", minioSize)

	// The size in MinIO should match what was actually uploaded through proxy
	assert.Equal(t, actualSize, minioSize, "Size mismatch between proxy upload and MinIO storage")

	// Log if there's a discrepancy with expected size
	if minioSize != expectedSize {
		t.Logf("⚠️  Size discrepancy: Expected %d bytes, MinIO has %d bytes", expectedSize, minioSize)
	}
}

// verifyLargeFileEncryptionMetadata checks that the file is properly encrypted
func verifyLargeFileEncryptionMetadata(t *testing.T, ctx context.Context, minioClient *s3.Client, bucket, key string) {
	t.Helper()

	// Get object metadata directly from MinIO
	headResult, err := minioClient.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	require.NoError(t, err, "Failed to get object metadata from MinIO")

	// Check for encryption metadata
	metadata := headResult.Metadata
	t.Logf("Object metadata: %+v", metadata)

	// Look for encryption-related metadata
	hasEncryptionMetadata := false
	for key, value := range metadata {
		if strings.Contains(strings.ToLower(key), "encrypt") ||
			strings.Contains(strings.ToLower(key), "cipher") ||
			strings.Contains(strings.ToLower(key), "algorithm") ||
			strings.Contains(strings.ToLower(key), "s3ep") {
			hasEncryptionMetadata = true
			t.Logf("Found encryption metadata: %s = %s", key, value)
		}
	}

	// Check server-side encryption
	if headResult.ServerSideEncryption != "" {
		t.Logf("Server-side encryption: %s", string(headResult.ServerSideEncryption))
		hasEncryptionMetadata = true
	}

	if !hasEncryptionMetadata {
		t.Logf("⚠️  No encryption metadata found - file may not be encrypted")
	} else {
		t.Logf("✅ Encryption metadata found - file appears to be encrypted")
	}
}

// downloadLargeFile downloads a large file and returns its content
func downloadLargeFile(t *testing.T, ctx context.Context, client *s3.Client, bucket, key string) []byte {
	t.Helper()

	startTime := time.Now()

	// Get object from proxy
	result, err := client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	require.NoError(t, err, "Failed to download object")
	defer result.Body.Close()

	// Read all data
	data, err := io.ReadAll(result.Body)
	require.NoError(t, err, "Failed to read downloaded data")

	downloadDuration := time.Since(startTime)
	t.Logf("Download completed: %d bytes in %v", len(data), downloadDuration)

	return data
}

// verifyDataIntegrity checks that downloaded data matches original data
func verifyDataIntegrity(t *testing.T, ctx context.Context, minioClient *s3.Client, bucket, key string, originalHash [32]byte, downloadedData []byte, expectedSize int64, critical bool) {
	t.Helper()

	downloadedSize := int64(len(downloadedData))
	downloadedHash := sha256.Sum256(downloadedData)

	t.Logf("Data integrity check:")
	t.Logf("  Expected size: %d bytes", expectedSize)
	t.Logf("  Downloaded size: %d bytes", downloadedSize)
	t.Logf("  Original hash: %x", originalHash)
	t.Logf("  Downloaded hash: %x", downloadedHash)

	// Check size
	if critical && downloadedSize != expectedSize {
		t.Errorf("CRITICAL: Downloaded size (%d) != expected size (%d)", downloadedSize, expectedSize)
	} else if downloadedSize != expectedSize {
		t.Logf("WARNING: Downloaded size (%d) != expected size (%d)", downloadedSize, expectedSize)
	}

	// Check hash - downloaded data should match original
	if critical && originalHash != downloadedHash {
		t.Errorf("CRITICAL: Data corruption detected - hash mismatch")
	} else if originalHash != downloadedHash {
		t.Logf("WARNING: Data corruption detected - hash mismatch")
	}

	if downloadedSize == expectedSize && originalHash == downloadedHash {
		t.Logf("✅ Data integrity verified")
	} else {
		t.Logf("❌ Data integrity issues detected")
	}

	// NEW: Verify downloaded data is NOT encrypted (should be properly decrypted by proxy)
	integration.AssertDataIsNotEncrypted(t, downloadedData, "Downloaded data should be unencrypted (decrypted by proxy)")

	// NEW: Verify encryption by downloading data directly from MinIO
	t.Logf("🔬 Encryption validation: Downloading data directly from MinIO...")
	minioResult, err := minioClient.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		t.Logf("WARNING: Could not download data directly from MinIO for encryption validation: %v", err)
		return
	}
	defer minioResult.Body.Close()

	minioData, err := io.ReadAll(minioResult.Body)
	if err != nil {
		t.Logf("WARNING: Could not read MinIO data for encryption validation: %v", err)
		return
	}

	minioHash := sha256.Sum256(minioData)
	t.Logf("  MinIO data size: %d bytes", len(minioData))
	t.Logf("  MinIO data hash: %x", minioHash)

	// MinIO data should be different from original (encrypted)
	if originalHash == minioHash {
		if critical {
			t.Errorf("CRITICAL: Data stored in MinIO is NOT encrypted - hash matches original!")
		} else {
			t.Logf("WARNING: Data stored in MinIO is NOT encrypted - hash matches original!")
		}
	} else {
		t.Logf("✅ Data stored in MinIO is encrypted (hash differs from original)")
	}

	// Simple but effective encryption validation:
	// Check that MinIO data doesn't contain obvious unencrypted Lorem Ipsum patterns
	if len(minioData) > 50 {
		sampleData := string(minioData[:50])
		if strings.Contains(sampleData, "Lorem ipsum") || strings.Contains(sampleData, "lorem ipsum") {
			if critical {
				t.Errorf("🚨 CRITICAL: MinIO data contains recognizable Lorem Ipsum text - may not be properly encrypted!")
			} else {
				t.Logf("WARNING: MinIO data contains recognizable Lorem Ipsum text - may not be properly encrypted!")
			}
		} else {
			t.Logf("✅ MinIO data appears encrypted (no recognizable patterns in sample)")
		}
	} else {
		t.Logf("✅ MinIO data is small (%d bytes) - hash validation sufficient", len(minioData))
	}
}

// cleanupTestFile removes the test file
func cleanupTestFile(t *testing.T, ctx context.Context, client *s3.Client, bucket, key string) {
	t.Helper()

	_, err := client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		t.Logf("Warning: Failed to cleanup test file %s: %v", key, err)
	}
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// max returns the maximum of two integers
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
