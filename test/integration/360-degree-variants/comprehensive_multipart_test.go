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

	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption/dataencryption"
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

			// Use timestamp to prevent test caching
			testKey := fmt.Sprintf("test-%s-%d-bytes-%d", strings.ReplaceAll(tc.name, " ", "-"), tc.size, time.Now().UnixNano()) // Upload through proxy
			t.Logf("Uploading %s (%d bytes) through proxy using %s upload...", tc.name, tc.size, tc.uploadType)
			uploadedSize := uploadLargeFileMultipart(t, testCtx, proxyClient, testBucket, testKey, testData)

			// The proxy reports plaintext sizes on every upload path. A byte lost
			// on the way through is what this suite exists to catch, so the check
			// is an exact match rather than a warning.
			if tc.critical {
				require.Equalf(t, tc.size, uploadedSize,
					"the proxy reports %d bytes for a %d byte upload of %s: bytes were lost",
					uploadedSize, tc.size, tc.name)
			} else {
				assert.Equalf(t, tc.size, uploadedSize,
					"the proxy reports %d bytes for a %d byte upload of %s", uploadedSize, tc.size, tc.name)
			}

			// Only the backend sees the encryption overhead, and it is the same
			// on every path: the segment chain adds 68 bytes per 64 KiB segment
			// and a 40-byte trailer, whether the object came in one request or
			// through a multipart upload (ADR 0003).
			verifyFileInMinIO(t, testCtx, minioClient, testBucket, testKey, tc.size)

			// Verify encryption metadata
			verifySegmentedObjectMetadata(t, testCtx, minioClient, testBucket, testKey)

			// Download and verify integrity
			t.Logf("Downloading %s through proxy...", tc.name)
			downloadedData := downloadLargeFile(t, testCtx, proxyClient, testBucket, testKey)

			// The comparison is the SHA-256 below. Dumping the payloads here printed
			// plaintext for every object on the success path, every run (WORK ORDER 1).
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

			// Use timestamp to prevent test caching
			objectKey := fmt.Sprintf("streaming-test-file-%s-%d", tc.name, time.Now().UnixNano()) // Upload using streaming multipart
			_, actualSize := uploadLargeFileStreaming(t, testCtx, proxyClient, testBucket, objectKey, tc.size)

			// Verify size - the stored object carries the segment chain's framing
			// on every path (ADR 0003). Below the part size it arrives as one
			// request, above it through the proxy's own multipart upload; the
			// overhead is the same either way.
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
			verifyMinIODirectAccess(t, testCtx, minioClient, testBucket, objectKey, tc.size)

			t.Logf("=== Completed %s test ===\n", tc.name)
		})
	}
}

// TestMultipartUploadCorruption is the regression test for the 1 GB multipart
// upload that used to store fewer bytes than it received and read back as a
// different object. It was written as an investigation script - every finding a
// t.Logf, nothing that could fail - so the bug it is named for could return
// under a green run. It now asserts the three things that were wrong: the bytes
// the upload accepted, the bytes MinIO holds, and the bytes that come back.
func TestMultipartUploadCorruption(t *testing.T) {
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

	require.Equal(t, testSize, uploadedSize,
		"the upload accepted fewer bytes than it was given: %d missing", testSize-uploadedSize)

	// What the backend really holds. It is the sealed chain, so it is longer
	// than the plaintext by exactly what the format adds, and a stored length
	// the format could not have produced is the corruption this test is named
	// for arriving at the backend.
	headResult, err := minioClient.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(testBucket),
		Key:    aws.String(testKey),
	})
	require.NoError(t, err, "Failed to get object from MinIO")

	minioSize := *headResult.ContentLength
	expectedStored, err := dataencryption.CiphertextSize(testSize)
	require.NoError(t, err)
	assert.Equal(t, expectedStored, minioSize,
		"the stored object is not the chain %d plaintext bytes seal to", testSize)

	downloadedData := downloadLargeFile(t, ctx, proxyClient, testBucket, testKey)
	downloadedHash := sha256.Sum256(downloadedData)

	require.Equal(t, testSize, int64(len(downloadedData)), "the object read back short")
	require.Equal(t, originalHash, downloadedHash,
		"the object read back is not the object that was uploaded")
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
	// Reading the stored bytes IS the encryption-at-rest assertion. Logging a
	// warning and returning made every way this read can fail - a wrong key, a
	// missing object, a closed backend - into a pass, and this is the only place
	// the suite looks at what the backend actually holds.
	require.NoError(t, err, "the stored object must be readable directly from MinIO")
	defer minioResult.Body.Close()

	minioData, err := io.ReadAll(minioResult.Body)
	require.NoError(t, err, "the stored bytes must be readable for the encryption check")

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

// verifyMinIODirectAccess reads the object straight from the backend, which is
// the only place the stored bytes can be seen. There is no size fork any more:
// every object is one segment chain, whichever write path produced it, and its
// stored length is a pure function of its plaintext length.
func verifyMinIODirectAccess(t *testing.T, ctx context.Context, minioClient *s3.Client, bucket, key string, plaintextSize int64) {
	t.Helper()

	t.Logf("🔍 CHECKING MinIO DIRECTLY:")
	minioResult, err := minioClient.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	require.NoError(t, err, "Failed to read the stored object metadata")

	minioSize := aws.ToInt64(minioResult.ContentLength)
	t.Logf("   MinIO stored size: %d bytes (plaintext: %d)", minioSize, plaintextSize)
	require.Equal(t, segStoredSize(plaintextSize), minioSize,
		"the stored object is not the length the segment chain prescribes for %d plaintext bytes", plaintextSize)

	directResult, err := minioClient.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	require.NoError(t, err, "Failed to download data directly from MinIO")
	defer directResult.Body.Close()

	minioData, err := io.ReadAll(directResult.Body)
	require.NoError(t, err, "Failed to read MinIO data for encryption validation")
	require.Equal(t, segStoredSize(plaintextSize), int64(len(minioData)),
		"the body the backend serves is not the length it reported")

	// The plaintext is Lorem Ipsum, so a readable run of it in the stored bytes
	// is encryption not having happened.
	if len(minioData) > 50 {
		sample := string(minioData[:50])
		require.NotContains(t, strings.ToLower(sample), "lorem ipsum",
			"the stored object starts with recognisable plaintext")
	}
}

// verifyFileInMinIO checks the object as it is actually stored. The proxy
// reports plaintext sizes, so the framing is only visible here. A multipart
// object is the same chain as a single-request one - the part boundaries the
// client chose leave no trace in it - so it is the same arithmetic.
func verifyFileInMinIO(t *testing.T, ctx context.Context, minioClient *s3.Client, bucket, key string, plaintextSize int64) {
	t.Helper()

	headResult, err := minioClient.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	require.NoError(t, err, "File not found in MinIO")

	storedSize := aws.ToInt64(headResult.ContentLength)
	t.Logf("MinIO reports stored size: %d bytes (plaintext: %d)", storedSize, plaintextSize)

	require.Equal(t, segStoredSize(plaintextSize), storedSize,
		"the stored object is not the length the segment chain prescribes for %d plaintext bytes", plaintextSize)
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
	// Reading the stored bytes IS the encryption-at-rest assertion. Logging a
	// warning and returning made every way this read can fail - a wrong key, a
	// missing object, a closed backend - into a pass, and this is the only place
	// the suite looks at what the backend actually holds.
	require.NoError(t, err, "the stored object must be readable directly from MinIO")
	defer minioResult.Body.Close()

	minioData, err := io.ReadAll(minioResult.Body)
	require.NoError(t, err, "the stored bytes must be readable for the encryption check")

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
