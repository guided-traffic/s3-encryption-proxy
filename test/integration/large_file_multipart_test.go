//go:build integration
// +build integration

package integration

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
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	// File sizes for testing
	Size10MB  = 10 * 1024 * 1024   // 10 MB
	Size100MB = 100 * 1024 * 1024  // 100 MB
	Size1GB   = 1024 * 1024 * 1024 // 1 GB

	// Multipart upload settings
	DefaultPartSize = 5 * 1024 * 1024 // 5 MB minimum part size
	MaxParts        = 10000
)

// TestLargeFileMultipartUpload tests multipart upload behavior with various file sizes
func TestLargeFileMultipartUpload(t *testing.T) {
	// Ensure services are available
	EnsureMinIOAndProxyAvailable(t)

	ctx := context.Background()
	testBucket := fmt.Sprintf("large-file-test-%d", time.Now().Unix())

	// Create clients
	minioClient, err := createMinIOClient()
	require.NoError(t, err, "Failed to create MinIO client")

	proxyClient, err := createProxyClient()
	require.NoError(t, err, "Failed to create Proxy client")

	// Setup test bucket
	_, err = proxyClient.CreateBucket(ctx, &s3.CreateBucketInput{
		Bucket: aws.String(testBucket),
	})
	require.NoError(t, err, "Failed to create test bucket")

	// Cleanup
	defer func() {
		CleanupTestBucket(t, proxyClient, testBucket)
	}()

	// Test cases with different file sizes
	testCases := []struct {
		name     string
		size     int64
		timeout  time.Duration
		critical bool // If true, test failure indicates critical bug
	}{
		{
			name:     "10MB file",
			size:     Size10MB,
			timeout:  2 * time.Minute,
			critical: false,
		},
		{
			name:     "100MB file",
			size:     Size100MB,
			timeout:  5 * time.Minute,
			critical: true, // This should always work
		},
		{
			name:     "1GB file",
			size:     Size1GB,
			timeout:  15 * time.Minute,
			critical: true, // This is failing according to the issue
		},
	}

	for _, tc := range testCases {
		tc := tc // capture loop variable
		t.Run(tc.name, func(t *testing.T) {
			testCtx, cancel := context.WithTimeout(ctx, tc.timeout)
			defer cancel()

			// Generate test data
			t.Logf("Generating %d bytes of random data...", tc.size)
			testData, originalHash := generateLargeFileTestData(t, tc.size) // Test key
			testKey := fmt.Sprintf("test-file-%d-bytes", tc.size)

			// Upload through proxy using multipart
			t.Logf("Uploading %s through proxy...", tc.name)
			uploadedSize := uploadLargeFileMultipart(t, testCtx, proxyClient, testBucket, testKey, testData)

			// Verify uploaded size matches expected
			if tc.critical && uploadedSize != tc.size {
				t.Errorf("CRITICAL BUG DETECTED: Expected %d bytes, but only %d bytes were uploaded", tc.size, uploadedSize)
			} else if uploadedSize != tc.size {
				t.Logf("WARNING: Size mismatch - Expected %d bytes, got %d bytes", tc.size, uploadedSize)
			}

			// Verify file exists in MinIO with correct size
			verifyFileInMinIO(t, testCtx, minioClient, testBucket, testKey, tc.size, uploadedSize)

			// Verify encryption metadata
			verifyLargeFileEncryptionMetadata(t, testCtx, minioClient, testBucket, testKey) // Download through proxy and verify integrity
			t.Logf("Downloading %s through proxy...", tc.name)
			downloadedData := downloadLargeFile(t, testCtx, proxyClient, testBucket, testKey)

			// Verify data integrity
			verifyDataIntegrity(t, originalHash, downloadedData, tc.size, tc.critical)

			// Cleanup test file
			cleanupTestFile(t, testCtx, proxyClient, testBucket, testKey)

			t.Logf("✅ %s test completed", tc.name)
		})
	}
}

// generateLargeFileTestData creates random test data of specified size
func generateLargeFileTestData(t *testing.T, size int64) ([]byte, [32]byte) {
	t.Helper()

	// Use fixed seed for deterministic test data
	rng := mathrand.New(mathrand.NewSource(12345))

	data := make([]byte, size)

	// For very large files, generate data in chunks to avoid memory issues
	chunkSize := 1024 * 1024 // 1MB chunks
	for offset := int64(0); offset < size; {
		remainingSize := size - offset
		currentChunkSize := int64(chunkSize)
		if remainingSize < currentChunkSize {
			currentChunkSize = remainingSize
		}

		chunk := data[offset : offset+currentChunkSize]
		// Use manual byte generation instead of rng.Read() for true determinism
		for i := range chunk {
			chunk[i] = byte(rng.Int())
		}

		offset += currentChunkSize
	}

	// Calculate hash of original data
	hash := sha256.Sum256(data)

	t.Logf("Generated %d bytes of test data (SHA256: %x)", size, hash)
	return data, hash
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

		chunk := generateDeterministicChunk(pos, int(currentChunkSize))
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
	data := generateDeterministicChunk(sr.currentPos, int(readSize))
	copy(p, data)

	sr.currentPos += readSize
	return int(readSize), nil
}

// GetOriginalHash returns the pre-calculated hash of all data
func (sr *StreamingReader) GetOriginalHash() []byte {
	return sr.originalHash
}

// generateDeterministicChunk generates deterministic data based on position
// Fixed: Ensures byte-by-byte consistency regardless of chunk boundaries
func generateDeterministicChunk(position int64, size int) []byte {
	data := make([]byte, size)

	for i := 0; i < size; i++ {
		// Generate each byte individually based on its absolute position
		bytePosition := position + int64(i)

		// Simple but effective deterministic byte generation
		// Each byte is determined solely by its absolute position in the file
		seed := bytePosition
		seed = (seed*1103515245 + 12345) & 0x7fffffff
		data[i] = byte(seed >> 16)
	}

	return data
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
func verifyDataIntegrityStreaming(t *testing.T, ctx context.Context, client *s3.Client, bucket, key string, originalReader *StreamingReader, expectedSize int64) {
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
}

// TestLargeFileMultipartStreaming tests multipart uploads with streaming data (simulating s3-explorer)
func TestLargeFileMultipartStreaming(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping large file streaming test in short mode")
	}

	ctx := context.Background()

	// Setup test environment
	proxyClient, err := createProxyClient()
	require.NoError(t, err, "Failed to create proxy client")

	bucketName := fmt.Sprintf("large-file-streaming-test-%d", time.Now().Unix())

	// Create bucket
	_, err = proxyClient.CreateBucket(ctx, &s3.CreateBucketInput{
		Bucket: aws.String(bucketName),
	})
	require.NoError(t, err, "Failed to create test bucket")

	// Clean up
	defer func() {
		// List and delete all objects in bucket
		listResult, _ := proxyClient.ListObjects(ctx, &s3.ListObjectsInput{
			Bucket: aws.String(bucketName),
		})
		if listResult != nil && listResult.Contents != nil {
			for _, obj := range listResult.Contents {
				proxyClient.DeleteObject(ctx, &s3.DeleteObjectInput{
					Bucket: aws.String(bucketName),
					Key:    obj.Key,
				})
			}
		}
		// Delete bucket
		proxyClient.DeleteBucket(ctx, &s3.DeleteBucketInput{
			Bucket: aws.String(bucketName),
		})
	}()

	testCases := []struct {
		name        string
		size        int64
		description string
	}{
		{"1MB_streaming", 1 * 1024 * 1024, "Small streaming test - should work"},
		{"10MB_streaming", 10 * 1024 * 1024, "Medium streaming test - may show corruption"},
		{"100MB_streaming", 100 * 1024 * 1024, "Large streaming test - likely to show corruption"},
		{"1GB_streaming", 1024 * 1024 * 1024, "Very large streaming test - definite corruption expected"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Logf("=== Starting %s test (%s) ===", tc.name, tc.description)
			t.Logf("File size: %d bytes (%.2f MB)", tc.size, float64(tc.size)/(1024*1024))

			objectKey := fmt.Sprintf("streaming-test-file-%s", tc.name)

			// Upload using streaming multipart
			_, actualSize := uploadLargeFileStreaming(t, ctx, proxyClient, bucketName, objectKey, tc.size)

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
					t.Errorf("Size mismatch for large file: expected %d bytes, got %d bytes", tc.size, actualSize)
				} else {
					t.Logf("✓ Size verification passed for large file: %d bytes", actualSize)
				}
			}

			// Create a FRESH StreamingReader for verification (the uploaded one is already consumed)
			freshStreamingReader := NewStreamingReader(tc.size, 64*1024)
			verifyDataIntegrityStreaming(t, ctx, proxyClient, bucketName, objectKey, freshStreamingReader, tc.size)

			// ADDITIONAL DEBUG: Check what MinIO actually has stored
			minioClient, err := createMinIOClient()
			if err == nil {
				t.Logf("🔍 CHECKING MinIO DIRECTLY:")
				minioResult, err := minioClient.HeadObject(ctx, &s3.HeadObjectInput{
					Bucket: aws.String(bucketName),
					Key:    aws.String(objectKey),
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
						if minioSize != tc.size {
							t.Errorf("🔴 MinIO STORAGE ISSUE: Expected %d bytes, MinIO has %d bytes (loss: %d)",
								tc.size, minioSize, tc.size-minioSize)
						} else {
							t.Logf("✅ MinIO storage is correct for large file")

							// CRITICAL TEST: Download directly from MinIO (bypassing proxy)
							t.Logf("🔬 DIRECT MinIO DOWNLOAD TEST:")
							directResult, err := minioClient.GetObject(ctx, &s3.GetObjectInput{
								Bucket: aws.String(bucketName),
								Key:    aws.String(objectKey),
							})
							if err == nil {
								defer directResult.Body.Close()
								directBytes, err := io.Copy(io.Discard, directResult.Body)
								if err == nil {
									t.Logf("   Direct MinIO download: %d bytes", directBytes)
									if directBytes == tc.size {
										t.Logf("✅ Direct MinIO download is PERFECT - confirms proxy download bug")
								} else {
									t.Errorf("🔴 Even direct MinIO download is corrupted: %d bytes", directBytes)
								}
							}
						}
					}
				}
				}
			}

			t.Logf("=== Completed %s test ===\n", tc.name)
		})
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
			strings.Contains(strings.ToLower(key), "algorithm") {
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
func verifyDataIntegrity(t *testing.T, originalHash [32]byte, downloadedData []byte, expectedSize int64, critical bool) {
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

	// Check hash
	if critical && originalHash != downloadedHash {
		t.Errorf("CRITICAL: Data corruption detected - hash mismatch")
	} else if originalHash != downloadedHash {
		t.Logf("WARNING: Data corruption detected - hash mismatch")
	}

	if downloadedSize == expectedSize && originalHash == downloadedHash {
		t.Logf("✅ Data integrity verified: perfect match")
	} else {
		t.Logf("❌ Data integrity issues detected")
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

// TestMultipartUploadCorruption specifically tests the reported 1GB corruption issue
func TestMultipartUploadCorruption(t *testing.T) {
	// This test specifically reproduces the reported issue
	EnsureMinIOAndProxyAvailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()

	testBucket := fmt.Sprintf("corruption-test-%d", time.Now().Unix())

	// Create clients
	minioClient, err := createMinIOClient()
	require.NoError(t, err, "Failed to create MinIO client")

	proxyClient, err := createProxyClient()
	require.NoError(t, err, "Failed to create Proxy client")

	// Setup test bucket
	_, err = proxyClient.CreateBucket(ctx, &s3.CreateBucketInput{
		Bucket: aws.String(testBucket),
	})
	require.NoError(t, err, "Failed to create test bucket")

	defer func() {
		CleanupTestBucket(t, proxyClient, testBucket)
	}()

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
