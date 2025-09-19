//go:build integration
// +build integration

package integration

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/stretchr/testify/require"

	// Import helper functions from the main integration package
	. "github.com/guided-traffic/s3-encryption-proxy/test/integration"
)

// TestLargeMultipartDownload500MB tests downloading a 500MB file that was uploaded via multipart
// This test expects the object to exist from TestLargeMultipartUpload500MB
// This test is designed to run independently to allow separate memory profiling
func TestLargeMultipartDownload500MB(t *testing.T) {
	if os.Getenv("INTEGRATION_TEST") == "" {
		t.Skip("Skipping integration test. Set INTEGRATION_TEST=1 to run.")
	}

	// Initial memory usage check for monitoring
	var memStats runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&memStats)

	t.Logf("Starting 500MB download test - Initial memory usage: %d MB",
		memStats.Alloc/(1024*1024))

	// Create context with timeout for large file operations (10 minutes)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	// Use test context with timeout
	tc := NewTestContextWithTimeout(t, ctx)
	// DON'T cleanup bucket - we expect it to exist from upload test

	// Use the same shared bucket name as the upload test
	tc.TestBucket = "large-multipart-tests-500mb"
	// Ensure bucket exists (in case upload test wasn't run)
	tc.EnsureTestBucket()

	bucketName := tc.TestBucket
	// Use the same object key pattern as the upload test
	objectKey := "large-multipart-500mb-test"

	startTime := time.Now()

	t.Run("Download_500MB_Streaming_Verification", func(t *testing.T) {
		// Memory check before download
		runtime.GC()
		runtime.ReadMemStats(&memStats)
		t.Logf("Download starting - Memory usage: %d MB", memStats.Alloc/(1024*1024))

		// Step 1: Verify object exists and get metadata
		headResp, err := tc.ProxyClient.HeadObject(ctx, &s3.HeadObjectInput{
			Bucket: aws.String(bucketName),
			Key:    aws.String(objectKey),
		})
		require.NoError(t, err, "Failed to get object metadata - make sure TestLargeMultipartUpload500MB was run first")
		require.Equal(t, int64(LargeFileSize500MB), *headResp.ContentLength,
			"Object size should be 500MB")

		t.Logf("Object exists with size: %d bytes", *headResp.ContentLength)

		// Step 2: Download and verify using streaming approach
		getResp, err := tc.ProxyClient.GetObject(ctx, &s3.GetObjectInput{
			Bucket: aws.String(bucketName),
			Key:    aws.String(objectKey),
		})
		require.NoError(t, err, "Failed to start object download")
		defer getResp.Body.Close()

		// Step 3: Stream download with verification using deterministic data generation
		actualHash := sha256.New()
		totalBytesRead := int64(0)
		bufferSize := 1024 * 1024 // 1MB read buffer
		readBuffer := make([]byte, bufferSize)

		// Generate expected hash by recreating the same data that was uploaded
		expectedHashSum := calculateExpectedHash()

		for {
			// Memory check during download
			if totalBytesRead%(100*1024*1024) == 0 && totalBytesRead > 0 { // Every 100MB
				runtime.GC()
				runtime.ReadMemStats(&memStats)
				t.Logf("Downloaded %d MB - Memory usage: %d MB",
					totalBytesRead/(1024*1024), memStats.Alloc/(1024*1024))
			}

			// Read chunk from download stream
			n, err := getResp.Body.Read(readBuffer)
			if n > 0 {
				actualData := readBuffer[:n]
				actualHash.Write(actualData)
				totalBytesRead += int64(n)
			}

			if err == io.EOF {
				break
			}
			require.NoError(t, err, "Error reading download stream")
		}

		downloadDuration := time.Since(startTime)
		throughputMBps := float64(totalBytesRead) / (1024 * 1024) / downloadDuration.Seconds()

		t.Logf("Download completed - Read %d bytes in %v (%.2f MB/s)",
			totalBytesRead, downloadDuration, throughputMBps)

		// Step 4: Verify total size and data integrity
		require.Equal(t, int64(LargeFileSize500MB), totalBytesRead,
			"Downloaded size should match expected size")

		// Compare SHA256 hashes
		actualHashSum := fmt.Sprintf("%x", actualHash.Sum(nil))

		require.Equal(t, expectedHashSum, actualHashSum,
			"Downloaded data SHA256 hash should match expected hash")

		t.Logf("Data integrity verified - SHA256: %s", actualHashSum)

		// Final memory check
		runtime.GC()
		runtime.ReadMemStats(&memStats)
		t.Logf("Download completed - Final memory usage: %d MB", memStats.Alloc/(1024*1024))
	})
}

// calculateExpectedHash recreates the exact same hash calculation as in the upload test
func calculateExpectedHash() string {
	hash := sha256.New()
	seed := int64(12345) // Same seed used during upload

	// Calculate number of parts needed
	numParts := (LargeFileSize500MB + MultipartPartSize - 1) / MultipartPartSize

	// Generate hash for each part using the same logic as upload test
	for partNum := 1; partNum <= numParts; partNum++ {
		// Calculate part size (last part may be smaller)
		currentPartSize := MultipartPartSize
		if partNum == numParts {
			remaining := LargeFileSize500MB - (int64(partNum-1) * MultipartPartSize)
			if remaining < MultipartPartSize {
				currentPartSize = int(remaining)
			}
		}

		// Generate deterministic data for this part using seed + partNum (same as upload)
		partData := generateDeterministicData(currentPartSize, seed+int64(partNum))
		hash.Write(partData)
	}

	return fmt.Sprintf("%x", hash.Sum(nil))
}
