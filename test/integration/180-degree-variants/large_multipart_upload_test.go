//go:build integration
// +build integration

package integration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"runtime"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/stretchr/testify/require"

	// Import helper functions from the main integration package
	. "github.com/guided-traffic/s3-encryption-proxy/test/integration"
)

// TestLargeMultipart500MB tests uploading and downloading a 500MB file using multipart upload
// This is a combined test to ensure upload runs before download
func TestLargeMultipart500MB(t *testing.T) {
	// Initial memory usage check for monitoring
	var memStats runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&memStats)

	t.Logf("Starting 500MB multipart upload/download test - Initial memory usage: %d MB",
		memStats.Alloc/(1024*1024))

	// Create context with timeout for large file operations (15 minutes for upload + download)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	// Use test context with timeout
	tc := NewTestContextWithTimeout(t, ctx)
	// Cleanup bucket after the combined test
	defer tc.CleanupTestBucket()

	// Use a shared bucket name
	tc.TestBucket = "large-multipart-tests-500mb"
	tc.EnsureTestBucket()

	bucketName := tc.TestBucket
	objectKey := "large-multipart-500mb-test"

	// Variable to store expected hash from upload for download verification
	var expectedHash string

	// Step 1: Upload test
	t.Run("Upload_500MB_Multipart_AES_CTR", func(t *testing.T) {
		startTime := time.Now()
		// Generate a deterministic seed for reproducible test data
		seed := int64(12345)

		// Calculate number of parts needed
		numParts := (LargeFileSize500MB + MultipartPartSize - 1) / MultipartPartSize
		t.Logf("Uploading 500MB file in %d parts of %d MB each", numParts, MultipartPartSize/(1024*1024))

		// Initiate multipart upload
		createResp, err := tc.ProxyClient.CreateMultipartUpload(tc.Ctx, &s3.CreateMultipartUploadInput{
			Bucket: aws.String(bucketName),
			Key:    aws.String(objectKey),
		})
		require.NoError(t, err, "Failed to initiate multipart upload")
		require.NotNil(t, createResp.UploadId, "Upload ID should not be nil")

		uploadID := *createResp.UploadId
		t.Logf("Created multipart upload with ID: %s", uploadID)

		// Track parts for completion
		var completedParts []types.CompletedPart
		overallHash := sha256.New()

		// Upload parts in sequence with memory-efficient streaming
		for partNum := 1; partNum <= numParts; partNum++ {
			// Memory check before each part
			runtime.GC()
			runtime.ReadMemStats(&memStats)
			t.Logf("Part %d/%d - Current memory usage: %d MB",
				partNum, numParts, memStats.Alloc/(1024*1024))

			// Calculate part size (last part may be smaller)
			currentPartSize := MultipartPartSize
			if partNum == numParts {
				remaining := LargeFileSize500MB - (int64(partNum-1) * MultipartPartSize)
				if remaining < MultipartPartSize {
					currentPartSize = int(remaining)
				}
			}

			// Generate deterministic data for this part using seed + partNum
			partData := generateDeterministicData(currentPartSize, seed+int64(partNum))

			// Update overall hash
			overallHash.Write(partData)

			// Upload the part
			uploadResp, err := tc.ProxyClient.UploadPart(tc.Ctx, &s3.UploadPartInput{
				Bucket:     aws.String(bucketName),
				Key:        aws.String(objectKey),
				PartNumber: aws.Int32(int32(partNum)),
				UploadId:   aws.String(uploadID),
				Body:       bytes.NewReader(partData),
			})
			require.NoError(t, err, "Failed to upload part %d", partNum)
			require.NotNil(t, uploadResp.ETag, "ETag should not be nil for part %d", partNum)

			// Store completed part info
			completedParts = append(completedParts, types.CompletedPart{
				ETag:       uploadResp.ETag,
				PartNumber: aws.Int32(int32(partNum)),
			})

			t.Logf("Uploaded part %d with ETag: %s (%d MB)",
				partNum, *uploadResp.ETag, currentPartSize/(1024*1024))

			// Clear part data from memory immediately
			partData = nil
			runtime.GC()
		}

		// Complete multipart upload
		completeResp, err := tc.ProxyClient.CompleteMultipartUpload(tc.Ctx, &s3.CompleteMultipartUploadInput{
			Bucket:   aws.String(bucketName),
			Key:      aws.String(objectKey),
			UploadId: aws.String(uploadID),
			MultipartUpload: &types.CompletedMultipartUpload{
				Parts: completedParts,
			},
		})
		require.NoError(t, err, "Failed to complete multipart upload")
		require.NotNil(t, completeResp.ETag, "Final ETag should not be nil")

		uploadDuration := time.Since(startTime)
		throughputMBps := float64(LargeFileSize500MB) / (1024 * 1024) / uploadDuration.Seconds()

		t.Logf("Successfully uploaded 500MB file in %v (%.2f MB/s)", uploadDuration, throughputMBps)
		t.Logf("Final ETag: %s", *completeResp.ETag)

		// Store the expected hash for validation in download test (assign to outer variable)
		expectedHash = fmt.Sprintf("%x", overallHash.Sum(nil))
		t.Logf("Upload completed - Expected SHA256: %s", expectedHash)

		// Final memory check
		runtime.GC()
		runtime.ReadMemStats(&memStats)
		t.Logf("Upload completed - Final memory usage: %d MB", memStats.Alloc/(1024*1024))

		// Verify object exists and has correct size
		headResp, err := tc.ProxyClient.HeadObject(tc.Ctx, &s3.HeadObjectInput{
			Bucket: aws.String(bucketName),
			Key:    aws.String(objectKey),
		})
		require.NoError(t, err, "Failed to get object metadata")
		require.Equal(t, int64(LargeFileSize500MB), *headResp.ContentLength,
			"Object size should match uploaded size")

		t.Logf("Object verification successful - Size: %d bytes", *headResp.ContentLength)
	})

	// Step 2: Download test (runs after upload since subtests run sequentially)
	t.Run("Download_500MB_Streaming_Verification", func(t *testing.T) {
		// Memory check before download
		runtime.GC()
		runtime.ReadMemStats(&memStats)
		t.Logf("Download starting - Memory usage: %d MB", memStats.Alloc/(1024*1024))

		startTime := time.Now()

		// Verify object exists and get metadata
		headResp, err := tc.ProxyClient.HeadObject(ctx, &s3.HeadObjectInput{
			Bucket: aws.String(bucketName),
			Key:    aws.String(objectKey),
		})
		require.NoError(t, err, "Failed to get object metadata")
		require.Equal(t, int64(LargeFileSize500MB), *headResp.ContentLength,
			"Object size should be 500MB")

		t.Logf("Object exists with size: %d bytes", *headResp.ContentLength)

		// Download and verify using streaming approach
		getResp, err := tc.ProxyClient.GetObject(ctx, &s3.GetObjectInput{
			Bucket: aws.String(bucketName),
			Key:    aws.String(objectKey),
		})
		require.NoError(t, err, "Failed to start object download")
		defer getResp.Body.Close()

		// Stream download with verification
		actualHash := sha256.New()
		totalBytesRead := int64(0)
		bufferSize := 1024 * 1024 // 1MB read buffer
		readBuffer := make([]byte, bufferSize)

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

		// Verify total size and data integrity
		require.Equal(t, int64(LargeFileSize500MB), totalBytesRead,
			"Downloaded size should match expected size")

		// Compare SHA256 hashes
		actualHashSum := fmt.Sprintf("%x", actualHash.Sum(nil))

		require.Equal(t, expectedHash, actualHashSum,
			"Downloaded data SHA256 hash should match expected hash from upload")

		t.Logf("Data integrity verified - SHA256: %s", actualHashSum)

		// Final memory check
		runtime.GC()
		runtime.ReadMemStats(&memStats)
		t.Logf("Download completed - Final memory usage: %d MB", memStats.Alloc/(1024*1024))
	})
}
