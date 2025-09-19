//go:build integration
// +build integration

package integration

import (
	"bytes"
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
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/stretchr/testify/require"

	// Import helper functions from the main integration package
	. "github.com/guided-traffic/s3-encryption-proxy/test/integration"
)

// TestLargeMultipartDownload2GB tests downloading a 2GB file that was uploaded via multipart
// This test assumes the object was created by TestLargeMultipartUpload2GB
// This test is designed to run independently to allow separate memory profiling
func TestLargeMultipartDownload2GB(t *testing.T) {
	if os.Getenv("INTEGRATION_TEST") == "" {
		t.Skip("Skipping integration test. Set INTEGRATION_TEST=1 to run.")
	}

	// Initial memory usage check for monitoring
	var memStats runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&memStats)

	t.Logf("Starting 2GB download test - Initial memory usage: %d MB",
		memStats.Alloc/(1024*1024))

	// Create context with extended timeout for large file operations (45 minutes)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Minute)
	defer cancel()

	// Use test context with extended timeout
	tc := NewTestContextWithTimeout(t, ctx)
	defer tc.CleanupTestBucket()

	// First, we need to upload the file (this test can also run standalone)
	bucketName := tc.TestBucket
	objectKey := fmt.Sprintf("large-download-2gb-%d", time.Now().Unix())

	// Check if we can reuse existing file from upload test (optimization)
	existingObjects, _ := tc.ProxyClient.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
		Bucket: aws.String(bucketName),
	})

	var foundExistingFile bool
	for _, obj := range existingObjects.Contents {
		if *obj.Size == int64(LargeFileSize2GB) {
			objectKey = *obj.Key
			foundExistingFile = true
			t.Logf("Found existing 2GB file: %s, skipping upload", objectKey)
			break
		}
	}

	// Setup: Upload the 2GB file first (only if no suitable file exists)
	if !foundExistingFile {
		t.Run("Setup_Upload_2GB_File", func(t *testing.T) {
		seed := int64(12345) // Same seed as upload test for consistency

		// Calculate number of parts needed
		numParts := (LargeFileSize2GB + MultipartPartSize - 1) / MultipartPartSize
		t.Logf("Setting up 2GB file upload in %d parts", numParts)

		// Initiate multipart upload
		createResp, err := tc.ProxyClient.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{
			Bucket: aws.String(bucketName),
			Key:    aws.String(objectKey),
		})
		require.NoError(t, err, "Failed to initiate multipart upload for setup")
		uploadID := *createResp.UploadId

		// Upload all parts
		var completedParts []types.CompletedPart
		for partNum := 1; partNum <= numParts; partNum++ {
			currentPartSize := MultipartPartSize
			if partNum == numParts {
				remaining := LargeFileSize2GB - (int64(partNum-1) * MultipartPartSize)
				if remaining < MultipartPartSize {
					currentPartSize = int(remaining)
				}
			}

			partData := generateDeterministicData(currentPartSize, seed+int64(partNum))

			uploadResp, err := tc.ProxyClient.UploadPart(ctx, &s3.UploadPartInput{
				Bucket:     aws.String(bucketName),
				Key:        aws.String(objectKey),
				PartNumber: aws.Int32(int32(partNum)),
				UploadId:   aws.String(uploadID),
				Body:       bytes.NewReader(partData),
			})
			require.NoError(t, err, "Failed to upload setup part %d", partNum)

			completedParts = append(completedParts, types.CompletedPart{
				ETag:       uploadResp.ETag,
				PartNumber: aws.Int32(int32(partNum)),
			})

			// Clear part data from memory
			partData = nil
			runtime.GC()
		}

		// Complete multipart upload
		_, err = tc.ProxyClient.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
			Bucket:   aws.String(bucketName),
			Key:      aws.String(objectKey),
			UploadId: aws.String(uploadID),
			MultipartUpload: &types.CompletedMultipartUpload{
				Parts: completedParts,
			},
		})
		require.NoError(t, err, "Failed to complete setup multipart upload")

		t.Logf("Setup completed - 2GB file uploaded for download testing")
		})
	}

	startTime := time.Now()

	t.Run("Download_2GB_Streaming_Verification", func(t *testing.T) {
		// Memory check before download
		runtime.GC()
		runtime.ReadMemStats(&memStats)
		t.Logf("Download starting - Memory usage: %d MB", memStats.Alloc/(1024*1024))

		// Step 1: Verify object exists and get metadata
		headResp, err := tc.ProxyClient.HeadObject(ctx, &s3.HeadObjectInput{
			Bucket: aws.String(bucketName),
			Key:    aws.String(objectKey),
		})
		require.NoError(t, err, "Failed to get object metadata")
		require.Equal(t, int64(LargeFileSize2GB), *headResp.ContentLength,
			"Object size should be 2GB")

		t.Logf("Object exists with size: %d bytes", *headResp.ContentLength)

		// Step 2: Download and verify using streaming approach
		getResp, err := tc.ProxyClient.GetObject(ctx, &s3.GetObjectInput{
			Bucket: aws.String(bucketName),
			Key:    aws.String(objectKey),
		})
		require.NoError(t, err, "Failed to start object download")
		defer getResp.Body.Close()

		// Step 3: Stream download with verification using deterministic data generation
		expectedHash := sha256.New()
		actualHash := sha256.New()

		seed := int64(12345) // Same seed used during upload
		totalBytesRead := int64(0)
		bufferSize := 1024 * 1024 // 1MB read buffer
		readBuffer := make([]byte, bufferSize)

		// Track parts for verification
		currentPart := 1
		partBytesRead := int64(0)

		for {
			// Memory check during download
			if totalBytesRead%(500*1024*1024) == 0 && totalBytesRead > 0 { // Every 500MB
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

				// Generate expected data for verification
				// We need to track which part we're in and generate corresponding expected data
				expectedData := generateExpectedDataForOffset(totalBytesRead, n, seed)
				expectedHash.Write(expectedData)

				totalBytesRead += int64(n)
				partBytesRead += int64(n)

				// Track part boundaries for logging
				if partBytesRead >= MultipartPartSize {
					t.Logf("Verified part %d - Total downloaded: %d MB",
						currentPart, totalBytesRead/(1024*1024))
					currentPart++
					partBytesRead = 0
				}
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
		require.Equal(t, int64(LargeFileSize2GB), totalBytesRead,
			"Downloaded size should match expected size")

		// Compare SHA256 hashes
		expectedHashSum := fmt.Sprintf("%x", expectedHash.Sum(nil))
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

// generateExpectedDataForOffset generates the expected data for a given offset and length
// This allows us to verify download integrity without storing the entire file in memory
func generateExpectedDataForOffset(offset int64, length int, seed int64) []byte {
	// Calculate which part this offset belongs to
	partNumber := (offset / MultipartPartSize) + 1
	offsetInPart := offset % MultipartPartSize

	// Create a buffer for the expected data
	expectedData := make([]byte, length)

	bytesGenerated := 0
	currentPartNumber := partNumber
	currentOffsetInPart := offsetInPart

	for bytesGenerated < length {
		// Calculate how many bytes we can generate from current part
		remainingInPart := MultipartPartSize - currentOffsetInPart
		remainingToGenerate := int64(length - bytesGenerated)

		bytesToGenerate := remainingInPart
		if remainingToGenerate < remainingInPart {
			bytesToGenerate = remainingToGenerate
		}

		// Generate data for current part using the same algorithm as upload
		partSeed := seed + currentPartNumber
		rng := newSimplePRNG(partSeed)

		// Skip to the correct offset within the part
		for i := int64(0); i < currentOffsetInPart; i++ {
			rng.next()
		}

		// Generate the required bytes
		for i := int64(0); i < bytesToGenerate; i++ {
			expectedData[bytesGenerated] = byte(rng.next() & 0xFF)
			bytesGenerated++
		}

		// Move to next part if needed
		currentPartNumber++
		currentOffsetInPart = 0
	}

	return expectedData
}
