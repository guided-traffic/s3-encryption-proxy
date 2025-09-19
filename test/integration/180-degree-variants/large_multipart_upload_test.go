//go:build integration
// +build integration

package integration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
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



// TestLargeMultipartUpload2GB tests uploading a 2GB file using multipart upload
// This test is designed to run independently to allow separate memory profiling
func TestLargeMultipartUpload2GB(t *testing.T) {
	if os.Getenv("INTEGRATION_TEST") == "" {
		t.Skip("Skipping integration test. Set INTEGRATION_TEST=1 to run.")
	}

	// Initial memory usage check for monitoring
	var memStats runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&memStats)

	t.Logf("Starting 2GB multipart upload test - Initial memory usage: %d MB",
		memStats.Alloc/(1024*1024))

	// Create context with extended timeout for large file operations (45 minutes)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Minute)
	defer cancel()

	// Create test context manually with extended timeout for large operations
	tc := &TestContext{
		MinIOClient: nil, // Will be created below
		ProxyClient: nil, // Will be created below
		TestBucket:  fmt.Sprintf("test-bucket-%d", time.Now().UnixNano()),
		T:           t,
		Ctx:         ctx,
	}

	// Create MinIO client
	minioClient, err := CreateMinIOClient()
	require.NoError(t, err, "Failed to create MinIO client")
	tc.MinIOClient = minioClient

	// Create Proxy client
	proxyClient, err := CreateProxyClient()
	require.NoError(t, err, "Failed to create Proxy client")
	tc.ProxyClient = proxyClient

	// Ensure bucket is created and cleaned up
	tc.EnsureTestBucket()
	defer tc.CleanupTestBucket()

	bucketName := tc.TestBucket
	objectKey := fmt.Sprintf("large-multipart-2gb-%d", time.Now().Unix())

	startTime := time.Now()

	t.Run("Upload_2GB_Multipart_AES_CTR", func(t *testing.T) {
		// Generate a deterministic seed for reproducible test data
		seed := int64(12345)

		// Calculate number of parts needed
		numParts := (LargeFileSize2GB + MultipartPartSize - 1) / MultipartPartSize
		t.Logf("Uploading 2GB file in %d parts of %d MB each", numParts, MultipartPartSize/(1024*1024))

		// Step 1: Initiate multipart upload
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

		// Step 2: Upload parts in sequence with memory-efficient streaming
		for partNum := 1; partNum <= numParts; partNum++ {
			// Memory check before each part
			runtime.GC()
			runtime.ReadMemStats(&memStats)
			t.Logf("Part %d/%d - Current memory usage: %d MB",
				partNum, numParts, memStats.Alloc/(1024*1024))

			// Calculate part size (last part may be smaller)
			currentPartSize := MultipartPartSize
			if partNum == numParts {
				remaining := LargeFileSize2GB - (int64(partNum-1) * MultipartPartSize)
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

		// Step 3: Complete multipart upload
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
		throughputMBps := float64(LargeFileSize2GB) / (1024 * 1024) / uploadDuration.Seconds()

		t.Logf("Successfully uploaded 2GB file in %v (%.2f MB/s)", uploadDuration, throughputMBps)
		t.Logf("Final ETag: %s", *completeResp.ETag)

		// Step 4: Store the expected hash for validation in download test
		expectedHash := fmt.Sprintf("%x", overallHash.Sum(nil))
		t.Logf("Upload completed - Expected SHA256: %s", expectedHash)

		// Final memory check
		runtime.GC()
		runtime.ReadMemStats(&memStats)
		t.Logf("Upload completed - Final memory usage: %d MB", memStats.Alloc/(1024*1024))

		// Step 5: Verify object exists and has correct size
		headResp, err := tc.ProxyClient.HeadObject(tc.Ctx, &s3.HeadObjectInput{
			Bucket: aws.String(bucketName),
			Key:    aws.String(objectKey),
		})
		require.NoError(t, err, "Failed to get object metadata")
		require.Equal(t, int64(LargeFileSize2GB), *headResp.ContentLength,
			"Object size should match uploaded size")

		t.Logf("Object verification successful - Size: %d bytes", *headResp.ContentLength)
	})
}
