//go:build integration
// +build integration

package performance_test

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	// Import helper functions from the main integration package
	. "github.com/guided-traffic/s3-encryption-proxy/test/integration"
)

func TestStreamingMultipartUpload(t *testing.T) {
	// Use test context
	tc := NewTestContext(t)
	defer tc.CleanupTestBucket()

	bucketName := tc.TestBucket
	objectKey := fmt.Sprintf("streaming-test-%d", time.Now().Unix())

	t.Run("AES-CTR Streaming Multipart Upload", func(t *testing.T) {
		// Use a large file size to ensure multipart upload
		fileSize := 10 * 1024 * 1024 // 10MB
		originalData := make([]byte, fileSize)
		_, err := io.ReadFull(rand.Reader, originalData)
		require.NoError(t, err, "Failed to generate random data")

		// Step 1: Create multipart upload using S3 SDK
		createResp, err := tc.ProxyClient.CreateMultipartUpload(tc.Ctx, &s3.CreateMultipartUploadInput{
			Bucket: aws.String(bucketName),
			Key:    aws.String(objectKey),
		})
		require.NoError(t, err, "Failed to create multipart upload")
		require.NotNil(t, createResp.UploadId, "Upload ID should not be nil")

		uploadID := *createResp.UploadId
		t.Logf("Created multipart upload with ID: %s", uploadID)

		// Step 2: Upload parts in streaming fashion
		partSize := 5 * 1024 * 1024                      // 5MB per part
		numParts := (fileSize + partSize - 1) / partSize // Ceiling division
		var completedParts []types.CompletedPart

		for i := 0; i < numParts; i++ {
			partNumber := int32(i + 1)
			start := i * partSize
			end := start + partSize
			if end > fileSize {
				end = fileSize
			}

			partData := originalData[start:end]

			// Upload part using S3 SDK
			uploadResp, err := tc.ProxyClient.UploadPart(tc.Ctx, &s3.UploadPartInput{
				Bucket:     aws.String(bucketName),
				Key:        aws.String(objectKey),
				PartNumber: aws.Int32(partNumber),
				UploadId:   aws.String(uploadID),
				Body:       bytes.NewReader(partData),
			})
			require.NoError(t, err, "Failed to upload part %d", partNumber)
			require.NotNil(t, uploadResp.ETag, "ETag should not be nil for part %d", partNumber)

			completedParts = append(completedParts, types.CompletedPart{
				ETag:       uploadResp.ETag,
				PartNumber: aws.Int32(partNumber),
			})

			t.Logf("Uploaded part %d with ETag: %s", partNumber, *uploadResp.ETag)
		}

		// Step 3: Complete multipart upload
		_, err = tc.ProxyClient.CompleteMultipartUpload(tc.Ctx, &s3.CompleteMultipartUploadInput{
			Bucket:   aws.String(bucketName),
			Key:      aws.String(objectKey),
			UploadId: aws.String(uploadID),
			MultipartUpload: &types.CompletedMultipartUpload{
				Parts: completedParts,
			},
		})
		require.NoError(t, err, "Failed to complete multipart upload")

		t.Log("Completed multipart upload")

		// Step 4: Download and verify the object
		getResp, err := tc.ProxyClient.GetObject(tc.Ctx, &s3.GetObjectInput{
			Bucket: aws.String(bucketName),
			Key:    aws.String(objectKey),
		})
		require.NoError(t, err, "Failed to get object")
		defer getResp.Body.Close()

		downloadedData, err := io.ReadAll(getResp.Body)
		require.NoError(t, err, "Failed to read downloaded data")

		// Verify data integrity using SHA256 hash
		originalHash := sha256.Sum256(originalData)
		downloadedHash := sha256.Sum256(downloadedData)
		assert.Equal(t, len(originalData), len(downloadedData), "Downloaded data size should match original")
		assert.Equal(t, originalHash, downloadedHash, "Downloaded data SHA256 hash should match original")

		t.Log("Successfully verified streaming multipart upload and download")

		// Step 5: Verify object exists in S3 (encrypted)
		s3Object, err := tc.MinIOClient.GetObject(tc.Ctx, &s3.GetObjectInput{
			Bucket: aws.String(bucketName),
			Key:    aws.String(objectKey),
		})
		require.NoError(t, err, "Failed to get object from S3")
		defer s3Object.Body.Close()

		s3Data, err := io.ReadAll(s3Object.Body)
		require.NoError(t, err, "Failed to read S3 object data")

		// S3 data should be encrypted (different from original)
		s3Hash := sha256.Sum256(s3Data)
		assert.NotEqual(t, originalHash, s3Hash, "S3 data should be encrypted (different hash)")

		// Verify the data stored in S3 is properly encrypted using basic validation
		// (entropy check only, since multipart objects may have some metadata patterns)
		AssertDataIsEncryptedBasic(t, s3Data, "S3 data should be properly encrypted with high entropy")

		t.Log("Successfully verified S3 encrypted data")
	})
}

func TestStreamingVsStandardPerformance(t *testing.T) {
	// Use test context
	tc := NewTestContext(t)
	defer tc.CleanupTestBucket()

	bucketName := tc.TestBucket
	fileSize := 20 * 1024 * 1024 // 20MB

	// Generate test data
	testData := make([]byte, fileSize)
	_, err := io.ReadFull(rand.Reader, testData)
	require.NoError(t, err, "Failed to generate test data")

	t.Run("Compare Streaming vs Standard Upload Performance", func(t *testing.T) {
		// Test streaming upload using S3 SDK
		streamingKey := fmt.Sprintf("streaming-perf-%d", time.Now().Unix())
		streamingStart := time.Now()

		err := performMultipartUploadWithSDK(t, tc, bucketName, streamingKey, testData)
		require.NoError(t, err, "Streaming upload should succeed")

		streamingDuration := time.Since(streamingStart)
		t.Logf("Streaming upload took: %v", streamingDuration)

		// Verify streaming upload using SHA256 hash
		downloadedData := downloadAndVerifyWithSDK(t, tc, bucketName, streamingKey)
		originalHash := sha256.Sum256(testData)
		downloadedHash := sha256.Sum256(downloadedData)
		assert.Equal(t, originalHash, downloadedHash, "Streaming upload data should match - SHA256 hash verification failed")

		t.Log("Streaming multipart upload performance test completed successfully")
	})
}

func performMultipartUploadWithSDK(t *testing.T, tc *TestContext, bucketName, objectKey string, data []byte) error {
	// Create multipart upload
	createResp, err := tc.ProxyClient.CreateMultipartUpload(tc.Ctx, &s3.CreateMultipartUploadInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(objectKey),
	})
	if err != nil {
		return fmt.Errorf("failed to create multipart upload: %w", err)
	}

	uploadID := *createResp.UploadId

	// Upload parts
	partSize := 5 * 1024 * 1024 // 5MB per part
	numParts := (len(data) + partSize - 1) / partSize
	var completedParts []types.CompletedPart

	for i := 0; i < numParts; i++ {
		partNumber := int32(i + 1)
		start := i * partSize
		end := start + partSize
		if end > len(data) {
			end = len(data)
		}

		partData := data[start:end]

		uploadResp, err := tc.ProxyClient.UploadPart(tc.Ctx, &s3.UploadPartInput{
			Bucket:     aws.String(bucketName),
			Key:        aws.String(objectKey),
			PartNumber: aws.Int32(partNumber),
			UploadId:   aws.String(uploadID),
			Body:       bytes.NewReader(partData),
		})
		if err != nil {
			return fmt.Errorf("failed to upload part %d: %w", partNumber, err)
		}

		completedParts = append(completedParts, types.CompletedPart{
			ETag:       uploadResp.ETag,
			PartNumber: aws.Int32(partNumber),
		})
	}

	// Complete multipart upload
	_, err = tc.ProxyClient.CompleteMultipartUpload(tc.Ctx, &s3.CompleteMultipartUploadInput{
		Bucket:   aws.String(bucketName),
		Key:      aws.String(objectKey),
		UploadId: aws.String(uploadID),
		MultipartUpload: &types.CompletedMultipartUpload{
			Parts: completedParts,
		},
	})
	if err != nil {
		return fmt.Errorf("failed to complete multipart upload: %w", err)
	}

	return nil
}

func downloadAndVerifyWithSDK(t *testing.T, tc *TestContext, bucketName, objectKey string) []byte {
	getResp, err := tc.ProxyClient.GetObject(tc.Ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(objectKey),
	})
	require.NoError(t, err, "Failed to get object")
	defer getResp.Body.Close()

	downloadedData, err := io.ReadAll(getResp.Body)
	require.NoError(t, err, "Failed to read downloaded data")

	return downloadedData
}
