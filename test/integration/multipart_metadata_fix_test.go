//go:build integration
// +build integration

package integration

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMultipartMetadataFix tests that multipart uploads properly store and retrieve encryption metadata
func TestMultipartMetadataFix(t *testing.T) {
	// Skip if services not available
	SkipIfMinIONotAvailable(t)
	SkipIfProxyNotAvailable(t)

	// Create test context
	tc := NewTestContext(t)
	defer tc.CleanupTestBucket()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Test data - make it large enough to trigger multipart
	testData := []byte(strings.Repeat("This is test data for multipart upload with encryption! ", 200))
	objectKey := "test/multipart-metadata-fix.txt"

	t.Logf("Testing multipart upload with %d bytes of data", len(testData))

	// Step 1: Create multipart upload via proxy
	createResp, err := tc.ProxyClient.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{
		Bucket:      aws.String(tc.TestBucket),
		Key:         aws.String(objectKey),
		ContentType: aws.String("text/plain"),
	})
	require.NoError(t, err, "Failed to create multipart upload")
	require.NotNil(t, createResp.UploadId)

	uploadID := *createResp.UploadId
	t.Logf("Created multipart upload with ID: %s", uploadID)

	// Step 2: Upload parts via proxy (this should encrypt them)
	const partSize = 5 * 1024 * 1024 // 5MB minimum for S3 multipart (except last part)
	parts := []struct {
		partNumber int32
		data       []byte
	}{
		{1, testData}, // Single part for this test
	}

	var completedParts []types.CompletedPart
	for _, part := range parts {
		uploadResp, err := tc.ProxyClient.UploadPart(ctx, &s3.UploadPartInput{
			Bucket:     aws.String(tc.TestBucket),
			Key:        aws.String(objectKey),
			UploadId:   aws.String(uploadID),
			PartNumber: aws.Int32(part.partNumber),
			Body:       bytes.NewReader(part.data),
		})
		require.NoError(t, err, "Failed to upload part %d", part.partNumber)
		require.NotNil(t, uploadResp.ETag)

		completedParts = append(completedParts, types.CompletedPart{
			PartNumber: aws.Int32(part.partNumber),
			ETag:       uploadResp.ETag,
		})

		t.Logf("Uploaded part %d with ETag: %s", part.partNumber, *uploadResp.ETag)
	}

	// Step 3: Complete multipart upload via proxy
	completeResp, err := tc.ProxyClient.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
		Bucket:   aws.String(tc.TestBucket),
		Key:      aws.String(objectKey),
		UploadId: aws.String(uploadID),
		MultipartUpload: &types.CompletedMultipartUpload{
			Parts: completedParts,
		},
	})
	require.NoError(t, err, "Failed to complete multipart upload")
	require.NotNil(t, completeResp.ETag)

	t.Logf("Completed multipart upload with final ETag: %s", *completeResp.ETag)

	// Step 4: Check that encryption metadata exists on the final object (via direct MinIO)
	t.Log("Checking encryption metadata via direct MinIO access...")

	headResp, err := tc.MinIOClient.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(tc.TestBucket),
		Key:    aws.String(objectKey),
	})
	require.NoError(t, err, "Failed to get object metadata from MinIO")

	// Look for encryption metadata
	hasEncryptionMetadata := false
	encryptionMetadataKeys := []string{}
	for key, value := range headResp.Metadata {
		if strings.HasPrefix(key, "x-s3ep-") {
			hasEncryptionMetadata = true
			encryptionMetadataKeys = append(encryptionMetadataKeys, key+"="+value)
		}
	}

	t.Logf("Found encryption metadata keys: %v", encryptionMetadataKeys)
	assert.True(t, hasEncryptionMetadata, "Object should have encryption metadata after multipart upload completion")

	// Step 5: Download via proxy and verify decryption works
	t.Log("Downloading object via proxy to test decryption...")

	getResp, err := tc.ProxyClient.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(tc.TestBucket),
		Key:    aws.String(objectKey),
	})
	require.NoError(t, err, "Failed to get object via proxy")
	defer getResp.Body.Close()

	// Read the decrypted data
	decryptedData := make([]byte, len(testData)+100) // Buffer with extra space
	n, err := getResp.Body.Read(decryptedData)
	if err != nil && err.Error() != "EOF" {
		require.NoError(t, err, "Failed to read decrypted object data")
	}
	decryptedData = decryptedData[:n]

	// Step 6: Verify the data was correctly decrypted
	assert.Equal(t, testData, decryptedData, "Decrypted data should match original data")
	t.Logf("SUCCESS: Decrypted data matches original (%d bytes)", len(decryptedData))

	// Step 7: Verify that direct MinIO access shows encrypted data (different from original)
	t.Log("Verifying data is encrypted in MinIO...")

	directGetResp, err := tc.MinIOClient.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(tc.TestBucket),
		Key:    aws.String(objectKey),
	})
	require.NoError(t, err, "Failed to get object directly from MinIO")
	defer directGetResp.Body.Close()

	rawData := make([]byte, len(testData)+100)
	n, err = directGetResp.Body.Read(rawData)
	if err != nil && err.Error() != "EOF" {
		require.NoError(t, err, "Failed to read raw object data from MinIO")
	}
	rawData = rawData[:n]

	// Raw data should be different from original (encrypted)
	assert.NotEqual(t, testData, rawData, "Raw data in MinIO should be encrypted (different from original)")
	t.Logf("SUCCESS: Raw data in MinIO is encrypted (%d bytes, differs from original)", len(rawData))

	// Step 8: Verify proxy response has clean metadata (no encryption metadata exposed)
	t.Log("Verifying proxy response has clean metadata...")

	proxyHeadResp, err := tc.ProxyClient.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(tc.TestBucket),
		Key:    aws.String(objectKey),
	})
	require.NoError(t, err, "Failed to get object metadata via proxy")

	// Proxy should hide encryption metadata from client
	hasProxyEncryptionMetadata := false
	for key := range proxyHeadResp.Metadata {
		if strings.HasPrefix(key, "x-s3ep-") {
			hasProxyEncryptionMetadata = true
			break
		}
	}

	assert.False(t, hasProxyEncryptionMetadata, "Proxy should hide encryption metadata from clients")
	t.Log("SUCCESS: Proxy correctly hides encryption metadata from clients")
}

// TestMultipartUploadPartialFailure tests multipart upload resilience
func TestMultipartUploadPartialFailure(t *testing.T) {
	// Skip if services not available
	SkipIfMinIONotAvailable(t)
	SkipIfProxyNotAvailable(t)

	tc := NewTestContext(t)
	defer tc.CleanupTestBucket()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	testData := []byte("Test data for partial failure scenario")
	objectKey := "test/multipart-partial-failure.txt"

	// Create multipart upload
	createResp, err := tc.ProxyClient.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{
		Bucket: aws.String(tc.TestBucket),
		Key:    aws.String(objectKey),
	})
	require.NoError(t, err)
	uploadID := *createResp.UploadId

	// Upload one part
	_, err = tc.ProxyClient.UploadPart(ctx, &s3.UploadPartInput{
		Bucket:     aws.String(tc.TestBucket),
		Key:        aws.String(objectKey),
		UploadId:   aws.String(uploadID),
		PartNumber: aws.Int32(1),
		Body:       bytes.NewReader(testData),
	})
	require.NoError(t, err)

	// Abort the upload instead of completing
	_, err = tc.ProxyClient.AbortMultipartUpload(ctx, &s3.AbortMultipartUploadInput{
		Bucket:   aws.String(tc.TestBucket),
		Key:      aws.String(objectKey),
		UploadId: aws.String(uploadID),
	})
	assert.NoError(t, err, "Should be able to abort multipart upload")

	// Verify object doesn't exist after abort
	_, err = tc.MinIOClient.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(tc.TestBucket),
		Key:    aws.String(objectKey),
	})
	assert.Error(t, err, "Object should not exist after multipart upload abort")

	t.Log("SUCCESS: Multipart upload abort worked correctly")
}
