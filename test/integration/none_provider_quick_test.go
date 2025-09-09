//go:build integration
// +build integration

package integration

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNoneProviderQuick is a quick test to verify the none provider is working
func TestNoneProviderQuick(t *testing.T) {
	// Set log level to reduce noise during tests
	logrus.SetLevel(logrus.ErrorLevel)

	// Skip if MinIO is not available
	EnsureMinIOAvailable(t)

	ctx := context.Background()

	// Create MinIO client for direct access
	minioClient, err := CreateMinIOClient()
	require.NoError(t, err, "Failed to create MinIO client")

	// Create proxy client
	proxyClient, err := CreateProxyClient()
	require.NoError(t, err, "Failed to create proxy client")

	// Test data
	bucketName := fmt.Sprintf("test-none-bucket-%d", time.Now().UnixNano())
	objectKey := "test-object.txt"
	testData := []byte("This is test data for none provider verification")

	// Create test bucket
	CreateTestBucket(t, minioClient, bucketName)
	defer CleanupTestBucket(t, minioClient, bucketName)

	t.Log("✅ Test bucket created successfully")

	// Step 1: Upload via proxy (should be unencrypted with none provider)
	_, err = proxyClient.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(objectKey),
		Body:   bytes.NewReader(testData),
		Metadata: map[string]string{
			"test-metadata": "none-provider-test",
		},
	})
	require.NoError(t, err, "Failed to upload object via proxy")

	t.Log("✅ Object uploaded via proxy successfully")

	// Step 2: Download directly from MinIO (should get unencrypted data)
	directResp, err := minioClient.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(objectKey),
	})
	require.NoError(t, err, "Failed to download object directly from MinIO")

	directData, err := io.ReadAll(directResp.Body)
	require.NoError(t, err, "Failed to read object data")
	directResp.Body.Close()

	t.Log("✅ Object downloaded directly from MinIO successfully")

	// Step 3: Verify data is identical (proving none provider passes through)
	assert.Equal(t, testData, directData, "Data should be identical (none provider should pass through)")

	// Step 4: Verify metadata is preserved
	assert.Equal(t, "none-provider-test", directResp.Metadata["test-metadata"], "Custom metadata should be preserved")

	// Step 5: Download via proxy (should also work)
	proxyResp, err := proxyClient.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(objectKey),
	})
	require.NoError(t, err, "Failed to download object via proxy")

	proxyData, err := io.ReadAll(proxyResp.Body)
	require.NoError(t, err, "Failed to read proxy data")
	proxyResp.Body.Close()

	t.Log("✅ Object downloaded via proxy successfully")

	// Step 6: Verify proxy download is also identical
	assert.Equal(t, testData, proxyData, "Proxy download should also return original data")

	t.Log("🎉 None provider test completed successfully! All data passed through unencrypted.")
}
