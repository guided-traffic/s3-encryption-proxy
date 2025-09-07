//go:build integration
// +build integration

package integration

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/stretchr/testify/require"
)

// TestLargeFileMultipartSmall tests multipart upload with smaller sizes first
func TestLargeFileMultipartSmall(t *testing.T) {
	// Ensure services are available
	EnsureMinIOAndProxyAvailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	testBucket := fmt.Sprintf("small-multipart-test-%d", time.Now().Unix())

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

	// Start with smaller test cases
	testCases := []struct {
		name    string
		size    int64
		timeout time.Duration
	}{
		{
			name:    "1MB file",
			size:    1 * 1024 * 1024,
			timeout: 1 * time.Minute,
		},
		{
			name:    "10MB file",
			size:    Size10MB,
			timeout: 2 * time.Minute,
		},
		{
			name:    "50MB file",
			size:    50 * 1024 * 1024,
			timeout: 3 * time.Minute,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			testCtx, cancel := context.WithTimeout(ctx, tc.timeout)
			defer cancel()

			// Generate test data
			t.Logf("Generating %d bytes of test data...", tc.size)
			testData, originalHash := generateLargeFileTestData(t, tc.size)

			testKey := fmt.Sprintf("test-small-%d-bytes", tc.size)

			// Upload through proxy
			uploadedSize := uploadLargeFileMultipart(t, testCtx, proxyClient, testBucket, testKey, testData)

			// Verify sizes match
			require.Equal(t, tc.size, uploadedSize, "Upload size mismatch for %s", tc.name)

			// Verify in MinIO
			verifyFileInMinIO(t, testCtx, minioClient, testBucket, testKey, tc.size, uploadedSize)

			// Verify encryption
			verifyLargeFileEncryptionMetadata(t, testCtx, minioClient, testBucket, testKey)

			// Download and verify
			downloadedData := downloadLargeFile(t, testCtx, proxyClient, testBucket, testKey)
			verifyDataIntegrity(t, originalHash, downloadedData, tc.size, true)

			// Cleanup
			cleanupTestFile(t, testCtx, proxyClient, testBucket, testKey)

			t.Logf("✅ %s completed successfully", tc.name)
		})
	}
}
