//go:build integration

package integration

import (
	"context"
	"crypto/rand"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	test_helper "github.com/guided-traffic/s3-encryption-proxy/test/integration"
)

// RandomString generates a random string of the specified length
func RandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, length)
	_, err := rand.Read(b)
	if err != nil {
		// Fallback to timestamp-based string if crypto/rand fails
		return fmt.Sprintf("%d", time.Now().UnixNano()%1000000)[:length]
	}

	for i := range b {
		b[i] = charset[b[i]%byte(len(charset))]
	}
	return string(b)
}

func TestListBucketsSimple(t *testing.T) {
	ctx := test_helper.NewTestContext(t)
	defer ctx.CleanupTestBucket()

	t.Run("ListBuckets_BasicFunctionality", func(t *testing.T) {
		// Test that ListBuckets works without errors
		output, err := ctx.ProxyClient.ListBuckets(context.Background(), &s3.ListBucketsInput{})
		require.NoError(t, err, "ListBuckets should work without error")
		require.NotNil(t, output, "ListBuckets should return non-nil output")

		t.Logf("ListBuckets returned %d buckets via proxy", len(output.Buckets))

		// Basic validation that response structure is correct
		assert.NotNil(t, output.Buckets, "Buckets list should not be nil")

		// Test that we can also call it via HTTP
		resp, err := http.Get(test_helper.ProxyEndpoint + "/")
		require.NoError(t, err, "HTTP GET to proxy root should work")
		defer resp.Body.Close()

		assert.Equal(t, 200, resp.StatusCode, "HTTP ListBuckets should return 200")
		assert.Contains(t, resp.Header.Get("Content-Type"), "xml", "Response should be XML")
	})

	t.Run("ListBuckets_PassthroughBehavior", func(t *testing.T) {
		// Create a unique test bucket via proxy
		testBucketName := "list-test-" + RandomString(8)

		// Create bucket via proxy
		_, err := ctx.ProxyClient.CreateBucket(context.Background(), &s3.CreateBucketInput{
			Bucket: aws.String(testBucketName),
		})
		require.NoError(t, err, "Should be able to create bucket via proxy")

		// Clean up bucket at the end
		defer func() {
			_, _ = ctx.ProxyClient.DeleteBucket(context.Background(), &s3.DeleteBucketInput{
				Bucket: aws.String(testBucketName),
			})
		}()

		// List buckets via proxy and check our bucket appears
		proxyOutput, err := ctx.ProxyClient.ListBuckets(context.Background(), &s3.ListBucketsInput{})
		require.NoError(t, err, "ListBuckets via proxy should work")

		// List buckets directly via MinIO and check our bucket appears
		minioOutput, err := ctx.MinIOClient.ListBuckets(context.Background(), &s3.ListBucketsInput{})
		require.NoError(t, err, "ListBuckets via MinIO should work")

		// Verify our test bucket appears in both results
		foundInProxy := false
		foundInMinIO := false

		for _, bucket := range proxyOutput.Buckets {
			if bucket.Name != nil && *bucket.Name == testBucketName {
				foundInProxy = true
				break
			}
		}

		for _, bucket := range minioOutput.Buckets {
			if bucket.Name != nil && *bucket.Name == testBucketName {
				foundInMinIO = true
				break
			}
		}

		assert.True(t, foundInProxy, "Bucket %s should be visible via proxy", testBucketName)
		assert.True(t, foundInMinIO, "Bucket %s should be visible via MinIO", testBucketName)

		t.Logf("✅ Bucket %s correctly appears in both proxy (%d buckets) and MinIO (%d buckets) results",
			testBucketName, len(proxyOutput.Buckets), len(minioOutput.Buckets))
	})
}
