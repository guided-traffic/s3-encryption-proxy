//go:build integration

package integration

import (
	"context"
	"crypto/rand"
	"encoding/xml"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func TestListBucketsOperation(t *testing.T) {
	ctx := NewTestContext(t)
	defer ctx.CleanupTestBucket()

	// Test 1: ListBuckets should work without any buckets initially
	t.Run("ListBuckets_EmptyResponse", func(t *testing.T) {
		// Call ListBuckets on proxy
		proxyOutput, err := ctx.ProxyClient.ListBuckets(context.Background(), &s3.ListBucketsInput{})
		require.NoError(t, err)
		assert.NotNil(t, proxyOutput)
		
		// Should return empty list of buckets or existing test buckets
		// (depending on what's already in MinIO)
		t.Logf("Found %d buckets via proxy", len(proxyOutput.Buckets))
	})

	// Test 2: Create bucket through proxy and verify it appears in ListBuckets
	t.Run("CreateBucket_ThenList", func(t *testing.T) {
		testBucketName := "test-list-buckets-" + RandomString(8)

		// Create bucket through proxy
		_, err := ctx.ProxyClient.CreateBucket(context.Background(), &s3.CreateBucketInput{
			Bucket: &testBucketName,
		})
		require.NoError(t, err)

		// List buckets through proxy
		proxyOutput, err := ctx.ProxyClient.ListBuckets(context.Background(), &s3.ListBucketsInput{})
		require.NoError(t, err)

		// Verify the bucket appears in the list
		found := false
		for _, bucket := range proxyOutput.Buckets {
			if bucket.Name != nil && *bucket.Name == testBucketName {
				found = true
				break
			}
		}
		assert.True(t, found, "Created bucket should appear in ListBuckets response")

		// Compare with direct MinIO client
		minioOutput, err := ctx.MinIOClient.ListBuckets(context.Background(), &s3.ListBucketsInput{})
		require.NoError(t, err)

		// Verify bucket count matches
		assert.Equal(t, len(minioOutput.Buckets), len(proxyOutput.Buckets),
			"Proxy and MinIO should return same number of buckets")

		// Cleanup
		_, err = ctx.ProxyClient.DeleteBucket(context.Background(), &s3.DeleteBucketInput{
			Bucket: &testBucketName,
		})
		require.NoError(t, err)
	})

	// Test 3: Compare ListBuckets response format between proxy and MinIO
	t.Run("ListBuckets_ResponseFormat", func(t *testing.T) {
		testBucketName := "test-format-" + RandomString(8)

		// Create bucket through MinIO directly
		_, err := ctx.MinIOClient.CreateBucket(context.Background(), &s3.CreateBucketInput{
			Bucket: &testBucketName,
		})
		require.NoError(t, err)
		defer func() {
			ctx.MinIOClient.DeleteBucket(context.Background(), &s3.DeleteBucketInput{
				Bucket: &testBucketName,
			})
		}()

		// Get responses from both proxy and MinIO
		proxyOutput, err := ctx.ProxyClient.ListBuckets(context.Background(), &s3.ListBucketsInput{})
		require.NoError(t, err)

		minioOutput, err := ctx.MinIOClient.ListBuckets(context.Background(), &s3.ListBucketsInput{})
		require.NoError(t, err)

		// Verify both contain the test bucket
		proxyHasBucket := false
		minioHasBucket := false

		for _, bucket := range proxyOutput.Buckets {
			if bucket.Name != nil && *bucket.Name == testBucketName {
				proxyHasBucket = true
				break
			}
		}

		for _, bucket := range minioOutput.Buckets {
			if bucket.Name != nil && *bucket.Name == testBucketName {
				minioHasBucket = true
				break
			}
		}

		assert.True(t, proxyHasBucket, "Proxy should see the bucket")
		assert.True(t, minioHasBucket, "MinIO should see the bucket")
	})

	// Test 4: Test ListBuckets via HTTP directly
	t.Run("ListBuckets_HTTPCall", func(t *testing.T) {
		// Make HTTP GET request to root path
		req, err := http.NewRequest("GET", ProxyEndpoint+"/", nil)
		require.NoError(t, err)

		client := &http.Client{}
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Verify response
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, "application/xml", resp.Header.Get("Content-Type"))

		// Parse XML response
		var listBucketsOutput s3.ListBucketsOutput
		err = xml.NewDecoder(resp.Body).Decode(&listBucketsOutput)
		require.NoError(t, err)

		// Verify structure is correct
		assert.NotNil(t, listBucketsOutput.Buckets)
		t.Logf("HTTP ListBuckets returned %d buckets", len(listBucketsOutput.Buckets))
	})

	// Test 5: Multiple buckets with different names
	t.Run("ListBuckets_MultipleBuckets", func(t *testing.T) {
		bucketNames := []string{
			"test-multi-a-" + RandomString(6),
			"test-multi-b-" + RandomString(6),
			"test-multi-c-" + RandomString(6),
		}

		// Create multiple buckets
		for _, bucketName := range bucketNames {
			_, err := ctx.ProxyClient.CreateBucket(context.Background(), &s3.CreateBucketInput{
				Bucket: &bucketName,
			})
			require.NoError(t, err)
		}

		// List buckets
		output, err := ctx.ProxyClient.ListBuckets(context.Background(), &s3.ListBucketsInput{})
		require.NoError(t, err)

		// Verify all buckets are present
		foundBuckets := make(map[string]bool)
		for _, bucket := range output.Buckets {
			if bucket.Name != nil {
				foundBuckets[*bucket.Name] = true
			}
		}

		for _, expectedBucket := range bucketNames {
			assert.True(t, foundBuckets[expectedBucket],
				"Bucket %s should be present in ListBuckets response", expectedBucket)
		}

		// Cleanup
		for _, bucketName := range bucketNames {
			_, err := ctx.ProxyClient.DeleteBucket(context.Background(), &s3.DeleteBucketInput{
				Bucket: &bucketName,
			})
			require.NoError(t, err)
		}
	})
}

func TestListBucketsPassthrough(t *testing.T) {
	ctx := NewTestContext(t)
	defer ctx.CleanupTestBucket()

	t.Run("ListBuckets_IsPassthrough", func(t *testing.T) {
		// The ListBuckets operation should be a direct passthrough
		// This means the proxy should not modify the response from MinIO

		// Create a test bucket directly in MinIO
		testBucketName := "test-passthrough-" + RandomString(8)
		_, err := ctx.MinIOClient.CreateBucket(context.Background(), &s3.CreateBucketInput{
			Bucket: &testBucketName,
		})
		require.NoError(t, err)
		defer func() {
			ctx.MinIOClient.DeleteBucket(context.Background(), &s3.DeleteBucketInput{
				Bucket: &testBucketName,
			})
		}()

		// Get response from MinIO directly
		minioOutput, err := ctx.MinIOClient.ListBuckets(context.Background(), &s3.ListBucketsInput{})
		require.NoError(t, err)

		// Get response from proxy
		proxyOutput, err := ctx.ProxyClient.ListBuckets(context.Background(), &s3.ListBucketsInput{})
		require.NoError(t, err)

		// The responses should be identical (proxy is passthrough)
		assert.Equal(t, len(minioOutput.Buckets), len(proxyOutput.Buckets),
			"Bucket count should match between MinIO and proxy")

		// Convert to maps for easier comparison
		minioMap := make(map[string]types.Bucket)
		proxyMap := make(map[string]types.Bucket)

		for _, bucket := range minioOutput.Buckets {
			if bucket.Name != nil {
				minioMap[*bucket.Name] = bucket
			}
		}

		for _, bucket := range proxyOutput.Buckets {
			if bucket.Name != nil {
				proxyMap[*bucket.Name] = bucket
			}
		}

		// Verify each bucket exists in both responses
		for name, minioBucket := range minioMap {
			proxyBucket, exists := proxyMap[name]
			assert.True(t, exists, "Bucket %s should exist in proxy response", name)
			if exists {
				assert.Equal(t, minioBucket.Name, proxyBucket.Name,
					"Bucket name should match for %s", name)
				// Creation dates might differ slightly due to timing, so we don't check them strictly
			}
		}
	})
}
