//go:build integration
// +build integration

package integration

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/stretchr/testify/require"
)

// Test configuration constants for MinIO and Proxy
const (
	MinIOEndpoint  = "http://localhost:9000"
	ProxyEndpoint  = "http://localhost:8080"
	MinIOAccessKey = "minio"
	MinIOSecretKey = "minio123"
	TestRegion     = "us-east-1"

	// Test timeout configurations
	DefaultTestTimeout = 30 * time.Second
	BucketOpTimeout    = 10 * time.Second
)

// TestContext holds common test utilities and clients
type TestContext struct {
	MinIOClient *s3.Client
	ProxyClient *s3.Client
	TestBucket  string
	T           *testing.T
	Ctx         context.Context
}

// NewTestContext creates a new test context with MinIO and Proxy clients
func NewTestContext(t *testing.T) *TestContext {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), DefaultTestTimeout)
	t.Cleanup(cancel)

	minioClient, err := createMinIOClient()
	require.NoError(t, err, "Failed to create MinIO client")

	proxyClient, err := createProxyClient()
	require.NoError(t, err, "Failed to create Proxy client")

	// Generate unique bucket name for this test
	testBucket := fmt.Sprintf("test-bucket-%d", time.Now().UnixNano())

	tc := &TestContext{
		MinIOClient: minioClient,
		ProxyClient: proxyClient,
		TestBucket:  testBucket,
		T:           t,
		Ctx:         ctx,
	}

	// Ensure bucket is created and cleaned up
	tc.EnsureTestBucket()

	return tc
}

// EnsureTestBucket creates the test bucket if it doesn't exist
func (tc *TestContext) EnsureTestBucket() {
	tc.T.Helper()

	// Create bucket via MinIO (direct)
	_, err := tc.MinIOClient.CreateBucket(tc.Ctx, &s3.CreateBucketInput{
		Bucket: aws.String(tc.TestBucket),
	})
	if err != nil && !strings.Contains(err.Error(), "BucketAlreadyOwnedByYou") &&
		!strings.Contains(err.Error(), "BucketAlreadyExists") {
		require.NoError(tc.T, err, "Failed to create test bucket")
	}

	// Wait a moment for bucket to be ready
	time.Sleep(100 * time.Millisecond)
}

// CleanupTestBucket removes the test bucket and all its contents
func (tc *TestContext) CleanupTestBucket() {
	tc.T.Helper()

	// List and delete all objects first
	listResp, err := tc.MinIOClient.ListObjectsV2(tc.Ctx, &s3.ListObjectsV2Input{
		Bucket: aws.String(tc.TestBucket),
	})
	if err == nil {
		for _, obj := range listResp.Contents {
			_, _ = tc.MinIOClient.DeleteObject(tc.Ctx, &s3.DeleteObjectInput{
				Bucket: aws.String(tc.TestBucket),
				Key:    obj.Key,
			})
		}
	}

	// Delete the bucket
	_, _ = tc.MinIOClient.DeleteBucket(tc.Ctx, &s3.DeleteBucketInput{
		Bucket: aws.String(tc.TestBucket),
	})
}

// createMinIOClient creates an S3 client configured for MinIO
func createMinIOClient() (*s3.Client, error) {
	cfg, err := config.LoadDefaultConfig(context.Background(),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
			MinIOAccessKey, MinIOSecretKey, "")),
		config.WithRegion(TestRegion),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	client := s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.BaseEndpoint = aws.String(MinIOEndpoint)
		o.UsePathStyle = true
	})

	return client, nil
}

// createProxyClient creates an S3 client configured for the encryption proxy
func createProxyClient() (*s3.Client, error) {
	cfg, err := config.LoadDefaultConfig(context.Background(),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
			MinIOAccessKey, MinIOSecretKey, "")),
		config.WithRegion(TestRegion),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	client := s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.BaseEndpoint = aws.String(ProxyEndpoint)
		o.UsePathStyle = true
	})

	return client, nil
}

// SkipIfMinIONotAvailable checks if MinIO is available and skips test if not
func SkipIfMinIONotAvailable(t *testing.T) {
	t.Helper()

	client, err := createMinIOClient()
	if err != nil {
		t.Skipf("MinIO not available: %v", err)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err = client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		t.Skipf("MinIO not responding: %v", err)
	}
}

// SkipIfProxyNotAvailable checks if the encryption proxy is available and skips test if not
func SkipIfProxyNotAvailable(t *testing.T) {
	t.Helper()

	client, err := createProxyClient()
	if err != nil {
		t.Skipf("Proxy not available: %v", err)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err = client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		t.Skipf("Proxy not responding: %v", err)
	}
}

// CompareObjectData compares object data between two S3 clients without verbose output
func CompareObjectData(t *testing.T, client1, client2 *s3.Client, bucket, key string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), BucketOpTimeout)
	defer cancel()

	// Get object from first client
	resp1, err := client1.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	require.NoError(t, err, "Failed to get object from first client")
	defer resp1.Body.Close()

	// Get object from second client
	resp2, err := client2.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	require.NoError(t, err, "Failed to get object from second client")
	defer resp2.Body.Close()

	// Read data from both responses
	data1 := make([]byte, 1024)
	n1, _ := resp1.Body.Read(data1)
	data1 = data1[:n1]

	data2 := make([]byte, 1024)
	n2, _ := resp2.Body.Read(data2)
	data2 = data2[:n2]

	// Compare data lengths and content
	require.Equal(t, n1, n2, "Object data lengths don't match")
	require.Equal(t, data1, data2, "Object data content doesn't match")
}

// Legacy compatibility functions (deprecated - use TestContext instead)

// IsMinIOAvailable checks if MinIO service is running and available (deprecated)
func IsMinIOAvailable() bool {
	client, err := createMinIOClient()
	if err != nil {
		return false
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err = client.ListBuckets(ctx, &s3.ListBucketsInput{})
	return err == nil
}

// IsProxyAvailable checks if the S3 encryption proxy is running and available (deprecated)
func IsProxyAvailable() bool {
	client, err := createProxyClient()
	if err != nil {
		return false
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err = client.ListBuckets(ctx, &s3.ListBucketsInput{})
	return err == nil
}

// CreateMinIOClient creates an S3 client configured for MinIO (deprecated)
func CreateMinIOClient() (*s3.Client, error) {
	return createMinIOClient()
}

// CreateProxyClient creates an S3 client configured for the proxy (deprecated)
func CreateProxyClient() (*s3.Client, error) {
	return createProxyClient()
}

// EnsureMinIOAndProxyAvailable skips the test if either MinIO or proxy are not available
func EnsureMinIOAndProxyAvailable(t *testing.T) {
	SkipIfMinIONotAvailable(t)
	SkipIfProxyNotAvailable(t)
}

// CreateTestBucket creates a test bucket in MinIO (idempotent)
func CreateTestBucket(t *testing.T, client *s3.Client, bucketName string) {
	ctx := context.Background()

	// Try to create bucket (ignore error if it already exists)
	_, err := client.CreateBucket(ctx, &s3.CreateBucketInput{
		Bucket: aws.String(bucketName),
	})

	// Ignore "BucketAlreadyExists" errors
	if err != nil && !IsAlreadyExistsError(err) {
		t.Logf("Warning: Could not create test bucket %s: %v", bucketName, err)
	}
}

// CleanupTestBucket removes all objects and deletes the test bucket
func CleanupTestBucket(t *testing.T, client *s3.Client, bucketName string) {
	ctx := context.Background()

	// List and delete all objects in bucket
	listResp, err := client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
		Bucket: aws.String(bucketName),
	})
	if err == nil && len(listResp.Contents) > 0 {
		for _, obj := range listResp.Contents {
			_, err := client.DeleteObject(ctx, &s3.DeleteObjectInput{
				Bucket: aws.String(bucketName),
				Key:    obj.Key,
			})
			if err != nil {
				t.Logf("Warning: Could not delete object %s: %v", *obj.Key, err)
			}
		}
	}

	// Delete the bucket itself
	_, err = client.DeleteBucket(ctx, &s3.DeleteBucketInput{
		Bucket: aws.String(bucketName),
	})
	if err != nil {
		t.Logf("Warning: Could not delete test bucket %s: %v", bucketName, err)
	}
}

// IsAlreadyExistsError checks if an error indicates the resource already exists
func IsAlreadyExistsError(err error) bool {
	if err == nil {
		return false
	}
	errorStr := err.Error()
	return contains(errorStr, "BucketAlreadyExists") ||
		contains(errorStr, "BucketAlreadyOwnedByYou") ||
		contains(errorStr, "already exists")
}

// contains checks if a string contains a substring (case-insensitive helper)
func contains(s, substr string) bool {
	return len(s) >= len(substr) &&
		s[len(s)-len(substr):] == substr ||
		len(s) > len(substr) && s[:len(substr)] == substr ||
		(len(s) > len(substr) && findInString(s, substr))
}

func findInString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
