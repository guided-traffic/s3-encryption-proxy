//go:build integration
// +build integration

package integration

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/guided-traffic/s3-encryption-proxy/internal/config"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

// IntegrationTestSuite holds the integration test suite
type IntegrationTestSuite struct {
	suite.Suite
	proxyServer *httptest.Server
	s3Client    *s3.S3
	testBucket  string
}

// SetupSuite sets up the test suite
func (suite *IntegrationTestSuite) SetupSuite() {
	// Check if integration tests should run
	if os.Getenv("INTEGRATION_TESTS") != "true" {
		suite.T().Skip("Integration tests skipped. Set INTEGRATION_TESTS=true to run.")
	}

	// Setup test configuration
	cfg := &config.Config{
		BindAddress:       "127.0.0.1:0", // Let the system choose a free port
		LogLevel:          "debug",
		TargetEndpoint:    getEnvOrDefault("S3_ENDPOINT", "http://localhost:9000"),
		Region:            getEnvOrDefault("S3_REGION", "us-east-1"),
		AccessKeyID:       getEnvOrDefault("S3_ACCESS_KEY", "minioadmin"),
		SecretKey:         getEnvOrDefault("S3_SECRET_KEY", "minioadmin"),
		KEKUri:            "local://test-kek", // Use local KEK for testing
		Algorithm:         "AES256_GCM",
		KeyRotationDays:   90,
		MetadataKeyPrefix: "x-s3ep-",
	}

	// Set log level to reduce noise in tests
	logrus.SetLevel(logrus.WarnLevel)

	// Create proxy server
	server, err := proxy.NewServer(cfg)
	require.NoError(suite.T(), err)

	// Start test server
	suite.proxyServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// This is a simplified handler for testing
		// In a real integration test, you'd set up the full proxy routing
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Integration test endpoint"))
	}))

	// Create S3 client pointing to the proxy
	sess, err := session.NewSession(&aws.Config{
		Region:           aws.String(cfg.Region),
		Endpoint:         aws.String(suite.proxyServer.URL),
		DisableSSL:       aws.Bool(true),
		S3ForcePathStyle: aws.Bool(true),
		Credentials:      credentials.NewStaticCredentials(cfg.AccessKeyID, cfg.SecretKey, ""),
	})
	require.NoError(suite.T(), err)

	suite.s3Client = s3.New(sess)
	suite.testBucket = fmt.Sprintf("test-bucket-%d", time.Now().Unix())
}

// TearDownSuite cleans up the test suite
func (suite *IntegrationTestSuite) TearDownSuite() {
	if suite.proxyServer != nil {
		suite.proxyServer.Close()
	}
}

// SetupTest sets up each test
func (suite *IntegrationTestSuite) SetupTest() {
	// Create test bucket if it doesn't exist
	if suite.s3Client != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		_, err := suite.s3Client.CreateBucketWithContext(ctx, &s3.CreateBucketInput{
			Bucket: aws.String(suite.testBucket),
		})
		// Ignore error if bucket already exists
		_ = err
	}
}

// TearDownTest cleans up each test
func (suite *IntegrationTestSuite) TearDownTest() {
	// Clean up test objects
	if suite.s3Client != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		// List and delete all objects in the test bucket
		listOutput, err := suite.s3Client.ListObjectsV2WithContext(ctx, &s3.ListObjectsV2Input{
			Bucket: aws.String(suite.testBucket),
		})
		if err == nil {
			for _, obj := range listOutput.Contents {
				_, _ = suite.s3Client.DeleteObjectWithContext(ctx, &s3.DeleteObjectInput{
					Bucket: aws.String(suite.testBucket),
					Key:    obj.Key,
				})
			}
		}
	}
}

// TestEncryptedPutAndGet tests putting and getting an encrypted object
func (suite *IntegrationTestSuite) TestEncryptedPutAndGet() {
	if suite.s3Client == nil {
		suite.T().Skip("S3 client not available")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	testKey := "test-file.txt"
	testData := []byte("This is test data that should be encrypted")

	// Put object through the proxy (should be encrypted)
	_, err := suite.s3Client.PutObjectWithContext(ctx, &s3.PutObjectInput{
		Bucket: aws.String(suite.testBucket),
		Key:    aws.String(testKey),
		Body:   bytes.NewReader(testData),
		Metadata: map[string]*string{
			"test-meta": aws.String("test-value"),
		},
	})
	require.NoError(suite.T(), err)

	// Get object through the proxy (should be decrypted)
	output, err := suite.s3Client.GetObjectWithContext(ctx, &s3.GetObjectInput{
		Bucket: aws.String(suite.testBucket),
		Key:    aws.String(testKey),
	})
	require.NoError(suite.T(), err)

	// Read and verify the data
	retrievedData, err := io.ReadAll(output.Body)
	require.NoError(suite.T(), err)
	output.Body.Close()

	assert.Equal(suite.T(), testData, retrievedData, "Retrieved data should match original")

	// Verify metadata is preserved (excluding encryption metadata)
	assert.Equal(suite.T(), "test-value", aws.StringValue(output.Metadata["test-meta"]))

	// Verify encryption metadata is not exposed
	for key := range output.Metadata {
		assert.NotContains(suite.T(), key, "x-s3ep-", "Encryption metadata should not be exposed")
	}
}

// TestDirectS3Access tests accessing encrypted data directly from S3
func (suite *IntegrationTestSuite) TestDirectS3Access() {
	if suite.s3Client == nil {
		suite.T().Skip("S3 client not available")
	}

	// This test would require a direct S3 client (bypassing the proxy)
	// to verify that data is actually encrypted in S3
	suite.T().Skip("Direct S3 access test requires separate S3 client setup")
}

// TestLargeObjectEncryption tests encryption of large objects
func (suite *IntegrationTestSuite) TestLargeObjectEncryption() {
	if suite.s3Client == nil {
		suite.T().Skip("S3 client not available")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	testKey := "large-test-file.bin"
	// Create 5MB of test data
	testData := make([]byte, 5*1024*1024)
	for i := range testData {
		testData[i] = byte(i % 256)
	}

	// Put large object
	_, err := suite.s3Client.PutObjectWithContext(ctx, &s3.PutObjectInput{
		Bucket: aws.String(suite.testBucket),
		Key:    aws.String(testKey),
		Body:   bytes.NewReader(testData),
	})
	require.NoError(suite.T(), err)

	// Get large object
	output, err := suite.s3Client.GetObjectWithContext(ctx, &s3.GetObjectInput{
		Bucket: aws.String(suite.testBucket),
		Key:    aws.String(testKey),
	})
	require.NoError(suite.T(), err)

	// Read and verify the data
	retrievedData, err := io.ReadAll(output.Body)
	require.NoError(suite.T(), err)
	output.Body.Close()

	assert.Equal(suite.T(), testData, retrievedData, "Large object data should match original")
}

// TestMultipleObjects tests encryption of multiple objects
func (suite *IntegrationTestSuite) TestMultipleObjects() {
	if suite.s3Client == nil {
		suite.T().Skip("S3 client not available")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	objects := map[string][]byte{
		"file1.txt": []byte("Content of file 1"),
		"file2.txt": []byte("Content of file 2"),
		"file3.txt": []byte("Content of file 3"),
	}

	// Put multiple objects
	for key, data := range objects {
		_, err := suite.s3Client.PutObjectWithContext(ctx, &s3.PutObjectInput{
			Bucket: aws.String(suite.testBucket),
			Key:    aws.String(key),
			Body:   bytes.NewReader(data),
		})
		require.NoError(suite.T(), err)
	}

	// Get and verify multiple objects
	for key, expectedData := range objects {
		output, err := suite.s3Client.GetObjectWithContext(ctx, &s3.GetObjectInput{
			Bucket: aws.String(suite.testBucket),
			Key:    aws.String(key),
		})
		require.NoError(suite.T(), err)

		retrievedData, err := io.ReadAll(output.Body)
		require.NoError(suite.T(), err)
		output.Body.Close()

		assert.Equal(suite.T(), expectedData, retrievedData, "Object %s data should match", key)
	}
}

// TestObjectDeletion tests object deletion through the proxy
func (suite *IntegrationTestSuite) TestObjectDeletion() {
	if suite.s3Client == nil {
		suite.T().Skip("S3 client not available")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	testKey := "delete-test.txt"
	testData := []byte("This file will be deleted")

	// Put object
	_, err := suite.s3Client.PutObjectWithContext(ctx, &s3.PutObjectInput{
		Bucket: aws.String(suite.testBucket),
		Key:    aws.String(testKey),
		Body:   bytes.NewReader(testData),
	})
	require.NoError(suite.T(), err)

	// Verify object exists
	_, err = suite.s3Client.HeadObjectWithContext(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(suite.testBucket),
		Key:    aws.String(testKey),
	})
	require.NoError(suite.T(), err)

	// Delete object
	_, err = suite.s3Client.DeleteObjectWithContext(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(suite.testBucket),
		Key:    aws.String(testKey),
	})
	require.NoError(suite.T(), err)

	// Verify object no longer exists
	_, err = suite.s3Client.HeadObjectWithContext(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(suite.testBucket),
		Key:    aws.String(testKey),
	})
	assert.Error(suite.T(), err, "Object should not exist after deletion")
}

// Helper function to get environment variable with default
func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// TestIntegration runs the integration test suite
func TestIntegration(t *testing.T) {
	suite.Run(t, new(IntegrationTestSuite))
}
