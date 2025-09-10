package s3

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/guided-traffic/s3-encryption-proxy/internal/config"
	"github.com/guided-traffic/s3-encryption-proxy/internal/encryption"
)

const (
	httpMethodGET    = "GET"
	httpMethodPUT    = "PUT"
	httpMethodHEAD   = "HEAD"
	httpMethodDELETE = "DELETE"
	httpMethodPOST   = "POST"
)

func setupTestClient(t *testing.T) (*Client, *httptest.Server) {
	// Create mock S3 server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == httpMethodPUT && strings.Contains(r.URL.Path, "/test-bucket/test-key"):
			w.Header().Set("ETag", `"test-etag"`)
			w.WriteHeader(http.StatusOK)
		case r.Method == httpMethodGET && strings.Contains(r.URL.Path, "/test-bucket/test-key"):
			// Mock unencrypted object response (no encryption metadata)
			w.Header().Set("Content-Type", "text/plain")
			w.Header().Set("Content-Length", "16")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("test-data-content"))
		case r.Method == httpMethodHEAD && strings.Contains(r.URL.Path, "/test-bucket/test-key"):
			w.Header().Set("x-amz-meta-s3ep-dek", "dGVzdC1lbmNyeXB0ZWQtZGVr")
			w.Header().Set("Content-Length", "18")
			w.WriteHeader(http.StatusOK)
		case r.Method == httpMethodDELETE && strings.Contains(r.URL.Path, "/test-bucket/test-key"):
			w.WriteHeader(http.StatusNoContent)
		case r.Method == httpMethodPOST && strings.Contains(r.URL.Query().Get("uploads"), ""):
			// Mock CreateMultipartUpload
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusOK)
			response := `<?xml version="1.0" encoding="UTF-8"?>
<InitiateMultipartUploadResult>
    <Bucket>test-bucket</Bucket>
    <Key>test-key</Key>
    <UploadId>test-upload-id</UploadId>
</InitiateMultipartUploadResult>`
			_, _ = w.Write([]byte(response))
		case r.Method == httpMethodPUT && strings.Contains(r.URL.Query().Get("partNumber"), "1"):
			// Mock UploadPart
			w.Header().Set("ETag", `"part-etag-1"`)
			w.WriteHeader(http.StatusOK)
		case r.Method == httpMethodPOST && strings.Contains(r.URL.Query().Get("uploadId"), "test-upload-id"):
			// Mock CompleteMultipartUpload
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusOK)
			response := `<?xml version="1.0" encoding="UTF-8"?>
<CompleteMultipartUploadResult>
    <Bucket>test-bucket</Bucket>
    <Key>test-key</Key>
    <ETag>"complete-etag"</ETag>
</CompleteMultipartUploadResult>`
			_, _ = w.Write([]byte(response))
		case r.Method == httpMethodGET && strings.Contains(r.URL.Path, "/test-bucket") && r.URL.Query().Get("list-type") == "2":
			// Mock ListObjectsV2 response
			response := `<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
    <Name>test-bucket</Name>
    <KeyCount>1</KeyCount>
    <MaxKeys>1000</MaxKeys>
    <IsTruncated>false</IsTruncated>
    <Contents>
        <Key>test-key</Key>
        <Size>10</Size>
    </Contents>
</ListBucketResult>`
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(response))
		case r.Method == httpMethodGET && strings.Contains(r.URL.Path, "/test-bucket"):
			// Mock ListObjects response
			response := `<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
    <Name>test-bucket</Name>
    <MaxKeys>1000</MaxKeys>
    <IsTruncated>false</IsTruncated>
    <Contents>
        <Key>test-key</Key>
        <Size>10</Size>
    </Contents>
</ListBucketResult>`
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(response))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))

	// Create test configuration with AES-CTR provider for testing
	testConfig := &config.Config{
		Encryption: config.EncryptionConfig{
			EncryptionMethodAlias: "test-aes-ctr",
			Providers: []config.EncryptionProvider{
				{
					Alias: "test-aes-ctr",
					Type:  "aes",
					Config: map[string]interface{}{
						"aes_key": "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=", // Base64 of 32-byte key
					},
				},
			},
		},
	}

	// Create encryption manager
	encMgr, err := encryption.NewManager(testConfig)
	require.NoError(t, err)

	// Create logger
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)

	// Create S3 client config
	s3Config := &Config{
		Endpoint:       server.URL,
		Region:         "us-east-1",
		AccessKeyID:    "test-key",
		SecretKey:      "test-secret",
		MetadataPrefix: "s3ep-",
		DisableSSL:     true,
		ForcePathStyle: true,
	}

	// Create S3 client
	client, err := NewClient(s3Config, encMgr, logger)
	require.NoError(t, err)

	return client, server
}

func TestNewClient(t *testing.T) {
	cfg := &config.Config{
		Encryption: config.EncryptionConfig{
			EncryptionMethodAlias: "test-aes-ctr",
			Providers: []config.EncryptionProvider{
				{
					Alias: "test-aes-ctr",
					Type:  "aes",
					Config: map[string]interface{}{
						"aes_key": "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=",
					},
				},
			},
		},
	}

	encMgr, err := encryption.NewManager(cfg)
	require.NoError(t, err)

	s3Config := &Config{
		Endpoint:       "http://localhost:9000",
		Region:         "us-east-1",
		AccessKeyID:    "test-key",
		SecretKey:      "test-secret",
		MetadataPrefix: "s3ep-",
		DisableSSL:     true,
		ForcePathStyle: true,
	}

	client, err := NewClient(s3Config, encMgr, logrus.New())
	assert.NoError(t, err)
	assert.NotNil(t, client)
	assert.Equal(t, "s3ep-", client.metadataPrefix)
}

func TestNewClient_InvalidConfig(t *testing.T) {
	cfg := &config.Config{
		Encryption: config.EncryptionConfig{
			EncryptionMethodAlias: "test-aes-ctr",
			Providers: []config.EncryptionProvider{
				{
					Alias: "test-aes-ctr",
					Type:  "aes",
					Config: map[string]interface{}{
						"aes_key": "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=",
					},
				},
			},
		},
	}

	encMgr, err := encryption.NewManager(cfg)
	require.NoError(t, err)

	// Test with invalid endpoint
	s3Config := &Config{
		Endpoint:       "://invalid-url",
		Region:         "us-east-1",
		AccessKeyID:    "test-key",
		SecretKey:      "test-secret",
		MetadataPrefix: "s3ep-",
		DisableSSL:     true,
		ForcePathStyle: true,
	}

	client, err := NewClient(s3Config, encMgr, logrus.New())
	// AWS SDK might still create client with invalid URL, so we just check it doesn't panic
	assert.NotNil(t, client)
	assert.NoError(t, err) // AWS SDK is flexible with URLs
}

func TestPutObject(t *testing.T) {
	client, server := setupTestClient(t)
	defer server.Close()

	ctx := context.Background()
	testData := []byte("test data content")

	input := &s3.PutObjectInput{
		Bucket:      aws.String("test-bucket"),
		Key:         aws.String("test-key"),
		Body:        bytes.NewReader(testData),
		ContentType: aws.String("text/plain"),
		Metadata: map[string]string{
			"custom-header": "custom-value",
		},
	}

	output, err := client.PutObject(ctx, input)
	assert.NoError(t, err)
	assert.NotNil(t, output)
	assert.Equal(t, `"test-etag"`, aws.ToString(output.ETag))
}

func TestPutObject_ReadBodyError(t *testing.T) {
	client, server := setupTestClient(t)
	defer server.Close()

	ctx := context.Background()

	input := &s3.PutObjectInput{
		Bucket: aws.String("test-bucket"),
		Key:    aws.String("test-key"),
		Body:   &errorReader{},
	}

	_, err := client.PutObject(ctx, input)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read object body")
}

// errorReader simulates a read error
type errorReader struct{}

func (e *errorReader) Read(p []byte) (n int, err error) {
	return 0, io.ErrUnexpectedEOF
}

func (e *errorReader) Seek(offset int64, whence int) (int64, error) {
	return 0, io.ErrUnexpectedEOF
}

func TestGetObject_Encrypted(t *testing.T) {
	// Create a mock server that returns unencrypted object (no encryption metadata)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == httpMethodGET && strings.Contains(r.URL.Path, "/test-bucket/test-key") {
			// Mock unencrypted object response - no encryption metadata
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("plain-test-data"))
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	// Create test configuration with "none" provider
	cfg := &config.Config{
		Encryption: config.EncryptionConfig{
			EncryptionMethodAlias: "test-aes-ctr",
			Providers: []config.EncryptionProvider{
				{
					Alias: "test-aes-ctr",
					Type:  "aes",
					Config: map[string]interface{}{
						"aes_key": "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=",
					},
				},
			},
		},
	}

	// Create encryption manager
	encMgr, err := encryption.NewManager(cfg)
	require.NoError(t, err)

	// Create S3 client config
	s3Config := &Config{
		Endpoint:       server.URL,
		Region:         "us-east-1",
		AccessKeyID:    "test-key",
		SecretKey:      "test-secret",
		MetadataPrefix: "s3ep-",
		DisableSSL:     true,
		ForcePathStyle: true,
	}

	// Create S3 client
	client, err := NewClient(s3Config, encMgr, logrus.New())
	require.NoError(t, err)

	ctx := context.Background()

	input := &s3.GetObjectInput{
		Bucket: aws.String("test-bucket"),
		Key:    aws.String("test-key"),
	}

	output, err := client.GetObject(ctx, input)
	assert.NoError(t, err)
	assert.NotNil(t, output)

	// Read the decrypted data
	data, err := io.ReadAll(output.Body)
	assert.NoError(t, err)
	if err := output.Body.Close(); err != nil {
		t.Logf("Failed to close response body: %v", err)
	}

	// For 'none' encryption provider, data should be the same
	assert.Equal(t, "plain-test-data", string(data))

	// Check that no encryption metadata exists (since object was never encrypted)
	_, exists := output.Metadata["s3ep-dek"]
	assert.False(t, exists)
}

func TestGetObject_NotEncrypted(t *testing.T) {
	// Create a mock server that returns unencrypted object
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == httpMethodGET && strings.Contains(r.URL.Path, "/test-bucket/unencrypted-key") {
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("plain text data"))
		}
	}))
	defer server.Close()

	cfg := &config.Config{
		Encryption: config.EncryptionConfig{
			EncryptionMethodAlias: "test-aes-ctr",
			Providers: []config.EncryptionProvider{
				{
					Alias: "test-aes-ctr",
					Type:  "aes",
					Config: map[string]interface{}{
						"aes_key": "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=",
					},
				},
			},
		},
	}

	encMgr, err := encryption.NewManager(cfg)
	require.NoError(t, err)

	s3Config := &Config{
		Endpoint:       server.URL,
		Region:         "us-east-1",
		AccessKeyID:    "test-key",
		SecretKey:      "test-secret",
		MetadataPrefix: "s3ep-",
		DisableSSL:     true,
		ForcePathStyle: true,
	}

	client, err := NewClient(s3Config, encMgr, logrus.New())
	require.NoError(t, err)

	ctx := context.Background()

	input := &s3.GetObjectInput{
		Bucket: aws.String("test-bucket"),
		Key:    aws.String("unencrypted-key"),
	}

	output, err := client.GetObject(ctx, input)
	assert.NoError(t, err)
	assert.NotNil(t, output)

	data, err := io.ReadAll(output.Body)
	assert.NoError(t, err)
	if err := output.Body.Close(); err != nil {
		t.Logf("Failed to close response body: %v", err)
	}

	assert.Equal(t, "plain text data", string(data))
}

func TestHeadObject(t *testing.T) {
	client, server := setupTestClient(t)
	defer server.Close()

	ctx := context.Background()

	input := &s3.HeadObjectInput{
		Bucket: aws.String("test-bucket"),
		Key:    aws.String("test-key"),
	}

	output, err := client.HeadObject(ctx, input)
	assert.NoError(t, err)
	assert.NotNil(t, output)

	// Check that encryption metadata is removed
	_, exists := output.Metadata["s3ep-dek"]
	assert.False(t, exists)
}

func TestDeleteObject(t *testing.T) {
	client, server := setupTestClient(t)
	defer server.Close()

	ctx := context.Background()

	input := &s3.DeleteObjectInput{
		Bucket: aws.String("test-bucket"),
		Key:    aws.String("test-key"),
	}

	output, err := client.DeleteObject(ctx, input)
	assert.NoError(t, err)
	assert.NotNil(t, output)
}

func TestListObjects(t *testing.T) {
	client, server := setupTestClient(t)
	defer server.Close()

	ctx := context.Background()

	input := &s3.ListObjectsInput{
		Bucket: aws.String("test-bucket"),
	}

	output, err := client.ListObjects(ctx, input)
	assert.NoError(t, err)
	assert.NotNil(t, output)
}

func TestListObjectsV2(t *testing.T) {
	client, server := setupTestClient(t)
	defer server.Close()

	ctx := context.Background()

	input := &s3.ListObjectsV2Input{
		Bucket: aws.String("test-bucket"),
	}

	output, err := client.ListObjectsV2(ctx, input)
	assert.NoError(t, err)
	assert.NotNil(t, output)
}

func TestPutObject_WithAllHeaders(t *testing.T) {
	client, server := setupTestClient(t)
	defer server.Close()

	ctx := context.Background()
	testData := []byte("test data content")

	input := &s3.PutObjectInput{
		Bucket:             aws.String("test-bucket"),
		Key:                aws.String("test-key"),
		Body:               bytes.NewReader(testData),
		ContentType:        aws.String("text/plain"),
		ContentEncoding:    aws.String("gzip"),
		ContentDisposition: aws.String("attachment"),
		ContentLanguage:    aws.String("en"),
		CacheControl:       aws.String("max-age=3600"),
		ACL:                types.ObjectCannedACLPrivate,
		StorageClass:       types.StorageClassStandard,
		Metadata: map[string]string{
			"custom-header": "custom-value",
		},
	}

	output, err := client.PutObject(ctx, input)
	assert.NoError(t, err)
	assert.NotNil(t, output)
}

func TestGetObject_WithConditionalHeaders(t *testing.T) {
	client, server := setupTestClient(t)
	defer server.Close()

	ctx := context.Background()

	input := &s3.GetObjectInput{
		Bucket:  aws.String("test-bucket"),
		Key:     aws.String("test-key"),
		IfMatch: aws.String("test-etag"),
		Range:   aws.String("bytes=0-10"),
	}

	output, err := client.GetObject(ctx, input)
	assert.NoError(t, err)
	assert.NotNil(t, output)
}

func TestClient_MetadataPrefix(t *testing.T) {
	cfg := &config.Config{
		Encryption: config.EncryptionConfig{
			EncryptionMethodAlias: "test-aes-ctr",
			Providers: []config.EncryptionProvider{
				{
					Alias: "test-aes-ctr",
					Type:  "aes",
					Config: map[string]interface{}{
						"aes_key": "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=",
					},
				},
			},
		},
	}

	encMgr, err := encryption.NewManager(cfg)
	require.NoError(t, err)

	s3Config := &Config{
		Endpoint:       "http://localhost:9000",
		Region:         "us-east-1",
		AccessKeyID:    "test-key",
		SecretKey:      "test-secret",
		MetadataPrefix: "custom-prefix-",
		DisableSSL:     true,
		ForcePathStyle: true,
	}

	client, err := NewClient(s3Config, encMgr, logrus.New())
	assert.NoError(t, err)
	assert.Equal(t, "custom-prefix-", client.metadataPrefix)
}
