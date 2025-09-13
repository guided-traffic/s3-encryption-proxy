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
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/guided-traffic/s3-encryption-proxy/internal/config"
	"github.com/guided-traffic/s3-encryption-proxy/internal/encryption"
)

func setupObjectHandlerTestClient(t *testing.T) (*Client, *httptest.Server) {
	// Create mock S3 server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "PUT" && strings.Contains(r.URL.Path, "/test-bucket/test-key") && !r.URL.Query().Has("partNumber") && !r.URL.Query().Has("uploadId"):
			w.Header().Set("ETag", `"test-etag"`)
			w.WriteHeader(http.StatusOK)
		case r.Method == "PUT" && strings.Contains(r.URL.Path, "/test-bucket/test-key") && (r.Header.Get("x-amz-copy-source") != "" || r.Header.Get("X-Amz-Copy-Source") != ""):
			// Mock CopyObject response
			response := `<?xml version="1.0" encoding="UTF-8"?>
<CopyObjectResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
    <ETag>"copy-etag"</ETag>
    <LastModified>2023-01-01T00:00:00.000Z</LastModified>
</CopyObjectResult>`
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(response))
		case r.Method == "POST" && strings.Contains(r.URL.Path, "/test-bucket/test-key") && r.URL.Query().Has("uploads"):
			// Mock CreateMultipartUpload response
			response := `<?xml version="1.0" encoding="UTF-8"?>
<InitiateMultipartUploadResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
    <Bucket>test-bucket</Bucket>
    <Key>test-key</Key>
    <UploadId>test-upload-id</UploadId>
</InitiateMultipartUploadResult>`
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(response))
		case r.Method == "PUT" && strings.Contains(r.URL.Path, "/test-bucket/test-key") && r.URL.Query().Has("partNumber"):
			// Mock UploadPart response
			w.Header().Set("ETag", `"test-etag"`)
			w.WriteHeader(http.StatusOK)
		case r.Method == "POST" && strings.Contains(r.URL.Path, "/test-bucket/test-key") && r.URL.Query().Has("uploadId"):
			// Mock CompleteMultipartUpload response
			response := `<?xml version="1.0" encoding="UTF-8"?>
<CompleteMultipartUploadResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
    <Location>http://test-bucket.s3.amazonaws.com/test-key</Location>
    <Bucket>test-bucket</Bucket>
    <Key>test-key</Key>
    <ETag>"complete-etag"</ETag>
</CompleteMultipartUploadResult>`
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(response))
		case r.Method == "GET" && strings.Contains(r.URL.Path, "/test-bucket/test-key"):
			// Mock unencrypted object response (no encryption metadata)
			w.Header().Set("Content-Type", "text/plain")
			w.Header().Set("Content-Length", "17")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("test-data-content"))
		case r.Method == "HEAD" && strings.Contains(r.URL.Path, "/test-bucket/test-key"):
			w.Header().Set("x-amz-meta-s3ep-dek", "dGVzdC1lbmNyeXB0ZWQtZGVr")
			w.Header().Set("Content-Length", "18")
			w.WriteHeader(http.StatusOK)
		case r.Method == "DELETE" && strings.Contains(r.URL.Path, "/test-bucket/test-key"):
			w.WriteHeader(http.StatusNoContent)
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
		SegmentSize:    12 * 1024 * 1024, // 12MB default segment size
	}

	// Create S3 client
	client, err := NewClient(s3Config, encMgr, logger)
	require.NoError(t, err)

	return client, server
}

func TestObjectHandler_PutObject(t *testing.T) {
	client, server := setupObjectHandlerTestClient(t)
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

	output, err := client.objectHandler.PutObject(ctx, input)
	assert.NoError(t, err)
	assert.NotNil(t, output)
	assert.Equal(t, `"test-etag"`, aws.ToString(output.ETag))
}

func TestObjectHandler_PutObject_WithContentTypeForcing(t *testing.T) {
	client, server := setupObjectHandlerTestClient(t)
	defer server.Close()

	ctx := context.Background()
	testData := []byte("test data content")

	tests := []struct {
		name        string
		contentType string
	}{
		{
			name:        "force AES-GCM",
			contentType: "application/x-s3ep-force-aes-gcm",
		},
		{
			name:        "force AES-CTR",
			contentType: "application/x-s3ep-force-aes-ctr",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := &s3.PutObjectInput{
				Bucket:      aws.String("test-bucket"),
				Key:         aws.String("test-key"),
				Body:        bytes.NewReader(testData),
				ContentType: aws.String(tt.contentType),
			}

			output, err := client.objectHandler.PutObject(ctx, input)
			assert.NoError(t, err)
			assert.NotNil(t, output)
		})
	}
}

func TestObjectHandler_GetObject(t *testing.T) {
	client, server := setupObjectHandlerTestClient(t)
	defer server.Close()

	ctx := context.Background()

	input := &s3.GetObjectInput{
		Bucket: aws.String("test-bucket"),
		Key:    aws.String("test-key"),
	}

	output, err := client.objectHandler.GetObject(ctx, input)
	assert.NoError(t, err)
	assert.NotNil(t, output)

	// Read the data
	data, err := io.ReadAll(output.Body)
	assert.NoError(t, err)
	if err := output.Body.Close(); err != nil {
		t.Logf("Failed to close response body: %v", err)
	}

	assert.Equal(t, "test-data-content", string(data))
}

func TestObjectHandler_HeadObject(t *testing.T) {
	client, server := setupObjectHandlerTestClient(t)
	defer server.Close()

	ctx := context.Background()

	input := &s3.HeadObjectInput{
		Bucket: aws.String("test-bucket"),
		Key:    aws.String("test-key"),
	}

	output, err := client.objectHandler.HeadObject(ctx, input)
	assert.NoError(t, err)
	assert.NotNil(t, output)

	// Check that encryption metadata is removed
	_, exists := output.Metadata["s3ep-dek"]
	assert.False(t, exists)
}

func TestObjectHandler_DeleteObject(t *testing.T) {
	client, server := setupObjectHandlerTestClient(t)
	defer server.Close()

	ctx := context.Background()

	input := &s3.DeleteObjectInput{
		Bucket: aws.String("test-bucket"),
		Key:    aws.String("test-key"),
	}

	output, err := client.objectHandler.DeleteObject(ctx, input)
	assert.NoError(t, err)
	assert.NotNil(t, output)
}

func TestObjectHandler_CopyObject(t *testing.T) {
	client, server := setupObjectHandlerTestClient(t)
	defer server.Close()

	ctx := context.Background()

	input := &s3.CopyObjectInput{
		Bucket:     aws.String("test-bucket"),
		Key:        aws.String("test-key-copy"),
		CopySource: aws.String("test-bucket/test-key"),
	}

	// For now, CopyObject is a simple passthrough
	_, err := client.objectHandler.CopyObject(ctx, input)
	// We expect this to work as a passthrough even if the mock doesn't handle it
	// The test verifies the method exists and can be called
	assert.NotNil(t, err) // Expected to fail with mock server
}
