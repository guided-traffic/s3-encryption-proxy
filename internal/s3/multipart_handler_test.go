package s3

import (
	"bytes"
	"context"
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

func setupMultipartHandlerTestClient(t *testing.T) (*Client, *httptest.Server) {
	// Create mock S3 server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "POST" && strings.Contains(r.URL.Query().Get("uploads"), ""):
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
		case r.Method == "PUT" && strings.Contains(r.URL.Query().Get("partNumber"), "1"):
			// Mock UploadPart
			w.Header().Set("ETag", `"part-etag-1"`)
			w.WriteHeader(http.StatusOK)
		case r.Method == "POST" && strings.Contains(r.URL.Query().Get("uploadId"), "test-upload-id"):
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
		case r.Method == "DELETE" && strings.Contains(r.URL.Query().Get("uploadId"), "test-upload-id"):
			// Mock AbortMultipartUpload
			w.WriteHeader(http.StatusNoContent)
		case r.Method == "GET" && strings.Contains(r.URL.Query().Get("uploadId"), "test-upload-id"):
			// Mock ListParts
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusOK)
			response := `<?xml version="1.0" encoding="UTF-8"?>
<ListPartsResult>
    <Bucket>test-bucket</Bucket>
    <Key>test-key</Key>
    <UploadId>test-upload-id</UploadId>
    <Part>
        <PartNumber>1</PartNumber>
        <ETag>"part-etag-1"</ETag>
        <Size>1024</Size>
    </Part>
</ListPartsResult>`
			_, _ = w.Write([]byte(response))
		case r.Method == "GET" && strings.Contains(r.URL.Query().Get("uploads"), ""):
			// Mock ListMultipartUploads
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusOK)
			response := `<?xml version="1.0" encoding="UTF-8"?>
<ListMultipartUploadsResult>
    <Bucket>test-bucket</Bucket>
    <Upload>
        <Key>test-key</Key>
        <UploadId>test-upload-id</UploadId>
    </Upload>
</ListMultipartUploadsResult>`
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

func TestMultipartHandler_CreateMultipartUpload(t *testing.T) {
	client, server := setupMultipartHandlerTestClient(t)
	defer server.Close()

	ctx := context.Background()

	input := &s3.CreateMultipartUploadInput{
		Bucket:      aws.String("test-bucket"),
		Key:         aws.String("test-key"),
		ContentType: aws.String("application/octet-stream"),
		Metadata: map[string]string{
			"custom-header": "custom-value",
		},
	}

	output, err := client.multipartHandler.CreateMultipartUpload(ctx, input)
	assert.NoError(t, err)
	assert.NotNil(t, output)
	assert.Equal(t, "test-upload-id", aws.ToString(output.UploadId))
}

func TestMultipartHandler_UploadPart(t *testing.T) {
	client, server := setupMultipartHandlerTestClient(t)
	defer server.Close()

	ctx := context.Background()
	testData := []byte("test part data for multipart upload")

	// First create a multipart upload
	createInput := &s3.CreateMultipartUploadInput{
		Bucket: aws.String("test-bucket"),
		Key:    aws.String("test-key"),
	}

	createOutput, err := client.multipartHandler.CreateMultipartUpload(ctx, createInput)
	require.NoError(t, err)

	// Upload a part
	partInput := &s3.UploadPartInput{
		Bucket:     aws.String("test-bucket"),
		Key:        aws.String("test-key"),
		UploadId:   createOutput.UploadId,
		PartNumber: aws.Int32(1),
		Body:       bytes.NewReader(testData),
	}

	partOutput, err := client.multipartHandler.UploadPart(ctx, partInput)
	assert.NoError(t, err)
	assert.NotNil(t, partOutput)
	assert.Equal(t, `"part-etag-1"`, aws.ToString(partOutput.ETag))
}

func TestMultipartHandler_CompleteMultipartUpload(t *testing.T) {
	client, server := setupMultipartHandlerTestClient(t)
	defer server.Close()

	ctx := context.Background()

	// Create multipart upload and upload a part first
	createInput := &s3.CreateMultipartUploadInput{
		Bucket: aws.String("test-bucket"),
		Key:    aws.String("test-key"),
	}

	createOutput, err := client.multipartHandler.CreateMultipartUpload(ctx, createInput)
	require.NoError(t, err)

	partInput := &s3.UploadPartInput{
		Bucket:     aws.String("test-bucket"),
		Key:        aws.String("test-key"),
		UploadId:   createOutput.UploadId,
		PartNumber: aws.Int32(1),
		Body:       bytes.NewReader([]byte("test data")),
	}

	partOutput, err := client.multipartHandler.UploadPart(ctx, partInput)
	require.NoError(t, err)

	// Complete the upload
	completeInput := &s3.CompleteMultipartUploadInput{
		Bucket:   aws.String("test-bucket"),
		Key:      aws.String("test-key"),
		UploadId: createOutput.UploadId,
		MultipartUpload: &types.CompletedMultipartUpload{
			Parts: []types.CompletedPart{
				{
					ETag:       partOutput.ETag,
					PartNumber: aws.Int32(1),
				},
			},
		},
	}

	completeOutput, err := client.multipartHandler.CompleteMultipartUpload(ctx, completeInput)
	assert.NoError(t, err)
	assert.NotNil(t, completeOutput)
	assert.Equal(t, `"complete-etag"`, aws.ToString(completeOutput.ETag))
}

func TestMultipartHandler_AbortMultipartUpload(t *testing.T) {
	client, server := setupMultipartHandlerTestClient(t)
	defer server.Close()

	ctx := context.Background()

	// Create multipart upload first
	createInput := &s3.CreateMultipartUploadInput{
		Bucket: aws.String("test-bucket"),
		Key:    aws.String("test-key"),
	}

	createOutput, err := client.multipartHandler.CreateMultipartUpload(ctx, createInput)
	require.NoError(t, err)

	// Abort the upload
	abortInput := &s3.AbortMultipartUploadInput{
		Bucket:   aws.String("test-bucket"),
		Key:      aws.String("test-key"),
		UploadId: createOutput.UploadId,
	}

	abortOutput, err := client.multipartHandler.AbortMultipartUpload(ctx, abortInput)
	assert.NoError(t, err)
	assert.NotNil(t, abortOutput)
}

func TestMultipartHandler_ListParts(t *testing.T) {
	client, server := setupMultipartHandlerTestClient(t)
	defer server.Close()

	ctx := context.Background()

	input := &s3.ListPartsInput{
		Bucket:   aws.String("test-bucket"),
		Key:      aws.String("test-key"),
		UploadId: aws.String("test-upload-id"),
	}

	output, err := client.multipartHandler.ListParts(ctx, input)
	assert.NoError(t, err)
	assert.NotNil(t, output)
}

func TestMultipartHandler_ListMultipartUploads(t *testing.T) {
	client, server := setupMultipartHandlerTestClient(t)
	defer server.Close()

	ctx := context.Background()

	input := &s3.ListMultipartUploadsInput{
		Bucket: aws.String("test-bucket"),
	}

	output, err := client.multipartHandler.ListMultipartUploads(ctx, input)
	assert.NoError(t, err)
	assert.NotNil(t, output)
}
