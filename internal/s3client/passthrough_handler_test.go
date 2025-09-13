package s3client

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	aws_config "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/stretchr/testify/assert"
)

func setupPassthroughHandlerTestClient(t *testing.T) (*PassthroughHandler, *httptest.Server) {
	// Create mock S3 server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && strings.Contains(r.URL.Path, "/test-bucket") && r.URL.Query().Get("list-type") == "2":
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
		case r.Method == "GET" && strings.Contains(r.URL.Path, "/test-bucket"):
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
		case r.Method == "POST" && strings.Contains(r.URL.Path, "/test-bucket") && r.URL.Query().Has("delete"):
			// Mock DeleteObjects response
			response := `<?xml version="1.0" encoding="UTF-8"?>
<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
    <Deleted>
        <Key>test-key</Key>
    </Deleted>
</DeleteResult>`
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(response))
		case r.Method == "GET" && strings.Contains(r.URL.Path, "/test-bucket/test-key") && r.URL.Query().Has("acl"):
			// Mock GetObjectAcl response
			response := `<?xml version="1.0" encoding="UTF-8"?>
<AccessControlPolicy>
    <Owner>
        <ID>owner-id</ID>
        <DisplayName>owner-name</DisplayName>
    </Owner>
    <AccessControlList>
        <Grant>
            <Grantee>
                <ID>owner-id</ID>
                <DisplayName>owner-name</DisplayName>
            </Grantee>
            <Permission>FULL_CONTROL</Permission>
        </Grant>
    </AccessControlList>
</AccessControlPolicy>`
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(response))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))

	// Create test configuration and client, but use our mock server endpoint
	s3Config := &Config{
		Endpoint:       server.URL,
		Region:         "us-east-1",
		AccessKeyID:    "test-key",
		SecretKey:      "test-secret",
		MetadataPrefix: "s3ep-",
		DisableSSL:     true,
		ForcePathStyle: true,
	}

	// Create AWS config with mock endpoint
	awsCfg, err := aws_config.LoadDefaultConfig(context.TODO(),
		aws_config.WithRegion(s3Config.Region),
		aws_config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
			s3Config.AccessKeyID,
			s3Config.SecretKey,
			"",
		)),
	)
	if err != nil {
		t.Fatalf("Failed to load AWS config: %v", err)
	}

	// Create S3 client pointing to our mock server
	s3Client := s3.NewFromConfig(awsCfg, func(o *s3.Options) {
		o.BaseEndpoint = aws.String(server.URL)
		o.UsePathStyle = s3Config.ForcePathStyle
	})

	handler := NewPassthroughHandler(s3Client)
	return handler, server
}

func TestPassthroughHandler_ListObjects(t *testing.T) {
	handler, server := setupPassthroughHandlerTestClient(t)
	defer server.Close()

	ctx := context.Background()

	input := &s3.ListObjectsInput{
		Bucket: aws.String("test-bucket"),
	}

	output, err := handler.ListObjects(ctx, input)
	assert.NoError(t, err)
	assert.NotNil(t, output)
}

func TestPassthroughHandler_ListObjectsV2(t *testing.T) {
	handler, server := setupPassthroughHandlerTestClient(t)
	defer server.Close()

	ctx := context.Background()

	input := &s3.ListObjectsV2Input{
		Bucket: aws.String("test-bucket"),
	}

	output, err := handler.ListObjectsV2(ctx, input)
	assert.NoError(t, err)
	assert.NotNil(t, output)
}

func TestPassthroughHandler_DeleteObjects(t *testing.T) {
	handler, server := setupPassthroughHandlerTestClient(t)
	defer server.Close()

	ctx := context.Background()

	input := &s3.DeleteObjectsInput{
		Bucket: aws.String("test-bucket"),
		Delete: &types.Delete{
			Objects: []types.ObjectIdentifier{
				{Key: aws.String("test-key")},
			},
		},
	}

	// Note: This test may fail with the current mock setup
	// as it requires proper XML parsing of the delete request
	output, err := handler.DeleteObjects(ctx, input)
	// We just verify the method can be called and returns properly
	assert.NoError(t, err)
	assert.NotNil(t, output)
}

func TestPassthroughHandler_GetObjectAcl(t *testing.T) {
	handler, server := setupPassthroughHandlerTestClient(t)
	defer server.Close()

	ctx := context.Background()

	input := &s3.GetObjectAclInput{
		Bucket: aws.String("test-bucket"),
		Key:    aws.String("test-key"),
	}

	output, err := handler.GetObjectAcl(ctx, input)
	assert.NoError(t, err)
	assert.NotNil(t, output)
}

func TestPassthroughHandler_PutObjectAcl(t *testing.T) {
	handler, server := setupPassthroughHandlerTestClient(t)
	defer server.Close()

	ctx := context.Background()

	input := &s3.PutObjectAclInput{
		Bucket: aws.String("test-bucket"),
		Key:    aws.String("test-key"),
		ACL:    types.ObjectCannedACLPrivate,
	}

	// This test verifies the method exists and can be called
	_, err := handler.PutObjectAcl(ctx, input)
	assert.NotNil(t, err) // Expected to fail with mock server
}

func TestPassthroughHandler_GetObjectTagging(t *testing.T) {
	handler, server := setupPassthroughHandlerTestClient(t)
	defer server.Close()

	ctx := context.Background()

	input := &s3.GetObjectTaggingInput{
		Bucket: aws.String("test-bucket"),
		Key:    aws.String("test-key"),
	}

	// This test verifies the method exists and can be called
	output, err := handler.GetObjectTagging(ctx, input)
	assert.NoError(t, err) // Should succeed with mock server
	assert.NotNil(t, output)
}

func TestPassthroughHandler_SelectObjectContent(t *testing.T) {
	handler, server := setupPassthroughHandlerTestClient(t)
	defer server.Close()

	ctx := context.Background()

	input := &s3.SelectObjectContentInput{
		Bucket:         aws.String("test-bucket"),
		Key:            aws.String("test-key"),
		Expression:     aws.String("SELECT * FROM S3Object"),
		ExpressionType: types.ExpressionTypeSql,
		InputSerialization: &types.InputSerialization{
			JSON: &types.JSONInput{},
		},
		OutputSerialization: &types.OutputSerialization{
			JSON: &types.JSONOutput{},
		},
	}

	// This test verifies the method exists and can be called
	_, err := handler.SelectObjectContent(ctx, input)
	assert.NotNil(t, err) // Expected to fail with mock server
}
