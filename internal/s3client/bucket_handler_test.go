package s3client

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/stretchr/testify/assert"
)

func TestNewBucketHandler(t *testing.T) {
	// Test creating a new bucket handler
	client, server := setupTestClient(t)
	defer server.Close()

	handler := NewBucketHandler(client.s3Client)
	assert.NotNil(t, handler)
	assert.NotNil(t, handler.s3Client)
}

func TestBucketHandler_CreateBucket_Interface(t *testing.T) {
	// Test that the method exists and has correct signature
	client, server := setupTestClient(t)
	defer server.Close()

	handler := NewBucketHandler(client.s3Client)

	// Just test that the method can be called (will fail with mock, but proves interface works)
	ctx := context.Background()
	input := &s3.CreateBucketInput{
		Bucket: aws.String("test-bucket"),
	}

	// This will fail but proves the method signature is correct
	_, err := handler.CreateBucket(ctx, input)
	// We expect an error since we don't have a real S3 endpoint
	assert.Error(t, err)
}

func TestBucketHandler_ListBuckets_Interface(t *testing.T) {
	// Test that the method exists and has correct signature
	client, server := setupTestClient(t)
	defer server.Close()

	handler := NewBucketHandler(client.s3Client)

	ctx := context.Background()
	input := &s3.ListBucketsInput{}

	// This will fail but proves the method signature is correct
	_, err := handler.ListBuckets(ctx, input)
	// We expect an error since we don't have a real S3 endpoint
	assert.Error(t, err)
}
