//go:build integration

package s3methods

import (
	"context"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/guided-traffic/s3-encryption-proxy/test/integration"
)

func TestDeleteObjectFunctionality(t *testing.T) {
	ctx := integration.NewTestContext(t)
	defer ctx.CleanupTestBucket()

	t.Run("DeleteObject_BasicFunctionality", func(t *testing.T) {
		// Create a test object first
		testKey := "test-delete-object-" + integration.RandomString(8)
		testContent := "This is test content for delete operation"

		// Put object via proxy
		_, err := ctx.ProxyClient.PutObject(context.Background(), &s3.PutObjectInput{
			Bucket: aws.String(ctx.TestBucket),
			Key:    aws.String(testKey),
			Body:   strings.NewReader(testContent),
		})
		require.NoError(t, err, "Should be able to create test object")

		// Verify object exists
		_, err = ctx.ProxyClient.HeadObject(context.Background(), &s3.HeadObjectInput{
			Bucket: aws.String(ctx.TestBucket),
			Key:    aws.String(testKey),
		})
		require.NoError(t, err, "Object should exist before deletion")

		// Delete object via proxy
		deleteOutput, err := ctx.ProxyClient.DeleteObject(context.Background(), &s3.DeleteObjectInput{
			Bucket: aws.String(ctx.TestBucket),
			Key:    aws.String(testKey),
		})
		require.NoError(t, err, "DeleteObject should succeed")
		assert.NotNil(t, deleteOutput, "DeleteObject output should not be nil")

		// Verify object no longer exists
		_, err = ctx.ProxyClient.HeadObject(context.Background(), &s3.HeadObjectInput{
			Bucket: aws.String(ctx.TestBucket),
			Key:    aws.String(testKey),
		})
		assert.Error(t, err, "Object should not exist after deletion")

		t.Logf("✅ Successfully deleted object %s", testKey)
	})

	t.Run("DeleteObject_NonExistentObject", func(t *testing.T) {
		// Try to delete a non-existent object
		nonExistentKey := "non-existent-object-" + integration.RandomString(8)

		deleteOutput, err := ctx.ProxyClient.DeleteObject(context.Background(), &s3.DeleteObjectInput{
			Bucket: aws.String(ctx.TestBucket),
			Key:    aws.String(nonExistentKey),
		})
		// S3 DeleteObject should succeed even for non-existent objects
		require.NoError(t, err, "DeleteObject should succeed even for non-existent objects")
		assert.NotNil(t, deleteOutput, "DeleteObject output should not be nil")

		t.Logf("✅ Successfully handled deletion of non-existent object %s", nonExistentKey)
	})

	t.Run("DeleteObject_EncryptedObject", func(t *testing.T) {
		// Create an encrypted object
		testKey := "test-encrypted-delete-" + integration.RandomString(8)
		testContent := "This is encrypted content for delete operation"

		// Put object via proxy (this will encrypt it)
		_, err := ctx.ProxyClient.PutObject(context.Background(), &s3.PutObjectInput{
			Bucket: aws.String(ctx.TestBucket),
			Key:    aws.String(testKey),
			Body:   strings.NewReader(testContent),
		})
		require.NoError(t, err, "Should be able to create encrypted test object")

		// Verify object exists and is encrypted by checking metadata
		headOutput, err := ctx.MinIOClient.HeadObject(context.Background(), &s3.HeadObjectInput{
			Bucket: aws.String(ctx.TestBucket),
			Key:    aws.String(testKey),
		})
		require.NoError(t, err, "Object should exist in MinIO")

		// Check if encryption metadata exists (indicating it's encrypted)
		hasEncryptionMetadata := false
		for key := range headOutput.Metadata {
			if strings.HasPrefix(key, "s3ep-") {
				hasEncryptionMetadata = true
				break
			}
		}
		assert.True(t, hasEncryptionMetadata, "Object should have encryption metadata")

		// Delete encrypted object via proxy
		deleteOutput, err := ctx.ProxyClient.DeleteObject(context.Background(), &s3.DeleteObjectInput{
			Bucket: aws.String(ctx.TestBucket),
			Key:    aws.String(testKey),
		})
		require.NoError(t, err, "DeleteObject should succeed for encrypted objects")
		assert.NotNil(t, deleteOutput, "DeleteObject output should not be nil")

		// Verify object no longer exists in both proxy and MinIO
		_, err = ctx.ProxyClient.HeadObject(context.Background(), &s3.HeadObjectInput{
			Bucket: aws.String(ctx.TestBucket),
			Key:    aws.String(testKey),
		})
		assert.Error(t, err, "Encrypted object should not exist after deletion via proxy")

		_, err = ctx.MinIOClient.HeadObject(context.Background(), &s3.HeadObjectInput{
			Bucket: aws.String(ctx.TestBucket),
			Key:    aws.String(testKey),
		})
		assert.Error(t, err, "Encrypted object should not exist after deletion in MinIO")

		t.Logf("✅ Successfully deleted encrypted object %s", testKey)
	})

	t.Run("DeleteObject_PassthroughBehavior", func(t *testing.T) {
		// Test that deletion works the same way through proxy and direct MinIO
		testKey := "test-passthrough-delete-" + integration.RandomString(8)
		testContent := "This is content for passthrough delete test"

		// Create object via MinIO directly
		_, err := ctx.MinIOClient.PutObject(context.Background(), &s3.PutObjectInput{
			Bucket: aws.String(ctx.TestBucket),
			Key:    aws.String(testKey),
			Body:   strings.NewReader(testContent),
		})
		require.NoError(t, err, "Should be able to create object via MinIO")

		// Verify object exists in both MinIO and proxy
		_, err = ctx.MinIOClient.HeadObject(context.Background(), &s3.HeadObjectInput{
			Bucket: aws.String(ctx.TestBucket),
			Key:    aws.String(testKey),
		})
		require.NoError(t, err, "Object should exist in MinIO")

		_, err = ctx.ProxyClient.HeadObject(context.Background(), &s3.HeadObjectInput{
			Bucket: aws.String(ctx.TestBucket),
			Key:    aws.String(testKey),
		})
		require.NoError(t, err, "Object should be accessible via proxy")

		// Delete object via proxy
		deleteOutput, err := ctx.ProxyClient.DeleteObject(context.Background(), &s3.DeleteObjectInput{
			Bucket: aws.String(ctx.TestBucket),
			Key:    aws.String(testKey),
		})
		require.NoError(t, err, "DeleteObject via proxy should succeed")
		assert.NotNil(t, deleteOutput, "DeleteObject output should not be nil")

		// Verify object is deleted from both MinIO and proxy
		_, err = ctx.MinIOClient.HeadObject(context.Background(), &s3.HeadObjectInput{
			Bucket: aws.String(ctx.TestBucket),
			Key:    aws.String(testKey),
		})
		assert.Error(t, err, "Object should not exist in MinIO after proxy deletion")

		_, err = ctx.ProxyClient.HeadObject(context.Background(), &s3.HeadObjectInput{
			Bucket: aws.String(ctx.TestBucket),
			Key:    aws.String(testKey),
		})
		assert.Error(t, err, "Object should not be accessible via proxy after deletion")

		t.Logf("✅ Successfully verified passthrough delete behavior for object %s", testKey)
	})
}
