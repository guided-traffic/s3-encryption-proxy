package encryption

import (
	"context"
	"fmt"
	"testing"

	"github.com/guided-traffic/s3-encryption-proxy/internal/config"
	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption"
	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption/factory"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestManager_MultipartUpload_CompleteFlow(t *testing.T) {
	cfg := &config.Config{
		Encryption: config.EncryptionConfig{
			EncryptionMethodAlias: "default",
			Providers: []config.EncryptionProvider{
				{
					Alias: "default",
					Type:  "aes-gcm",
					Config: map[string]interface{}{
						"key": "12345678901234567890123456789012",
					},
				},
			},
		},
	}

	manager, err := NewManager(cfg)
	require.NoError(t, err)

	ctx := context.Background()
	uploadID := "test-upload-123"
	objectKey := "test/multipart/object"
	bucketName := "test-bucket"

	// Step 1: Initiate multipart upload
	err = manager.InitiateMultipartUpload(ctx, uploadID, objectKey, bucketName)
	require.NoError(t, err)

	// Verify upload state was created
	state, err := manager.GetMultipartUploadState(uploadID)
	require.NoError(t, err)
	assert.Equal(t, uploadID, state.UploadID)
	assert.Equal(t, objectKey, state.ObjectKey)
	assert.Equal(t, bucketName, state.BucketName)
	assert.Equal(t, factory.ContentTypeMultipart, state.ContentType)
	assert.False(t, state.IsCompleted)
	assert.Equal(t, "aes-256-ctr", state.Metadata["data_algorithm"])

	// Step 2: Upload parts
	testParts := map[int][]byte{
		1: []byte("This is part 1 of the multipart upload test."),
		2: []byte("This is part 2 with different content."),
		3: []byte("Final part 3 to complete the test upload."),
	}

	partResults := make(map[int]*encryption.EncryptionResult)
	partETags := make(map[int]string)

	for partNumber, partData := range testParts {
		result, err := manager.UploadPart(ctx, uploadID, partNumber, partData)
		require.NoError(t, err)
		assert.NotNil(t, result)
		assert.NotEqual(t, partData, result.EncryptedData)
		assert.NotEmpty(t, result.EncryptedDEK)
		assert.NotEmpty(t, result.Metadata)

		// Verify part metadata
		assert.Equal(t, uploadID, result.Metadata["upload_id"])
		assert.Equal(t, fmt.Sprintf("%d", partNumber), result.Metadata["part_number"])
		assert.Equal(t, "multipart_part", result.Metadata["encryption_mode"])
		assert.Equal(t, "aes-256-ctr", result.Metadata["data_algorithm"])

		partResults[partNumber] = result
		partETags[partNumber] = fmt.Sprintf("etag-%d", partNumber) // Mock ETag
	}

	// Step 3: Complete multipart upload
	finalMetadata, err := manager.CompleteMultipartUpload(ctx, uploadID, partETags)
	require.NoError(t, err)
	assert.NotEmpty(t, finalMetadata)
	assert.Equal(t, "multipart_completed", finalMetadata["encryption_mode"])
	assert.Equal(t, "3", finalMetadata["total_parts"])
	assert.Equal(t, uploadID, finalMetadata["upload_id"])

	// Verify upload state is now completed
	state, err = manager.GetMultipartUploadState(uploadID)
	require.NoError(t, err)
	assert.True(t, state.IsCompleted)
	assert.Len(t, state.PartETags, 3)

	// Step 4: Test decryption of parts
	for partNumber, result := range partResults {
		originalData := testParts[partNumber]

		decryptedData, err := manager.DecryptMultipartData(ctx, result.EncryptedData, result.EncryptedDEK, result.Metadata, objectKey, partNumber)
		require.NoError(t, err)
		assert.Equal(t, originalData, decryptedData)
	}
}

func TestManager_MultipartUpload_InitiateTwice(t *testing.T) {
	cfg := &config.Config{
		Encryption: config.EncryptionConfig{
			EncryptionMethodAlias: "default",
			Providers: []config.EncryptionProvider{
				{
					Alias: "default",
					Type:  "aes-gcm",
					Config: map[string]interface{}{
						"key": "12345678901234567890123456789012",
					},
				},
			},
		},
	}

	manager, err := NewManager(cfg)
	require.NoError(t, err)

	ctx := context.Background()
	uploadID := "duplicate-upload-123"

	// First initiation should succeed
	err = manager.InitiateMultipartUpload(ctx, uploadID, "test/key", "bucket")
	require.NoError(t, err)

	// Second initiation with same ID should fail
	err = manager.InitiateMultipartUpload(ctx, uploadID, "test/key", "bucket")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already exists")
}

func TestManager_MultipartUpload_UploadPartNonexistentUpload(t *testing.T) {
	cfg := &config.Config{
		Encryption: config.EncryptionConfig{
			EncryptionMethodAlias: "default",
			Providers: []config.EncryptionProvider{
				{
					Alias: "default",
					Type:  "aes-gcm",
					Config: map[string]interface{}{
						"key": "12345678901234567890123456789012",
					},
				},
			},
		},
	}

	manager, err := NewManager(cfg)
	require.NoError(t, err)

	ctx := context.Background()

	// Try to upload part for nonexistent upload
	_, err = manager.UploadPart(ctx, "nonexistent-upload", 1, []byte("test data"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestManager_MultipartUpload_AbortUpload(t *testing.T) {
	cfg := &config.Config{
		Encryption: config.EncryptionConfig{
			EncryptionMethodAlias: "default",
			Providers: []config.EncryptionProvider{
				{
					Alias: "default",
					Type:  "aes-gcm",
					Config: map[string]interface{}{
						"key": "12345678901234567890123456789012",
					},
				},
			},
		},
	}

	manager, err := NewManager(cfg)
	require.NoError(t, err)

	ctx := context.Background()
	uploadID := "abort-upload-123"

	// Initiate upload
	err = manager.InitiateMultipartUpload(ctx, uploadID, "test/key", "bucket")
	require.NoError(t, err)

	// Verify it exists
	_, err = manager.GetMultipartUploadState(uploadID)
	require.NoError(t, err)

	// Abort upload
	err = manager.AbortMultipartUpload(ctx, uploadID)
	require.NoError(t, err)

	// Should no longer exist
	_, err = manager.GetMultipartUploadState(uploadID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestManager_MultipartUpload_CompleteAfterCompletion(t *testing.T) {
	cfg := &config.Config{
		Encryption: config.EncryptionConfig{
			EncryptionMethodAlias: "default",
			Providers: []config.EncryptionProvider{
				{
					Alias: "default",
					Type:  "aes-gcm",
					Config: map[string]interface{}{
						"key": "12345678901234567890123456789012",
					},
				},
			},
		},
	}

	manager, err := NewManager(cfg)
	require.NoError(t, err)

	ctx := context.Background()
	uploadID := "complete-twice-123"

	// Initiate and complete upload
	err = manager.InitiateMultipartUpload(ctx, uploadID, "test/key", "bucket")
	require.NoError(t, err)

	_, err = manager.CompleteMultipartUpload(ctx, uploadID, map[int]string{1: "etag1"})
	require.NoError(t, err)

	// Try to complete again
	_, err = manager.CompleteMultipartUpload(ctx, uploadID, map[int]string{1: "etag1"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already completed")
}

func TestManager_EncryptChunkedData(t *testing.T) {
	cfg := &config.Config{
		Encryption: config.EncryptionConfig{
			EncryptionMethodAlias: "default",
			Providers: []config.EncryptionProvider{
				{
					Alias: "default",
					Type:  "aes-gcm",
					Config: map[string]interface{}{
						"key": "12345678901234567890123456789012",
					},
				},
			},
		},
	}

	manager, err := NewManager(cfg)
	require.NoError(t, err)

	ctx := context.Background()
	chunkData := []byte("This is chunked data that should use AES-CTR")
	objectKey := "test/chunked/object"

	// Test chunked encryption
	result, err := manager.EncryptChunkedData(ctx, chunkData, objectKey)
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.NotEqual(t, chunkData, result.EncryptedData)
	assert.NotEmpty(t, result.EncryptedDEK)
	assert.Equal(t, "aes-256-ctr", result.Metadata["data_algorithm"])
	assert.Equal(t, "multipart", result.Metadata["content_type"])

	// Test decryption
	decrypted, err := manager.DecryptData(ctx, result.EncryptedData, result.EncryptedDEK, objectKey, "")
	require.NoError(t, err)
	assert.Equal(t, chunkData, decrypted)
}

func TestManager_EncryptDataWithContentType(t *testing.T) {
	cfg := &config.Config{
		Encryption: config.EncryptionConfig{
			EncryptionMethodAlias: "default",
			Providers: []config.EncryptionProvider{
				{
					Alias: "default",
					Type:  "aes-gcm",
					Config: map[string]interface{}{
						"key": "12345678901234567890123456789012",
					},
				},
			},
		},
	}

	manager, err := NewManager(cfg)
	require.NoError(t, err)

	ctx := context.Background()
	testData := []byte("Test data for content type verification")
	objectKey := "test/content-type/object"

	tests := []struct {
		name                string
		contentType         factory.ContentType
		expectedAlgorithm   string
	}{
		{
			name:              "Whole file uses AES-GCM",
			contentType:       factory.ContentTypeWhole,
			expectedAlgorithm: "aes-256-gcm",
		},
		{
			name:              "Multipart uses AES-CTR",
			contentType:       factory.ContentTypeMultipart,
			expectedAlgorithm: "aes-256-ctr",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := manager.EncryptDataWithContentType(ctx, testData, objectKey, tt.contentType)
			require.NoError(t, err)
			assert.Equal(t, tt.expectedAlgorithm, result.Metadata["data_algorithm"])
			assert.Equal(t, string(tt.contentType), result.Metadata["content_type"])

			// Test decryption works
			decrypted, err := manager.DecryptData(ctx, result.EncryptedData, result.EncryptedDEK, objectKey, "")
			require.NoError(t, err)
			assert.Equal(t, testData, decrypted)
		})
	}
}
