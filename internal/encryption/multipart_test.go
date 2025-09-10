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
	prefixValue := "s3ep-"
	cfg := &config.Config{
		Encryption: config.EncryptionConfig{
			EncryptionMethodAlias: "default",
			MetadataKeyPrefix:     &prefixValue, // Top-level metadata prefix config
			Providers: []config.EncryptionProvider{
				{
					Alias: "default",
					Type:  "aes",
					Config: map[string]interface{}{
						"aes_key": "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=",
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
	assert.Equal(t, "aes-256-ctr", state.Metadata["data-algorithm"])

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
		assert.NotNil(t, result.Metadata)

		// Verify part metadata - no metadata needed for parts (IV and part number handled separately)
		assert.Len(t, result.Metadata, 0) // No metadata should be present in parts

		partResults[partNumber] = result
		partETags[partNumber] = fmt.Sprintf("etag-%d", partNumber) // Mock ETag
	}

	// Step 3: Complete multipart upload
	finalMetadata, err := manager.CompleteMultipartUpload(ctx, uploadID, partETags)
	require.NoError(t, err)
	assert.NotEmpty(t, finalMetadata)

	// Verify the 5 required metadata fields are present (with s3ep- prefix)
	assert.Contains(t, finalMetadata, "s3ep-data-algorithm")
	assert.Contains(t, finalMetadata, "s3ep-encrypted-dek")
	assert.Contains(t, finalMetadata, "s3ep-encryption-iv")
	assert.Contains(t, finalMetadata, "s3ep-kek-algorithm")
	assert.Contains(t, finalMetadata, "s3ep-kek-fingerprint")

	// Verify values
	assert.Equal(t, "aes-256-ctr", finalMetadata["s3ep-data-algorithm"])
	assert.Equal(t, "aes", finalMetadata["s3ep-kek-algorithm"])

	// Verify upload state is now completed
	state, err = manager.GetMultipartUploadState(uploadID)
	require.NoError(t, err)
	assert.True(t, state.IsCompleted)
	assert.Len(t, state.PartETags, 3)

	// Step 4: Test decryption of parts using final metadata (which contains IV)
	for partNumber, result := range partResults {
		originalData := testParts[partNumber]

		// Use final metadata for decryption which contains the IV
		decryptedData, err := manager.DecryptMultipartData(ctx, result.EncryptedData, result.EncryptedDEK, finalMetadata, objectKey, partNumber)
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
					Type:  "aes",
					Config: map[string]interface{}{
						"aes_key": "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=",
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
					Type:  "aes",
					Config: map[string]interface{}{
						"aes_key": "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=",
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
					Type:  "aes",
					Config: map[string]interface{}{
						"aes_key": "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=",
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
					Type:  "aes",
					Config: map[string]interface{}{
						"aes_key": "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=",
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

	// Try to complete again - should succeed (idempotent operation)
	metadata, err := manager.CompleteMultipartUpload(ctx, uploadID, map[int]string{1: "etag1"})
	assert.NoError(t, err, "Completion should be idempotent")
	assert.NotNil(t, metadata, "Should return metadata even for repeated completion")
}

func TestManager_EncryptChunkedData(t *testing.T) {
	cfg := &config.Config{
		Encryption: config.EncryptionConfig{
			EncryptionMethodAlias: "default",
			Providers: []config.EncryptionProvider{
				{
					Alias: "default",
					Type:  "aes",
					Config: map[string]interface{}{
						"aes_key": "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=",
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
	assert.Equal(t, "aes-256-ctr", result.Metadata["data-algorithm"])
	assert.Equal(t, "multipart", result.Metadata["content-type"])

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
					Type:  "aes",
					Config: map[string]interface{}{
						"aes_key": "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=",
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
			assert.Equal(t, tt.expectedAlgorithm, result.Metadata["data-algorithm"])
			assert.Equal(t, string(tt.contentType), result.Metadata["content-type"])

			// Test decryption works
			decrypted, err := manager.DecryptData(ctx, result.EncryptedData, result.EncryptedDEK, objectKey, "")
			require.NoError(t, err)
			assert.Equal(t, testData, decrypted)
		})
	}
}

// TestManager_MultipartUpload_CleanupSeparationOfConcerns tests the new cleanup functionality
func TestManager_MultipartUpload_CleanupSeparationOfConcerns(t *testing.T) {
	cfg := &config.Config{
		Encryption: config.EncryptionConfig{
			EncryptionMethodAlias: "default",
			Providers: []config.EncryptionProvider{
				{
					Alias: "default",
					Type:  "aes",
					Config: map[string]interface{}{
						"aes_key": "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=",
					},
				},
			},
		},
	}

	manager, err := NewManager(cfg)
	require.NoError(t, err)

	ctx := context.Background()
	uploadID := "cleanup-test-upload"
	objectKey := "test/cleanup/object"
	bucketName := "test-bucket"

	// Step 1: Initiate multipart upload
	err = manager.InitiateMultipartUpload(ctx, uploadID, objectKey, bucketName)
	require.NoError(t, err)

	// Step 1.5: Upload a test part to satisfy completion requirements
	testData := []byte("test data for cleanup test")
	result, err := manager.UploadPart(ctx, uploadID, 1, testData)
	require.NoError(t, err)
	require.NotNil(t, result)

	// Store the part ETag (simulate what the S3 handler would do)
	err = manager.StorePartETag(uploadID, 1, "test-etag-1")
	require.NoError(t, err)

	// Step 2: Complete the upload (business logic)
	_, err = manager.CompleteMultipartUpload(ctx, uploadID, map[int]string{1: "test-etag-1"})
	require.NoError(t, err)

	// Verify upload is marked as completed
	state, err := manager.GetMultipartUploadState(uploadID)
	require.NoError(t, err)
	assert.True(t, state.IsCompleted)

	// Step 3: SEPARATION OF CONCERNS - Cleanup should work independently
	err = manager.CleanupMultipartUpload(uploadID)
	require.NoError(t, err, "Cleanup should always succeed")

	// Verify upload state is removed from memory
	_, err = manager.GetMultipartUploadState(uploadID)
	assert.Error(t, err, "Upload state should be removed after cleanup")
	assert.Contains(t, err.Error(), "not found", "Should get 'not found' error after cleanup")

	// Step 4: Cleanup should be idempotent (can be called multiple times)
	err = manager.CleanupMultipartUpload(uploadID)
	require.NoError(t, err, "Cleanup should be idempotent and succeed even if already cleaned up")

	// Step 5: Cleanup should work even for non-existent uploads
	err = manager.CleanupMultipartUpload("non-existent-upload")
	require.NoError(t, err, "Cleanup should succeed even for non-existent uploads (idempotent)")
}
