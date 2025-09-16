package encryption

import (
	"context"
	"testing"

	"github.com/guided-traffic/s3-encryption-proxy/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Helper function for string pointer
func stringPtr(s string) *string {
	return &s
}

func TestManager_MultipartUpload_HMACIntegration(t *testing.T) {
	// Create test config with integrity verification enabled
	cfg := &config.Config{
		Encryption: config.EncryptionConfig{
			IntegrityVerification: true,
			MetadataKeyPrefix:     stringPtr("s3ep-"),
			Providers: []config.EncryptionProvider{
				{
					Alias: "test-aes",
					Type:  "aes",
					Config: map[string]interface{}{
						"aes_key": "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=", // base64 encoded 32 bytes
					},
				},
			},
			EncryptionMethodAlias: "test-aes",
		},
	}

	// Create manager
	manager, err := NewManager(cfg)
	require.NoError(t, err)

	ctx := context.Background()
	uploadID := "test-hmac-upload-12345"
	objectKey := "test-objects/hmac-multipart-file.dat"
	bucketName := "test-bucket"

	t.Run("InitiateMultipartUploadWithHMAC", func(t *testing.T) {
		err := manager.InitiateMultipartUpload(ctx, uploadID, objectKey, bucketName)
		assert.NoError(t, err)

		// Verify the state includes HMAC setup
		manager.uploadsMutex.RLock()
		state, exists := manager.multipartUploads[uploadID]
		manager.uploadsMutex.RUnlock()

		assert.True(t, exists, "Upload state should exist")
		assert.True(t, state.HMACEnabled, "HMAC should be enabled")
		assert.NotNil(t, state.StreamingHMACEncryptor, "HMAC encryptor should be created")
	})

	t.Run("UploadPartsWithHMAC", func(t *testing.T) {
		// Part 1
		part1Data := []byte("This is the first part of the multipart upload for HMAC testing. ")
		result1, err := manager.UploadPart(ctx, uploadID, 1, part1Data)
		require.NoError(t, err)

		assert.NotNil(t, result1.EncryptedData)
		assert.NotEqual(t, part1Data, result1.EncryptedData, "Data should be encrypted")
		assert.NotNil(t, result1.EncryptedDEK)
		assert.NotNil(t, result1.Metadata)

		// Part 2
		part2Data := []byte("This is the second part of the multipart upload, continuing the data stream. ")
		result2, err := manager.UploadPart(ctx, uploadID, 2, part2Data)
		require.NoError(t, err)

		assert.NotNil(t, result2.EncryptedData)
		assert.NotEqual(t, part2Data, result2.EncryptedData, "Data should be encrypted")

		// Part 3
		part3Data := []byte("Final part of the multipart upload with HMAC integrity verification enabled.")
		result3, err := manager.UploadPart(ctx, uploadID, 3, part3Data)
		require.NoError(t, err)

		assert.NotNil(t, result3.EncryptedData)
		assert.NotEqual(t, part3Data, result3.EncryptedData, "Data should be encrypted")
	})

	t.Run("CompleteMultipartUploadWithHMAC", func(t *testing.T) {
		parts := map[int]string{
			1: "etag-part-1",
			2: "etag-part-2",
			3: "etag-part-3",
		}

		finalMetadata, err := manager.CompleteMultipartUpload(ctx, uploadID, parts)
		require.NoError(t, err)

		assert.NotNil(t, finalMetadata, "Final metadata should not be nil")

		// Verify HMAC metadata is present
		hmacKey := "s3ep-hmac"
		hmacValue, exists := finalMetadata[hmacKey]
		assert.True(t, exists, "HMAC metadata should be present")
		assert.NotEmpty(t, hmacValue, "HMAC value should not be empty")

		// Verify other standard metadata
		assert.Contains(t, finalMetadata, "s3ep-dek-algorithm", "DEK algorithm should be present")
		assert.Contains(t, finalMetadata, "s3ep-encrypted-dek", "Encrypted DEK should be present")
		assert.Contains(t, finalMetadata, "s3ep-aes-iv", "AES IV should be present")
		assert.Contains(t, finalMetadata, "s3ep-kek-algorithm", "KEK algorithm should be present")
		assert.Contains(t, finalMetadata, "s3ep-kek-fingerprint", "KEK fingerprint should be present")

		assert.Equal(t, "aes-256-ctr", finalMetadata["s3ep-dek-algorithm"], "Should use AES-CTR for multipart")
	})

	t.Run("VerifyHMACConsistency", func(t *testing.T) {
		// Complete another identical upload to verify HMAC consistency
		uploadID2 := "test-hmac-upload-consistency"

		err := manager.InitiateMultipartUpload(ctx, uploadID2, objectKey, bucketName)
		require.NoError(t, err)

		// Upload the same parts
		part1Data := []byte("This is the first part of the multipart upload for HMAC testing. ")
		_, err = manager.UploadPart(ctx, uploadID2, 1, part1Data)
		require.NoError(t, err)

		part2Data := []byte("This is the second part of the multipart upload, continuing the data stream. ")
		_, err = manager.UploadPart(ctx, uploadID2, 2, part2Data)
		require.NoError(t, err)

		part3Data := []byte("Final part of the multipart upload with HMAC integrity verification enabled.")
		_, err = manager.UploadPart(ctx, uploadID2, 3, part3Data)
		require.NoError(t, err)

		finalMetadata2, err := manager.CompleteMultipartUpload(ctx, uploadID2, map[int]string{
			1: "etag-part-1", 2: "etag-part-2", 3: "etag-part-3",
		})
		require.NoError(t, err)

		// Since DEKs and IVs are random, HMACs should be different even for same data
		hmac1 := finalMetadata2["s3ep-hmac"]

		// Get first upload metadata for comparison
		manager.uploadsMutex.RLock()
		state1, exists1 := manager.multipartUploads[uploadID]
		manager.uploadsMutex.RUnlock()

		assert.True(t, exists1, "First upload state should still exist")
		hmac0 := state1.Metadata["s3ep-hmac"]

		// HMACs should be different due to different DEKs
		assert.NotEqual(t, hmac0, hmac1, "Different uploads should have different HMACs due to different DEKs")

		// But both should be valid base64 encoded values
		assert.NotEmpty(t, hmac0, "First HMAC should not be empty")
		assert.NotEmpty(t, hmac1, "Second HMAC should not be empty")
	})
}

func TestManager_MultipartUpload_HMACDisabled(t *testing.T) {
	// Create test config with integrity verification disabled
	cfg := &config.Config{
		Encryption: config.EncryptionConfig{
			IntegrityVerification: false, // Disabled
			MetadataKeyPrefix:     stringPtr("s3ep-"),
			Providers: []config.EncryptionProvider{
				{
					Alias: "test-aes-no-hmac",
					Type:  "aes",
					Config: map[string]interface{}{
						"aes_key": "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=",
					},
				},
			},
			EncryptionMethodAlias: "test-aes-no-hmac",
		},
	}

	// Create manager
	manager, err := NewManager(cfg)
	require.NoError(t, err)

	ctx := context.Background()
	uploadID := "test-no-hmac-upload-12345"
	objectKey := "test-objects/no-hmac-multipart-file.dat"
	bucketName := "test-bucket"

	t.Run("InitiateWithoutHMAC", func(t *testing.T) {
		err := manager.InitiateMultipartUpload(ctx, uploadID, objectKey, bucketName)
		assert.NoError(t, err)

		// Verify HMAC is disabled
		manager.uploadsMutex.RLock()
		state, exists := manager.multipartUploads[uploadID]
		manager.uploadsMutex.RUnlock()

		assert.True(t, exists, "Upload state should exist")
		assert.False(t, state.HMACEnabled, "HMAC should be disabled")
		assert.Nil(t, state.StreamingHMACEncryptor, "HMAC encryptor should not be created")
	})

	t.Run("CompleteWithoutHMAC", func(t *testing.T) {
		// Upload a part
		partData := []byte("Test data without HMAC")
		_, err := manager.UploadPart(ctx, uploadID, 1, partData)
		require.NoError(t, err)

		// Complete the upload
		finalMetadata, err := manager.CompleteMultipartUpload(ctx, uploadID, map[int]string{1: "etag-1"})
		require.NoError(t, err)

		// Verify no HMAC metadata
		hmacKey := "s3ep-hmac"
		_, exists := finalMetadata[hmacKey]
		assert.False(t, exists, "HMAC metadata should not be present when disabled")

		// But other metadata should still be there
		assert.Contains(t, finalMetadata, "s3ep-dek-algorithm", "DEK algorithm should be present")
		assert.Contains(t, finalMetadata, "s3ep-encrypted-dek", "Encrypted DEK should be present")
	})
}
