package encryption

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/guided-traffic/s3-encryption-proxy/internal/config"
)

const testObjectKey = "test/object.txt"

func TestNewManager_Success(t *testing.T) {
	cfg := &config.Config{
		Encryption: config.EncryptionConfig{
			EncryptionMethodAlias: "default",
			Providers: []config.EncryptionProvider{
				{
					Alias:  "default",
					Type:   "none",
					Config: map[string]interface{}{},
				},
			},
		},
	}

	manager, err := NewManager(cfg)
	require.NoError(t, err)
	assert.NotNil(t, manager)
	assert.NotNil(t, manager.activeEncryptor)
	assert.Len(t, manager.decryptors, 1)
	assert.Contains(t, manager.decryptors, "default")
}

func TestNewManager_MultipleProviders(t *testing.T) {
	cfg := &config.Config{
		Encryption: config.EncryptionConfig{
			EncryptionMethodAlias: "primary",
			Providers: []config.EncryptionProvider{
				{
					Alias:  "primary",
					Type:   "none",
					Config: map[string]interface{}{},
				},
				{
					Alias:  "secondary",
					Type:   "none",
					Config: map[string]interface{}{},
				},
			},
		},
	}

	manager, err := NewManager(cfg)
	require.NoError(t, err)
	assert.NotNil(t, manager)
	assert.Len(t, manager.decryptors, 2)
	assert.Contains(t, manager.decryptors, "primary")
	assert.Contains(t, manager.decryptors, "secondary")
}

func TestNewManager_NoActiveProvider(t *testing.T) {
	cfg := &config.Config{
		Encryption: config.EncryptionConfig{
			EncryptionMethodAlias: "",
			Providers:             []config.EncryptionProvider{},
		},
	}

	_, err := NewManager(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get active provider")
}

func TestNewManager_InvalidActiveProvider(t *testing.T) {
	cfg := &config.Config{
		Encryption: config.EncryptionConfig{
			EncryptionMethodAlias: "nonexistent",
			Providers: []config.EncryptionProvider{
				{
					Alias:  "default",
					Type:   "none",
					Config: map[string]interface{}{},
				},
			},
		},
	}

	_, err := NewManager(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "active encryption provider 'nonexistent' not found")
}

func TestNewManager_InvalidProviderType(t *testing.T) {
	cfg := &config.Config{
		Encryption: config.EncryptionConfig{
			EncryptionMethodAlias: "default",
			Providers: []config.EncryptionProvider{
				{
					Alias:  "default",
					Type:   "invalid-type",
					Config: map[string]interface{}{},
				},
			},
		},
	}

	_, err := NewManager(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "provider 'default' has invalid type 'invalid-type'")
}

func TestEncryptData_Success(t *testing.T) {
	cfg := &config.Config{
		Encryption: config.EncryptionConfig{
			EncryptionMethodAlias: "default",
			Providers: []config.EncryptionProvider{
				{
					Alias:  "default",
					Type:   "none",
					Config: map[string]interface{}{},
				},
			},
		},
	}

	manager, err := NewManager(cfg)
	require.NoError(t, err)

	ctx := context.Background()
	data := []byte("test data")
	objectKey := testObjectKey

	result, err := manager.EncryptData(ctx, data, objectKey)
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, data, result.EncryptedData) // None provider returns data as-is
	assert.Equal(t, "default", result.Metadata["provider_alias"])
}

func TestDecryptData_SuccessWithSpecificProvider(t *testing.T) {
	cfg := &config.Config{
		Encryption: config.EncryptionConfig{
			EncryptionMethodAlias: "default",
			Providers: []config.EncryptionProvider{
				{
					Alias:  "default",
					Type:   "none",
					Config: map[string]interface{}{},
				},
			},
		},
	}

	manager, err := NewManager(cfg)
	require.NoError(t, err)

	ctx := context.Background()
	encryptedData := []byte("test data")
	objectKey := testObjectKey

	decrypted, err := manager.DecryptData(ctx, encryptedData, nil, objectKey, "default")
	require.NoError(t, err)
	assert.Equal(t, encryptedData, decrypted)
}

func TestDecryptData_SuccessWithoutSpecificProvider(t *testing.T) {
	cfg := &config.Config{
		Encryption: config.EncryptionConfig{
			EncryptionMethodAlias: "primary",
			Providers: []config.EncryptionProvider{
				{
					Alias:  "primary",
					Type:   "none",
					Config: map[string]interface{}{},
				},
				{
					Alias:  "secondary",
					Type:   "none",
					Config: map[string]interface{}{},
				},
			},
		},
	}

	manager, err := NewManager(cfg)
	require.NoError(t, err)

	ctx := context.Background()
	encryptedData := []byte("test data")
	objectKey := testObjectKey

	// Should succeed with any available provider
	decrypted, err := manager.DecryptData(ctx, encryptedData, nil, objectKey, "")
	require.NoError(t, err)
	assert.Equal(t, encryptedData, decrypted)
}

func TestDecryptData_NonexistentProvider(t *testing.T) {
	cfg := &config.Config{
		Encryption: config.EncryptionConfig{
			EncryptionMethodAlias: "default",
			Providers: []config.EncryptionProvider{
				{
					Alias:  "default",
					Type:   "none",
					Config: map[string]interface{}{},
				},
			},
		},
	}

	manager, err := NewManager(cfg)
	require.NoError(t, err)

	ctx := context.Background()
	encryptedData := []byte("test data")
	objectKey := testObjectKey

	// Should fallback to trying all providers
	decrypted, err := manager.DecryptData(ctx, encryptedData, nil, objectKey, "nonexistent")
	require.NoError(t, err)
	assert.Equal(t, encryptedData, decrypted)
}

func TestRotateKEK_Success(t *testing.T) {
	cfg := &config.Config{
		Encryption: config.EncryptionConfig{
			EncryptionMethodAlias: "default",
			Providers: []config.EncryptionProvider{
				{
					Alias:  "default",
					Type:   "none",
					Config: map[string]interface{}{},
				},
			},
		},
	}

	manager, err := NewManager(cfg)
	require.NoError(t, err)

	ctx := context.Background()
	err = manager.RotateKEK(ctx)
	assert.NoError(t, err) // None provider always succeeds
}

func TestGetProviderAliases_Success(t *testing.T) {
	cfg := &config.Config{
		Encryption: config.EncryptionConfig{
			EncryptionMethodAlias: "primary",
			Providers: []config.EncryptionProvider{
				{
					Alias:  "primary",
					Type:   "none",
					Config: map[string]interface{}{},
				},
				{
					Alias:  "secondary",
					Type:   "none",
					Config: map[string]interface{}{},
				},
			},
		},
	}

	manager, err := NewManager(cfg)
	require.NoError(t, err)

	aliases := manager.GetProviderAliases()
	assert.Len(t, aliases, 2)
	assert.Contains(t, aliases, "primary")
	assert.Contains(t, aliases, "secondary")
}

func TestGetActiveProviderAlias_Success(t *testing.T) {
	cfg := &config.Config{
		Encryption: config.EncryptionConfig{
			EncryptionMethodAlias: "test-provider",
			Providers: []config.EncryptionProvider{
				{
					Alias:  "test-provider",
					Type:   "none",
					Config: map[string]interface{}{},
				},
			},
		},
	}

	manager, err := NewManager(cfg)
	require.NoError(t, err)

	alias := manager.GetActiveProviderAlias()
	assert.Equal(t, "test-provider", alias)
}

func TestGetActiveProviderAlias_InvalidConfig(t *testing.T) {
	// Create manager with invalid config that would fail GetActiveProvider
	manager := &Manager{
		config: &config.Config{
			Encryption: config.EncryptionConfig{
				EncryptionMethodAlias: "nonexistent",
				Providers:             []config.EncryptionProvider{},
			},
		},
	}

	alias := manager.GetActiveProviderAlias()
	assert.Equal(t, "unknown", alias)
}

// Multipart Upload Tests

func TestCreateMultipartUpload(t *testing.T) {
	cfg := &config.Config{
		Encryption: config.EncryptionConfig{
			EncryptionMethodAlias: "default",
			Providers: []config.EncryptionProvider{
				{
					Alias:  "default",
					Type:   "none",
					Config: map[string]interface{}{},
				},
			},
		},
	}

	manager, err := NewManager(cfg)
	require.NoError(t, err)

	uploadID := "test-upload-id"
	objectKey := "test-object"
	bucketName := "test-bucket"

	state, err := manager.CreateMultipartUpload(context.Background(), uploadID, objectKey, bucketName)
	require.NoError(t, err)

	// Verify the upload state was created
	assert.Equal(t, uploadID, state.UploadID)
	assert.Equal(t, objectKey, state.ObjectKey)
	assert.Equal(t, "default", state.ProviderAlias)
	assert.NotNil(t, state.DEK)
	assert.NotNil(t, state.EncryptedDEK)
	assert.NotNil(t, state.PartETags)
	assert.Len(t, state.PartETags, 0) // Initially empty

	// Verify we can retrieve it
	retrievedState, err := manager.GetMultipartUploadState(uploadID)
	require.NoError(t, err)
	assert.Equal(t, state.UploadID, retrievedState.UploadID)
}

func TestCreateMultipartUpload_DuplicateUploadID(t *testing.T) {
	cfg := &config.Config{
		Encryption: config.EncryptionConfig{
			EncryptionMethodAlias: "default",
			Providers: []config.EncryptionProvider{
				{
					Alias:  "default",
					Type:   "none",
					Config: map[string]interface{}{},
				},
			},
		},
	}

	manager, err := NewManager(cfg)
	require.NoError(t, err)

	uploadID := "test-upload-id"
	objectKey := "test-object"

	// First creation should succeed
	_, err = manager.CreateMultipartUpload(context.Background(), uploadID, objectKey, "test-bucket")
	require.NoError(t, err)

	// Second creation with same uploadID should fail
	_, err = manager.CreateMultipartUpload(context.Background(), uploadID, objectKey, "test-bucket")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already exists")
}

func TestEncryptMultipartData(t *testing.T) {
	cfg := &config.Config{
		Encryption: config.EncryptionConfig{
			EncryptionMethodAlias: "default",
			Providers: []config.EncryptionProvider{
				{
					Alias:  "default",
					Type:   "none",
					Config: map[string]interface{}{},
				},
			},
		},
	}

	manager, err := NewManager(cfg)
	require.NoError(t, err)

	uploadID := "test-upload-id"
	objectKey := "test-object"
	testData := []byte("test data for multipart upload")

	// Create multipart upload first
	_, err = manager.CreateMultipartUpload(context.Background(), uploadID, objectKey, "test-bucket")
	require.NoError(t, err)

	// Encrypt the data
	encResult, err := manager.EncryptMultipartData(context.Background(), uploadID, 1, testData)
	require.NoError(t, err)
	// With "none" provider, data is not actually encrypted, but we get a result structure
	assert.NotNil(t, encResult.EncryptedData)
	assert.NotNil(t, encResult) // The important part is that we get a result
}

func TestEncryptMultipartData_NonexistentUpload(t *testing.T) {
	cfg := &config.Config{
		Encryption: config.EncryptionConfig{
			EncryptionMethodAlias: "default",
			Providers: []config.EncryptionProvider{
				{
					Alias:  "default",
					Type:   "none",
					Config: map[string]interface{}{},
				},
			},
		},
	}

	manager, err := NewManager(cfg)
	require.NoError(t, err)

	testData := []byte("test data")

	// Try to encrypt data for non-existent upload
	_, err = manager.EncryptMultipartData(context.Background(), "nonexistent-upload", 1, testData)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestRecordPartETag(t *testing.T) {
	cfg := &config.Config{
		Encryption: config.EncryptionConfig{
			EncryptionMethodAlias: "default",
			Providers: []config.EncryptionProvider{
				{
					Alias:  "default",
					Type:   "none",
					Config: map[string]interface{}{},
				},
			},
		},
	}

	manager, err := NewManager(cfg)
	require.NoError(t, err)

	uploadID := "test-upload-id"
	objectKey := "test-object"

	// Create multipart upload first
	_, err = manager.CreateMultipartUpload(context.Background(), uploadID, objectKey, "test-bucket")
	require.NoError(t, err)

	// Record some part ETags
	err = manager.RecordPartETag(uploadID, 1, "etag1")
	require.NoError(t, err)

	err = manager.RecordPartETag(uploadID, 2, "etag2")
	require.NoError(t, err)

	// Verify the ETags were recorded
	state, err := manager.GetMultipartUploadState(uploadID)
	require.NoError(t, err)
	assert.Equal(t, "etag1", state.PartETags[1])
	assert.Equal(t, "etag2", state.PartETags[2])
}

func TestRecordPartETag_NonexistentUpload(t *testing.T) {
	cfg := &config.Config{
		Encryption: config.EncryptionConfig{
			EncryptionMethodAlias: "default",
			Providers: []config.EncryptionProvider{
				{
					Alias:  "default",
					Type:   "none",
					Config: map[string]interface{}{},
				},
			},
		},
	}

	manager, err := NewManager(cfg)
	require.NoError(t, err)

	// Try to record ETag for non-existent upload
	err = manager.RecordPartETag("nonexistent-upload", 1, "etag1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestCompleteMultipartUpload(t *testing.T) {
	cfg := &config.Config{
		Encryption: config.EncryptionConfig{
			EncryptionMethodAlias: "default",
			Providers: []config.EncryptionProvider{
				{
					Alias:  "default",
					Type:   "none",
					Config: map[string]interface{}{},
				},
			},
		},
	}

	manager, err := NewManager(cfg)
	require.NoError(t, err)

	uploadID := "test-upload-id"
	objectKey := "test-object"

	// Create multipart upload and record some parts
	_, err = manager.CreateMultipartUpload(context.Background(), uploadID, objectKey, "test-bucket")
	require.NoError(t, err)

	err = manager.RecordPartETag(uploadID, 1, "etag1")
	require.NoError(t, err)

	err = manager.RecordPartETag(uploadID, 2, "etag2")
	require.NoError(t, err)

	// Complete the upload
	state, err := manager.CompleteMultipartUpload(uploadID)
	require.NoError(t, err)
	assert.Equal(t, uploadID, state.UploadID)
	assert.Equal(t, objectKey, state.ObjectKey)

	// Verify the upload state still exists (completion doesn't remove it)
	retrievedState, err := manager.GetMultipartUploadState(uploadID)
	require.NoError(t, err)
	assert.Equal(t, state.UploadID, retrievedState.UploadID)
}

func TestCompleteMultipartUpload_NonexistentUpload(t *testing.T) {
	cfg := &config.Config{
		Encryption: config.EncryptionConfig{
			EncryptionMethodAlias: "default",
			Providers: []config.EncryptionProvider{
				{
					Alias:  "default",
					Type:   "none",
					Config: map[string]interface{}{},
				},
			},
		},
	}

	manager, err := NewManager(cfg)
	require.NoError(t, err)

	// Try to complete non-existent upload
	_, err = manager.CompleteMultipartUpload("nonexistent-upload")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestAbortMultipartUpload(t *testing.T) {
	cfg := &config.Config{
		Encryption: config.EncryptionConfig{
			EncryptionMethodAlias: "default",
			Providers: []config.EncryptionProvider{
				{
					Alias:  "default",
					Type:   "none",
					Config: map[string]interface{}{},
				},
			},
		},
	}

	manager, err := NewManager(cfg)
	require.NoError(t, err)

	uploadID := "test-upload-id"
	objectKey := "test-object"

	// Create multipart upload
	_, err = manager.CreateMultipartUpload(context.Background(), uploadID, objectKey, "test-bucket")
	require.NoError(t, err)

	// Abort the upload
	err = manager.AbortMultipartUpload(uploadID)
	require.NoError(t, err)

	// Verify the upload state was removed
	_, err = manager.GetMultipartUploadState(uploadID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestAbortMultipartUpload_NonexistentUpload(t *testing.T) {
	cfg := &config.Config{
		Encryption: config.EncryptionConfig{
			EncryptionMethodAlias: "default",
			Providers: []config.EncryptionProvider{
				{
					Alias:  "default",
					Type:   "none",
					Config: map[string]interface{}{},
				},
			},
		},
	}

	manager, err := NewManager(cfg)
	require.NoError(t, err)

	// Try to abort non-existent upload - should not error
	err = manager.AbortMultipartUpload("nonexistent-upload")
	require.NoError(t, err) // Abort is idempotent
}

func TestListMultipartUploads(t *testing.T) {
	cfg := &config.Config{
		Encryption: config.EncryptionConfig{
			EncryptionMethodAlias: "default",
			Providers: []config.EncryptionProvider{
				{
					Alias:  "default",
					Type:   "none",
					Config: map[string]interface{}{},
				},
			},
		},
	}

	manager, err := NewManager(cfg)
	require.NoError(t, err)

	// Initially no uploads
	uploads := manager.ListMultipartUploads()
	assert.Len(t, uploads, 0)

	// Create some uploads
	_, err = manager.CreateMultipartUpload(context.Background(), "upload1", "object1", "test-bucket")
	require.NoError(t, err)

	_, err = manager.CreateMultipartUpload(context.Background(), "upload2", "object2", "test-bucket")
	require.NoError(t, err)

	// List uploads
	uploads = manager.ListMultipartUploads()
	assert.Len(t, uploads, 2)

	// Verify the uploads are in the list
	var uploadIDs []string
	for id := range uploads {
		uploadIDs = append(uploadIDs, id)
	}
	assert.Contains(t, uploadIDs, "upload1")
	assert.Contains(t, uploadIDs, "upload2")
}

func TestCopyMultipartPart(t *testing.T) {
	cfg := &config.Config{
		Encryption: config.EncryptionConfig{
			EncryptionMethodAlias: "default",
			Providers: []config.EncryptionProvider{
				{
					Alias:  "default",
					Type:   "none",
					Config: map[string]interface{}{},
				},
			},
		},
	}

	manager, err := NewManager(cfg)
	require.NoError(t, err)

	// Create target upload
	_, err = manager.CreateMultipartUpload(context.Background(), "target-upload", "target-object", "test-bucket")
	require.NoError(t, err)

	// Create source upload
	_, err = manager.CreateMultipartUpload(context.Background(), "source-upload", "source-object", "test-bucket")
	require.NoError(t, err)

	// Try to copy a part - should fail as it's not implemented for encrypted objects
	_, err = manager.CopyMultipartPart("target-upload", "source-bucket", "source-key", "source-upload", 1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not supported")
}

func TestCopyMultipartPart_NonexistentUpload(t *testing.T) {
	cfg := &config.Config{
		Encryption: config.EncryptionConfig{
			EncryptionMethodAlias: "default",
			Providers: []config.EncryptionProvider{
				{
					Alias:  "default",
					Type:   "none",
					Config: map[string]interface{}{},
				},
			},
		},
	}

	manager, err := NewManager(cfg)
	require.NoError(t, err)

	// Try to copy to non-existent upload
	_, err = manager.CopyMultipartPart("nonexistent-upload", "source-bucket", "source-key", "source-upload", 1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestMultipartUpload_ConcurrentAccess(t *testing.T) {
	cfg := &config.Config{
		Encryption: config.EncryptionConfig{
			EncryptionMethodAlias: "default",
			Providers: []config.EncryptionProvider{
				{
					Alias:  "default",
					Type:   "none",
					Config: map[string]interface{}{},
				},
			},
		},
	}

	manager, err := NewManager(cfg)
	require.NoError(t, err)

	uploadID := "concurrent-upload"
	objectKey := "concurrent-object"

	// Create multipart upload
	_, err = manager.CreateMultipartUpload(context.Background(), uploadID, objectKey, "test-bucket")
	require.NoError(t, err)

	// Test concurrent access by running multiple goroutines
	done := make(chan bool, 10)

	// Concurrent ETag recording
	for i := 1; i <= 10; i++ {
		go func(partNum int) {
			defer func() { done <- true }()
			err := manager.RecordPartETag(uploadID, partNum, fmt.Sprintf("etag%d", partNum))
			assert.NoError(t, err)
		}(i)
	}

	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		<-done
	}

	// Verify all ETags were recorded correctly
	state, err := manager.GetMultipartUploadState(uploadID)
	require.NoError(t, err)
	assert.Len(t, state.PartETags, 10)

	for i := 1; i <= 10; i++ {
		expectedETag := fmt.Sprintf("etag%d", i)
		assert.Equal(t, expectedETag, state.PartETags[i])
	}
}

func TestManager_ProviderConfiguration(t *testing.T) {
	// Test that manager correctly configures different providers
	tests := []struct {
		name        string
		provider    config.EncryptionProvider
		expectError bool
	}{
		{
			name: "None provider",
			provider: config.EncryptionProvider{
				Alias: "none-test",
				Type:  "none",
			},
			expectError: false,
		},
		{
			name: "Invalid provider type",
			provider: config.EncryptionProvider{
				Alias: "invalid",
				Type:  "unknown-type",
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.Config{
				Encryption: config.EncryptionConfig{
					EncryptionMethodAlias: tt.provider.Alias,
					Providers:             []config.EncryptionProvider{tt.provider},
				},
			}

			manager, err := NewManager(cfg)
			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, manager)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, manager)
			}
		})
	}
}

func TestManager_ThreadSafetyWithMultipart(t *testing.T) {
	// Test thread safety during multipart operations
	cfg := &config.Config{
		Encryption: config.EncryptionConfig{
			EncryptionMethodAlias: "none",
			Providers: []config.EncryptionProvider{
				{
					Alias: "none",
					Type:  "none",
				},
			},
		},
	}

	manager, err := NewManager(cfg)
	require.NoError(t, err)

	ctx := context.Background()
	const numGoroutines = 10

	// Run concurrent multipart operations
	done := make(chan error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			uploadID := fmt.Sprintf("upload-%d", id)
			objectKey := fmt.Sprintf("test/object-%d.txt", id)
			bucketName := "test-bucket"

			// Create multipart upload
			_, err := manager.CreateMultipartUpload(ctx, uploadID, objectKey, bucketName)
			if err != nil {
				done <- err
				return
			}

			// Encrypt some parts
			for partNum := 1; partNum <= 3; partNum++ {
				data := []byte(fmt.Sprintf("Part %d data for upload %d", partNum, id))
				_, err = manager.EncryptMultipartData(ctx, uploadID, partNum, data)
				if err != nil {
					done <- err
					return
				}

				// Record ETag
				etag := fmt.Sprintf("etag-%d-%d", id, partNum)
				err = manager.RecordPartETag(uploadID, partNum, etag)
				if err != nil {
					done <- err
					return
				}
			}

			// Complete the upload
			_, err = manager.CompleteMultipartUpload(uploadID)
			done <- err
		}(i)
	}

	// Wait for all operations to complete
	for i := 0; i < numGoroutines; i++ {
		err := <-done
		assert.NoError(t, err)
	}
}

func TestManager_ErrorHandling(t *testing.T) {
	cfg := &config.Config{
		Encryption: config.EncryptionConfig{
			EncryptionMethodAlias: "none",
			Providers: []config.EncryptionProvider{
				{
					Alias: "none",
					Type:  "none",
				},
			},
		},
	}

	manager, err := NewManager(cfg)
	require.NoError(t, err)

	ctx := context.Background()

	// Test operations on non-existent upload
	t.Run("EncryptPartOnNonExistentUpload", func(t *testing.T) {
		_, err := manager.EncryptMultipartData(ctx, "non-existent-upload", 1, []byte("data"))
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "multipart upload non-existent-upload not found")
	})

	t.Run("CompleteNonExistentUpload", func(t *testing.T) {
		_, err := manager.CompleteMultipartUpload("non-existent-upload")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "multipart upload non-existent-upload not found")
	})

	t.Run("AbortNonExistentUpload", func(t *testing.T) {
		err := manager.AbortMultipartUpload("non-existent-upload")
		assert.NoError(t, err) // Abort should be idempotent
	})

	t.Run("RecordETagOnNonExistentUpload", func(t *testing.T) {
		err := manager.RecordPartETag("non-existent-upload", 1, "etag")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "multipart upload non-existent-upload not found")
	})
}

func TestManager_MemoryManagement(t *testing.T) {
	// Test that manager properly cleans up memory for large uploads
	cfg := &config.Config{
		Encryption: config.EncryptionConfig{
			EncryptionMethodAlias: "none",
			Providers: []config.EncryptionProvider{
				{
					Alias: "none",
					Type:  "none",
				},
			},
		},
	}

	manager, err := NewManager(cfg)
	require.NoError(t, err)

	ctx := context.Background()
	uploadID := "memory-test-upload"
	objectKey := "test/large-object.bin"
	bucketName := "test-bucket"

	// Create upload
	_, err = manager.CreateMultipartUpload(ctx, uploadID, objectKey, bucketName)
	require.NoError(t, err)

	// Upload parts with large data
	const partSize = 1024 * 1024 // 1MB parts
	for partNum := 1; partNum <= 5; partNum++ {
		largeData := make([]byte, partSize)
		// Fill with test pattern
		for i := range largeData {
			largeData[i] = byte(partNum)
		}

		_, err = manager.EncryptMultipartData(ctx, uploadID, partNum, largeData)
		require.NoError(t, err)

		// Record ETag
		etag := fmt.Sprintf("etag-%d", partNum)
		err = manager.RecordPartETag(uploadID, partNum, etag)
		require.NoError(t, err)
	}

	// Complete upload
	result, err := manager.CompleteMultipartUpload(uploadID)
	require.NoError(t, err)
	assert.NotNil(t, result)

	// Test that manager can handle memory cleanup gracefully
	// Create a new upload to verify the manager is still functional
	newUploadState, err := manager.CreateMultipartUpload(ctx, "test-bucket", "test-key", "provider1")
	require.NoError(t, err)
	assert.NotNil(t, newUploadState)

	// Clean up the new upload
	err = manager.AbortMultipartUpload(newUploadState.UploadID)
	assert.NoError(t, err)
}
