package encryption

import (
	"context"
	"testing"

	"github.com/guided-traffic/s3-encryption-proxy/internal/config"
	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption/factory"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewManager_Simple(t *testing.T) {
	cfg := &config.Config{
		Encryption: config.EncryptionConfig{
			EncryptionMethodAlias: "default",
			Providers: []config.EncryptionProvider{
				{
					Alias: "default",
					Type:  "aes-gcm",
					Config: map[string]interface{}{
						"key": "12345678901234567890123456789012", // 32-byte key
					},
				},
			},
		},
	}

	manager, err := NewManager(cfg)
	require.NoError(t, err)
	assert.NotNil(t, manager)
	assert.NotNil(t, manager.factory)
	assert.NotEmpty(t, manager.activeFingerprint)
}

func TestNewManager_UnsupportedProvider(t *testing.T) {
	cfg := &config.Config{
		Encryption: config.EncryptionConfig{
			EncryptionMethodAlias: "default",
			Providers: []config.EncryptionProvider{
				{
					Alias: "default",
					Type:  "unsupported",
					Config: map[string]interface{}{
						"key": "test",
					},
				},
			},
		},
	}

	_, err := NewManager(cfg)
	assert.Error(t, err)
	// The error comes from config validation, not from our manager
	assert.Contains(t, err.Error(), "invalid type")
}

func TestManager_EncryptDecryptData_Success(t *testing.T) {
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
	testData := []byte("Hello, World! This is test data.")
	objectKey := "test/object/key"

	// Test encryption
	result, err := manager.EncryptData(ctx, testData, objectKey)
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.NotEqual(t, testData, result.EncryptedData)
	assert.NotEmpty(t, result.EncryptedDEK)
	assert.NotEmpty(t, result.Metadata)
	assert.Equal(t, "aes", result.Metadata["kek-algorithm"])

	// Test decryption
	decrypted, err := manager.DecryptData(ctx, result.EncryptedData, result.EncryptedDEK, objectKey, "")
	require.NoError(t, err)
	assert.Equal(t, testData, decrypted)
}

func TestManager_EncryptData_LargeData(t *testing.T) {
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
	// Create large test data (6MB) to trigger multipart content type
	largeData := make([]byte, 6*1024*1024)
	for i := range largeData {
		largeData[i] = byte(i % 256)
	}
	objectKey := "test/large/object"

	// Test encryption with standard EncryptData (should use AES-GCM for whole files)
	result, err := manager.EncryptData(ctx, largeData, objectKey)
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.NotEqual(t, largeData, result.EncryptedData)
	assert.NotEmpty(t, result.EncryptedDEK)
	assert.NotEmpty(t, result.Metadata)

	// Standard EncryptData should use AES-GCM (ContentTypeWhole is default)
	assert.Equal(t, "aes-256-gcm", result.Metadata["data-algorithm"])
	assert.Equal(t, "whole", result.Metadata["content-type"])

	// Test decryption
	decrypted, err := manager.DecryptData(ctx, result.EncryptedData, result.EncryptedDEK, objectKey, "")
	require.NoError(t, err)
	assert.Equal(t, largeData, decrypted)

	// Test explicit multipart encryption for large data
	multipartResult, err := manager.EncryptDataWithContentType(ctx, largeData, objectKey, factory.ContentTypeMultipart)
	require.NoError(t, err)
	assert.Equal(t, "aes-256-ctr", multipartResult.Metadata["data-algorithm"])
	assert.Equal(t, "multipart", multipartResult.Metadata["content-type"])
}

func TestManager_GetProviderAliases(t *testing.T) {
	cfg := &config.Config{
		Encryption: config.EncryptionConfig{
			EncryptionMethodAlias: "primary",
			Providers: []config.EncryptionProvider{
				{
					Alias: "primary",
					Type:  "aes-gcm",
					Config: map[string]interface{}{
						"key": "12345678901234567890123456789012",
					},
				},
				{
					Alias: "secondary",
					Type:  "aes-gcm",
					Config: map[string]interface{}{
						"key": "abcdefghijklmnopqrstuvwxyz123456",
					},
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

func TestManager_GetActiveProviderAlias(t *testing.T) {
	cfg := &config.Config{
		Encryption: config.EncryptionConfig{
			EncryptionMethodAlias: "active",
			Providers: []config.EncryptionProvider{
				{
					Alias: "active",
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

	activeAlias := manager.GetActiveProviderAlias()
	assert.Equal(t, "active", activeAlias)
}

func TestManager_RotateKEK_NotSupported(t *testing.T) {
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
	err = manager.RotateKEK(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "key rotation not supported")
}

func TestManager_GetProvider_NotSupported(t *testing.T) {
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

	provider, exists := manager.GetProvider("default")
	assert.Nil(t, provider)
	assert.False(t, exists)
}

// TestEncryptWithNoneProvider_PurePassthrough verifies that the none provider
// performs pure pass-through without adding any encryption metadata.
func TestEncryptWithNoneProvider_PurePassthrough(t *testing.T) {
	cfg := &config.Config{
		Encryption: config.EncryptionConfig{
			EncryptionMethodAlias: "none-provider",
			Providers: []config.EncryptionProvider{
				{
					Alias: "none-provider",
					Type:  "none",
					Config: map[string]interface{}{
						"metadata_key_prefix": "s3ep-",
					},
				},
			},
		},
	}

	manager, err := NewManager(cfg)
	require.NoError(t, err)

	testData := []byte("Hello, this is test data for none provider!")
	ctx := context.Background()

	// Test encryption with none provider
	result, err := manager.EncryptData(ctx, testData, "test-key")
	require.NoError(t, err)

	// With none provider, data should be unchanged
	assert.Equal(t, testData, result.EncryptedData, "None provider should not modify data")

	// With none provider, no encryption metadata should be added
	assert.Nil(t, result.EncryptedDEK, "None provider should not add encrypted DEK")
	assert.Nil(t, result.Metadata, "None provider should not add encryption metadata")

	t.Logf("✅ None provider returned unchanged data: %d bytes", len(result.EncryptedData))
	t.Logf("✅ None provider returned no encryption metadata")
}

// TestEncryptWithNoneProvider_Multipart tests multipart upload behavior with none provider
func TestEncryptWithNoneProvider_Multipart(t *testing.T) {
	cfg := &config.Config{
		Encryption: config.EncryptionConfig{
			EncryptionMethodAlias: "none-provider",
			Providers: []config.EncryptionProvider{
				{
					Alias: "none-provider",
					Type:  "none",
					Config: map[string]interface{}{
						"metadata_key_prefix": "s3ep-",
					},
				},
			},
		},
	}

	manager, err := NewManager(cfg)
	require.NoError(t, err)

	ctx := context.Background()
	uploadID := "test-upload-id-123"
	objectKey := "test-multipart-object"
	bucketName := "test-bucket"

	// Test initiate multipart upload with none provider
	err = manager.InitiateMultipartUpload(ctx, uploadID, objectKey, bucketName)
	require.NoError(t, err)

	// Test upload part with none provider
	partData := []byte("This is part data for none provider multipart test")
	partResult, err := manager.UploadPart(ctx, uploadID, 1, partData)
	require.NoError(t, err)
	assert.Equal(t, partData, partResult.EncryptedData, "None provider should not modify part data")
	assert.Nil(t, partResult.EncryptedDEK, "None provider should not add encrypted DEK for parts")
	assert.Nil(t, partResult.Metadata, "None provider should not add metadata for parts")

	// Test complete multipart upload with none provider
	parts := map[int]string{
		1: "test-etag-1",
	}

	completeMetadata, err := manager.CompleteMultipartUpload(ctx, uploadID, parts)
	require.NoError(t, err)
	assert.Nil(t, completeMetadata, "None provider should not return encryption metadata on completion")

	t.Logf("✅ None provider multipart upload completed without encryption metadata")
}
