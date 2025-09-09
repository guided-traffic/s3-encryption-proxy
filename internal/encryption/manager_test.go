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
