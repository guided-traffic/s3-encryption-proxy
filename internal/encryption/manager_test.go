package encryption

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/guided-traffic/s3-encryption-proxy/internal/config"
)

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
	objectKey := "test/object.txt"

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
	objectKey := "test/object.txt"

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
	objectKey := "test/object.txt"

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
	objectKey := "test/object.txt"

	// Should fallback to trying all providers
	decrypted, err := manager.DecryptData(ctx, encryptedData, nil, objectKey, "nonexistent")
	require.NoError(t, err)
	assert.Equal(t, encryptedData, decrypted)
}

func TestDecryptDataLegacy_Success(t *testing.T) {
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
	objectKey := "test/object.txt"

	decrypted, err := manager.DecryptDataLegacy(ctx, encryptedData, nil, objectKey)
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
