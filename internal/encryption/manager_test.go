package encryption

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewManager_AESGCMProvider(t *testing.T) {
	cfg := &Config{
		EncryptionType: "aes256-gcm",
		AESKey:         "1UR+yQO2Ap3NJabyhkwSm0qk/vllEa2Jae+NSxyVas8=", // 32-byte base64 key
	}

	manager, err := NewManager(cfg)
	require.NoError(t, err)
	assert.NotNil(t, manager)
	assert.Equal(t, cfg, manager.config)
}

func TestNewManager_TinkProvider(t *testing.T) {
	cfg := &Config{
		EncryptionType: "tink",
		KEKUri:         "gcp-kms://projects/test/locations/global/keyRings/test/cryptoKeys/test",
	}

	manager, err := NewManager(cfg)
	require.NoError(t, err)
	assert.NotNil(t, manager)
	assert.Equal(t, cfg, manager.config)
}

func TestNewManager_InvalidConfig(t *testing.T) {
	tests := []struct {
		name   string
		config *Config
	}{
		{
			name: "unsupported encryption type",
			config: &Config{
				EncryptionType: "unsupported",
			},
		},
		{
			name: "AES-GCM without key",
			config: &Config{
				EncryptionType: "aes256-gcm",
			},
		},
		{
			name: "Tink without KEK URI",
			config: &Config{
				EncryptionType: "tink",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manager, err := NewManager(tt.config)
			assert.Error(t, err)
			assert.Nil(t, manager)
		})
	}
}

func TestManager_EncryptDecryptData(t *testing.T) {
	cfg := &Config{
		EncryptionType: "aes256-gcm",
		AESKey:         "1UR+yQO2Ap3NJabyhkwSm0qk/vllEa2Jae+NSxyVas8=", // 32-byte base64 key
	}

	manager, err := NewManager(cfg)
	require.NoError(t, err)

	ctx := context.Background()
	testData := []byte("Hello, World! This is test data for encryption.")
	objectKey := "test-object-key"

	// Encrypt data
	result, err := manager.EncryptData(ctx, testData, objectKey)
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.NotEmpty(t, result.EncryptedData)
	assert.NotEqual(t, testData, result.EncryptedData)

	// Decrypt data
	decrypted, err := manager.DecryptData(ctx, result.EncryptedData, result.EncryptedDEK, objectKey)
	require.NoError(t, err)
	assert.Equal(t, testData, decrypted)
}

func TestManager_RotateKEK_AESGCMNotSupported(t *testing.T) {
	cfg := &Config{
		EncryptionType: "aes256-gcm",
		AESKey:         "1UR+yQO2Ap3NJabyhkwSm0qk/vllEa2Jae+NSxyVas8=", // 32-byte base64 key
	}

	manager, err := NewManager(cfg)
	require.NoError(t, err)

	ctx := context.Background()
	err = manager.RotateKEK(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not supported")
}

func TestManager_RotateKEK_TinkNotImplemented(t *testing.T) {
	cfg := &Config{
		EncryptionType: "tink",
		KEKUri:         "gcp-kms://projects/test/locations/global/keyRings/test/cryptoKeys/test",
	}

	manager, err := NewManager(cfg)
	require.NoError(t, err)

	ctx := context.Background()
	err = manager.RotateKEK(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not implemented")
}
