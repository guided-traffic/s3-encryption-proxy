package providers

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAESGCMProvider_EncryptDecrypt(t *testing.T) {
	// Generate a test key
	key, err := GenerateAESGCMKey()
	require.NoError(t, err)

	// Create provider
	provider, err := NewAESGCMProvider(key)
	require.NoError(t, err)

	ctx := context.Background()
	testData := []byte("Hello, World! This is a test message for AES-256-GCM encryption.")
	associatedData := []byte("test-object-key")

	// Encrypt
	result, err := provider.Encrypt(ctx, testData, associatedData)
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.NotEmpty(t, result.EncryptedData)
	assert.Nil(t, result.EncryptedDEK, "AES-GCM should not use a DEK")
	assert.Equal(t, "aes256-gcm", result.Metadata["algorithm"])

	// Ensure encrypted data is different from original
	assert.NotEqual(t, testData, result.EncryptedData)

	// Decrypt
	decrypted, err := provider.Decrypt(ctx, result.EncryptedData, nil, associatedData)
	require.NoError(t, err)
	assert.Equal(t, testData, decrypted)
}

func TestAESGCMProvider_NewFromBase64(t *testing.T) {
	tests := []struct {
		name      string
		base64Key string
		wantError bool
	}{
		{
			name:      "valid base64 key",
			base64Key: "1UR+yQO2Ap3NJabyhkwSm0qk/vllEa2Jae+NSxyVas8=", // 32 bytes
			wantError: false,
		},
		{
			name:      "invalid base64",
			base64Key: "invalid-base64!",
			wantError: true,
		},
		{
			name:      "wrong key length",
			base64Key: "dGVzdA==", // "test" - only 4 bytes
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider, err := NewAESGCMProviderFromBase64(tt.base64Key)
			if tt.wantError {
				assert.Error(t, err)
				assert.Nil(t, provider)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, provider)
			}
		})
	}
}

func TestAESGCMProvider_RotateKEK(t *testing.T) {
	key, err := GenerateAESGCMKey()
	require.NoError(t, err)

	provider, err := NewAESGCMProvider(key)
	require.NoError(t, err)

	// KEK rotation should not be supported for AES-GCM
	err = provider.RotateKEK(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not supported")
}

func TestAESGCMProvider_DecryptWithWrongAssociatedData(t *testing.T) {
	key, err := GenerateAESGCMKey()
	require.NoError(t, err)

	provider, err := NewAESGCMProvider(key)
	require.NoError(t, err)

	ctx := context.Background()
	testData := []byte("test data")
	correctAAD := []byte("correct-aad")
	wrongAAD := []byte("wrong-aad")

	// Encrypt with correct AAD
	result, err := provider.Encrypt(ctx, testData, correctAAD)
	require.NoError(t, err)

	// Decrypt with wrong AAD should fail
	_, err = provider.Decrypt(ctx, result.EncryptedData, nil, wrongAAD)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decrypt")
}

func TestGenerateAESGCMKey(t *testing.T) {
	key, err := GenerateAESGCMKey()
	require.NoError(t, err)
	assert.Len(t, key, 32, "Generated key should be 32 bytes (256 bits)")

	// Generate another key and ensure they're different
	key2, err := GenerateAESGCMKey()
	require.NoError(t, err)
	assert.NotEqual(t, key, key2, "Generated keys should be different")
}
