package dataencryption

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAESCTRProvider_EncryptDecrypt(t *testing.T) {
	provider := NewAESCTRDataEncryptor()
	ctx := context.Background()

	// Generate a DEK
	dek, err := provider.GenerateDEK(ctx)
	require.NoError(t, err)

	// Test data
	testData := []byte("Hello, World!")
	associatedData := []byte("test-key")

	// Encrypt
	encryptedData, err := provider.Encrypt(ctx, testData, dek, associatedData)
	require.NoError(t, err)
	assert.NotEmpty(t, encryptedData)

	// Verify that Decrypt now returns the expected error (new behavior)
	_, err = provider.Decrypt(ctx, encryptedData, dek, associatedData)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "AES-CTR decryption should be handled through the Encryption Manager")

	// Verify IVProvider interface works
	ivProvider, ok := provider.(interface{ GetLastIV() []byte })
	require.True(t, ok, "AESCTRDataEncryptor should implement IVProvider")
	iv := ivProvider.GetLastIV()
	require.NotNil(t, iv)
	assert.Len(t, iv, 16) // AES block size
}

func TestAESCTRProvider_Algorithm(t *testing.T) {
	provider := NewAESCTRDataEncryptor()
	assert.Equal(t, "aes-256-ctr", provider.Algorithm())
}
