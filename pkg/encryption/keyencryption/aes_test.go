package keyencryption

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAESKeyEncryptor_Basic(t *testing.T) {
	// Create KEK (32 bytes for AES-256)
	kek := []byte("12345678901234567890123456789012")

	provider, err := NewAESKeyEncryptor(kek)
	require.NoError(t, err)

	ctx := context.Background()
	testDEK := []byte("test-dek-32-bytes-123456789012345")

	// Test EncryptDEK
	encryptedDEK, keyID, err := provider.EncryptDEK(ctx, testDEK)
	require.NoError(t, err)
	assert.NotEmpty(t, keyID)
	assert.NotEqual(t, testDEK, encryptedDEK)

	// Test DecryptDEK
	decryptedDEK, err := provider.DecryptDEK(ctx, encryptedDEK, keyID)
	require.NoError(t, err)
	assert.Equal(t, testDEK, decryptedDEK)
}

func TestAESKeyEncryptor_Algorithm(t *testing.T) {
	kek := []byte("12345678901234567890123456789012")
	provider, err := NewAESKeyEncryptor(kek)
	require.NoError(t, err)

	fingerprint := provider.Fingerprint()
	assert.NotEmpty(t, fingerprint)
}

func TestAESProvider_InvalidKEK(t *testing.T) {
	// Test invalid KEK size
	shortKEK := []byte("short")
	_, err := NewAESKeyEncryptor(shortKEK)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "must be exactly 32 bytes")
}

func TestAESProviderFromConfig(t *testing.T) {
	provider, err := NewAESProvider(map[string]interface{}{
		"aes_key": "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=",
	})
	require.NoError(t, err)

	ctx := context.Background()
	testDEK := []byte("test-dek-32-bytes-123456789012345")

	encryptedDEK, keyID, err := provider.EncryptDEK(ctx, testDEK)
	require.NoError(t, err)
	assert.NotEmpty(t, keyID)

	decryptedDEK, err := provider.DecryptDEK(ctx, encryptedDEK, keyID)
	require.NoError(t, err)
	assert.Equal(t, testDEK, decryptedDEK)
}
