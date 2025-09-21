package dataencryption

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAESGCMProvider_EncryptDecrypt(t *testing.T) {
	// Create provider
	provider := NewAESGCMDataEncryptor()

	ctx := context.Background()
	testData := []byte("Hello, World! This is a test message for aes-gcm encryption.")
	associatedData := []byte("test-object-key")

	// Calculate original data hash
	originalHash := fmt.Sprintf("%x", sha256.Sum256(testData))

	// Generate a DEK for this test
	dek, err := provider.GenerateDEK(ctx)
	require.NoError(t, err)

	// Encrypt using streaming interface
	dataReader := bufio.NewReader(bytes.NewReader(testData))
	encryptedReader, err := provider.EncryptStream(ctx, dataReader, dek, associatedData)
	require.NoError(t, err)

	// Calculate encrypted data hash (should be different from original)
	encryptedHash, err := calculateStreamingSHA256(encryptedReader)
	require.NoError(t, err)
	assert.NotEmpty(t, encryptedHash)
	assert.NotEqual(t, originalHash, encryptedHash, "Encrypted data hash should differ from original")

	// For decryption, encrypt again to get a fresh encrypted stream
	dataReader2 := bufio.NewReader(bytes.NewReader(testData))
	encryptedReader2, err := provider.EncryptStream(ctx, dataReader2, dek, associatedData)
	require.NoError(t, err)

	// Decrypt using streaming interface (AES-GCM extracts nonce from encrypted data, so pass nil for IV)
	decryptedReader, err := provider.DecryptStream(ctx, encryptedReader2, dek, nil, associatedData)
	require.NoError(t, err)

	// Calculate decrypted data hash (should match original)
	decryptedHash, err := calculateStreamingSHA256(decryptedReader)
	require.NoError(t, err)
	assert.Equal(t, originalHash, decryptedHash, "Decrypted data hash should match original")
}

func TestAESGCMProvider_Algorithm(t *testing.T) {
	provider := NewAESGCMDataEncryptor()
	assert.Equal(t, "aes-gcm", provider.Algorithm(), "Should return correct algorithm")
}

func TestAESGCMProvider_GenerateDEK(t *testing.T) {
	provider := NewAESGCMDataEncryptor()
	ctx := context.Background()

	dek, err := provider.GenerateDEK(ctx)
	require.NoError(t, err)
	assert.Len(t, dek, 32, "Generated DEK should be 32 bytes (256 bits)")

	// Generate another DEK and ensure they're different
	dek2, err := provider.GenerateDEK(ctx)
	require.NoError(t, err)
	assert.NotEqual(t, dek, dek2, "Generated DEKs should be different")
}
