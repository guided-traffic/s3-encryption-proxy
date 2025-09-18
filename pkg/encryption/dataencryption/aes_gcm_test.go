package dataencryption

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAESGCMProvider_EncryptDecrypt(t *testing.T) {
	// Create provider
	provider := NewAESGCMDataEncryptor()

	ctx := context.Background()
	testData := []byte("Hello, World! This is a test message for AES-256-GCM encryption.")
	associatedData := []byte("test-object-key")

	// Generate a DEK for this test
	dek, err := provider.GenerateDEK(ctx)
	require.NoError(t, err)

	// Encrypt using streaming interface
	dataReader := bufio.NewReader(bytes.NewReader(testData))
	encryptedReader, err := provider.EncryptStream(ctx, dataReader, dek, associatedData)
	require.NoError(t, err)

	// Read all encrypted data
	encryptedData, err := io.ReadAll(encryptedReader)
	require.NoError(t, err)
	assert.NotEmpty(t, encryptedData)

	// Ensure encrypted data is different from original
	assert.NotEqual(t, testData, encryptedData)

	// Decrypt using streaming interface (AES-GCM extracts nonce from encrypted data, so pass nil for IV)
	encryptedDataReader := bufio.NewReader(bytes.NewReader(encryptedData))
	decryptedReader, err := provider.DecryptStream(ctx, encryptedDataReader, dek, nil, associatedData)
	require.NoError(t, err)

	// Read all decrypted data
	decrypted, err := io.ReadAll(decryptedReader)
	require.NoError(t, err)
	assert.Equal(t, testData, decrypted)
}

func TestAESGCMProvider_Algorithm(t *testing.T) {
	provider := NewAESGCMDataEncryptor()
	assert.Equal(t, "aes-256-gcm", provider.Algorithm(), "Should return correct algorithm")
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
