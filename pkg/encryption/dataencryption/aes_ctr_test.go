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

func TestAESCTRProvider_EncryptDecryptStream(t *testing.T) {
	provider := NewAESCTRDataEncryptor()
	ctx := context.Background()

	// Generate a DEK
	dek, err := provider.GenerateDEK(ctx)
	require.NoError(t, err)

	// Test data
	testData := []byte("Hello, World!")
	associatedData := []byte("test-key")

	// Encrypt using streaming interface
	reader := bufio.NewReader(bytes.NewReader(testData))
	encryptedReader, err := provider.EncryptStream(ctx, reader, dek, associatedData)
	require.NoError(t, err)
	assert.NotNil(t, encryptedReader)

	// Read encrypted data
	var encryptedBuffer bytes.Buffer
	_, err = io.Copy(&encryptedBuffer, encryptedReader)
	require.NoError(t, err)
	encryptedData := encryptedBuffer.Bytes()
	assert.NotEmpty(t, encryptedData)
	assert.NotEqual(t, testData, encryptedData) // Ensure data is actually encrypted

	// Get IV for decryption
	ivProvider, ok := provider.(interface{ GetLastIV() []byte })
	require.True(t, ok, "AESCTRDataEncryptor should implement IVProvider")
	iv := ivProvider.GetLastIV()
	require.NotNil(t, iv)
	assert.Len(t, iv, 16) // AES block size

	// Decrypt using streaming interface
	// For AES-CTR, we need to handle the IV properly.
	// Since DecryptStream expects metadata management to provide the IV,
	// we'll test the type assertion to access DecryptStreamWithIV which the implementation provides
	encryptedReader2 := bufio.NewReader(bytes.NewReader(encryptedData))

	// Create a new provider instance for decryption
	decryptProvider := NewAESCTRDataEncryptor()

	// Type assert to access the specific AES-CTR implementation method
	aesCTRProvider, ok := decryptProvider.(*AESCTRDataEncryptor)
	require.True(t, ok, "Provider should be AESCTRDataEncryptor")

	// Use DecryptStreamWithIV method which exists on the concrete type
	decryptedReader, err := aesCTRProvider.DecryptStreamWithIV(ctx, encryptedReader2, dek, iv, associatedData)
	require.NoError(t, err)
	assert.NotNil(t, decryptedReader)

	// Read decrypted data
	var decryptedBuffer bytes.Buffer
	_, err = io.Copy(&decryptedBuffer, decryptedReader)
	require.NoError(t, err)
	decryptedData := decryptedBuffer.Bytes()

	// Verify decryption
	assert.Equal(t, testData, decryptedData)
}

func TestAESCTRProvider_Algorithm(t *testing.T) {
	provider := NewAESCTRDataEncryptor()
	assert.Equal(t, "aes-256-ctr", provider.Algorithm())
}
