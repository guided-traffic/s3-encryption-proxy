package dataencryption

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
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

	// Calculate original data hash
	originalHash := fmt.Sprintf("%x", sha256.Sum256(testData))

	// Encrypt using streaming interface
	reader := bufio.NewReader(bytes.NewReader(testData))
	encryptedReader, err := provider.EncryptStream(ctx, reader, dek, associatedData)
	require.NoError(t, err)
	assert.NotNil(t, encryptedReader)

	// Get IV for this encryption
	ivProvider, ok := provider.(interface{ GetLastIV() []byte })
	require.True(t, ok, "AESCTRDataEncryptor should implement IVProvider")
	iv := ivProvider.GetLastIV()
	require.NotNil(t, iv)
	assert.Len(t, iv, 16) // AES block size

	// Store encrypted data for decryption (necessary since streams are consumed)
	var encryptedBuffer bytes.Buffer
	_, err = io.Copy(&encryptedBuffer, encryptedReader)
	require.NoError(t, err)
	encryptedData := encryptedBuffer.Bytes()
	assert.NotEmpty(t, encryptedData)

	// Verify encrypted data is different by comparing hashes
	encryptedHash := fmt.Sprintf("%x", sha256.Sum256(encryptedData))
	assert.NotEqual(t, originalHash, encryptedHash, "Encrypted data hash should differ from original")

	// Create a new provider instance for decryption
	decryptProvider := NewAESCTRDataEncryptor()

	// Type assert to access the specific AES-CTR implementation method
	aesCTRProvider, ok := decryptProvider.(*AESCTRDataEncryptor)
	require.True(t, ok, "Provider should be AESCTRDataEncryptor")

	// Decrypt using the same IV
	encryptedReader2 := bufio.NewReader(bytes.NewReader(encryptedData))
	decryptedReader, err := aesCTRProvider.DecryptStream(ctx, encryptedReader2, dek, iv, associatedData)
	require.NoError(t, err)
	assert.NotNil(t, decryptedReader)

	// Calculate decrypted data hash using streaming approach
	decryptedHash, err := calculateStreamingSHA256(decryptedReader)
	require.NoError(t, err)
	assert.Equal(t, originalHash, decryptedHash, "Decrypted data hash should match original")
}

func TestAESCTRProvider_Algorithm(t *testing.T) {
	provider := NewAESCTRDataEncryptor()
	assert.Equal(t, "aes-ctr", provider.Algorithm())
}
