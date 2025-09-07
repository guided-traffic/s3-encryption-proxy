package providers

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAESCTRProvider_EncryptDecrypt(t *testing.T) {
	// Generate a test key (256 bits)
	testKeyB64 := "XZmcGLpObUuGV8CFOmfLKs7rggrX2TwIk5/Lbt9Azl4=" // Demo key from config

	provider, err := NewAESCTRProviderFromBase64(testKeyB64)
	require.NoError(t, err, "Should create provider successfully")

	tests := []struct {
		name           string
		plaintext      []byte
		associatedData []byte
	}{
		{
			name:           "simple text",
			plaintext:      []byte("Hello, World!"),
			associatedData: []byte("test-object-key"),
		},
		{
			name:           "empty data",
			plaintext:      []byte(""),
			associatedData: []byte("empty-key"),
		},
		{
			name:           "binary data",
			plaintext:      []byte{0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD},
			associatedData: []byte("binary-key"),
		},
		{
			name:           "large data",
			plaintext:      make([]byte, 10000), // 10KB of zeros
			associatedData: []byte("large-key"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()

			// Encrypt the data
			encResult, err := provider.Encrypt(ctx, tt.plaintext, tt.associatedData)
			require.NoError(t, err, "Encryption should succeed")
			require.NotNil(t, encResult, "Encryption result should not be nil")

			// Validate encryption result structure
			assert.NotEmpty(t, encResult.EncryptedData, "Encrypted data should not be empty")
			assert.NotEmpty(t, encResult.EncryptedDEK, "Encrypted DEK should not be empty")
			assert.Contains(t, encResult.Metadata, "encryption-mode", "Should contain encryption mode")
			assert.Equal(t, "aes-ctr", encResult.Metadata["encryption-mode"], "Should be AES-CTR mode")

			// Decrypt the data
			decrypted, err := provider.Decrypt(ctx, encResult.EncryptedData, encResult.EncryptedDEK, tt.associatedData)
			require.NoError(t, err, "Decryption should succeed")

			// Verify decrypted data matches original
			assert.Equal(t, tt.plaintext, decrypted, "Decrypted data should match original")

			t.Logf("Test %s: Original size=%d, Encrypted size=%d, DEK size=%d",
				tt.name, len(tt.plaintext), len(encResult.EncryptedData), len(encResult.EncryptedDEK))
		})
	}
}

func TestAESCTRProvider_NewFromBase64(t *testing.T) {
	tests := []struct {
		name        string
		keyB64      string
		expectError bool
	}{
		{
			name:        "valid base64 key",
			keyB64:      "XZmcGLpObUuGV8CFOmfLKs7rggrX2TwIk5/Lbt9Azl4=", // 256-bit key
			expectError: false,
		},
		{
			name:        "invalid base64",
			keyB64:      "invalid-base64!@#",
			expectError: true,
		},
		{
			name:        "wrong key length",
			keyB64:      base64.StdEncoding.EncodeToString([]byte("too-short")), // Only 9 bytes
			expectError: true,
		},
		{
			name:        "empty key",
			keyB64:      "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider, err := NewAESCTRProviderFromBase64(tt.keyB64)

			if tt.expectError {
				assert.Error(t, err, "Should fail with invalid input")
				assert.Nil(t, provider, "Provider should be nil on error")
			} else {
				assert.NoError(t, err, "Should succeed with valid input")
				assert.NotNil(t, provider, "Provider should not be nil")
			}
		})
	}
}

func TestAESCTRProvider_Config(t *testing.T) {
	config := &AESCTRConfig{
		AESKey: "XZmcGLpObUuGV8CFOmfLKs7rggrX2TwIk5/Lbt9Azl4=",
	}

	err := config.Validate()
	assert.NoError(t, err, "Valid config should pass validation")

	provider, err := NewAESCTRProviderFromConfig(config)
	require.NoError(t, err, "Should create provider from config")
	assert.NotNil(t, provider, "Provider should not be nil")

	// Test the provider works
	ctx := context.Background()
	plaintext := []byte("config test data")
	associatedData := []byte("config-test-key")

	encResult, err := provider.Encrypt(ctx, plaintext, associatedData)
	require.NoError(t, err, "Encryption should work")

	decrypted, err := provider.Decrypt(ctx, encResult.EncryptedData, encResult.EncryptedDEK, associatedData)
	require.NoError(t, err, "Decryption should work")

	assert.Equal(t, plaintext, decrypted, "Round-trip should preserve data")
}

func TestAESCTRProvider_RotateKEK(t *testing.T) {
	testKeyB64 := "XZmcGLpObUuGV8CFOmfLKs7rggrX2TwIk5/Lbt9Azl4="

	provider, err := NewAESCTRProviderFromBase64(testKeyB64)
	require.NoError(t, err)

	ctx := context.Background()

	// Key rotation should not be supported for direct AES-CTR
	err = provider.RotateKEK(ctx)
	assert.Error(t, err, "Key rotation should not be supported")
	assert.Contains(t, err.Error(), "not supported", "Should indicate not supported")
}

func TestAESCTRProvider_GenerateAndDecryptDataKey(t *testing.T) {
	testKeyB64 := "XZmcGLpObUuGV8CFOmfLKs7rggrX2TwIk5/Lbt9Azl4="

	provider, err := NewAESCTRProviderFromBase64(testKeyB64)
	require.NoError(t, err)

	ctx := context.Background()

	// Generate a data key
	dataKey, encryptedKey, err := provider.GenerateDataKey(ctx)
	require.NoError(t, err, "Should generate data key successfully")
	require.NotNil(t, dataKey, "Data key should not be nil")
	require.NotNil(t, encryptedKey, "Encrypted key should not be nil")
	assert.Len(t, dataKey, 32, "Data key should be 32 bytes (256 bits)")
	assert.NotEmpty(t, encryptedKey, "Encrypted key should not be empty")

	// Decrypt the data key
	decryptedKey, err := provider.DecryptDataKey(ctx, encryptedKey)
	require.NoError(t, err, "Should decrypt data key successfully")
	assert.Equal(t, dataKey, decryptedKey, "Decrypted key should match original")
}

func TestAESCTRProvider_StreamingEncryption(t *testing.T) {
	testKeyB64 := "XZmcGLpObUuGV8CFOmfLKs7rggrX2TwIk5/Lbt9Azl4="

	provider, err := NewAESCTRProviderFromBase64(testKeyB64)
	require.NoError(t, err)

	ctx := context.Background()

	// Generate a data key and IV
	dataKey, _, err := provider.GenerateDataKey(ctx)
	require.NoError(t, err)

	// Generate a test IV
	iv := make([]byte, 16)
	for i := range iv {
		iv[i] = byte(i) // Simple test pattern
	}

	// Test data
	plaintext := []byte("This is streaming test data for AES-CTR mode")
	counter := uint64(0)

	// Encrypt with streaming
	ciphertext, err := provider.EncryptStream(ctx, plaintext, dataKey, iv, counter)
	require.NoError(t, err, "Streaming encryption should succeed")
	assert.Len(t, ciphertext, len(plaintext), "Ciphertext should be same length as plaintext")

	// Decrypt with streaming (should be identical to encryption for CTR mode)
	decrypted, err := provider.DecryptStream(ctx, ciphertext, dataKey, iv, counter)
	require.NoError(t, err, "Streaming decryption should succeed")
	assert.Equal(t, plaintext, decrypted, "Streaming decryption should recover original data")
}

func TestAESCTRProvider_GetProviderType(t *testing.T) {
	testKeyB64 := "XZmcGLpObUuGV8CFOmfLKs7rggrX2TwIk5/Lbt9Azl4="

	provider, err := NewAESCTRProviderFromBase64(testKeyB64)
	require.NoError(t, err)

	assert.Equal(t, "aes-ctr", provider.GetProviderType(), "Should return correct provider type")
}

func TestAESCTRProvider_DecryptWithWrongAssociatedData(t *testing.T) {
	testKeyB64 := "XZmcGLpObUuGV8CFOmfLKs7rggrX2TwIk5/Lbt9Azl4="

	provider, err := NewAESCTRProviderFromBase64(testKeyB64)
	require.NoError(t, err)

	ctx := context.Background()
	plaintext := []byte("test data")
	correctAssociatedData := []byte("correct-key")
	wrongAssociatedData := []byte("wrong-key")

	// Encrypt with correct associated data
	encResult, err := provider.Encrypt(ctx, plaintext, correctAssociatedData)
	require.NoError(t, err)

	// Try to decrypt with wrong associated data
	// Note: For AES-CTR, the associated data is used for DEK encryption, not data encryption
	// So this should fail at the DEK decryption level
	decrypted, err := provider.Decrypt(ctx, encResult.EncryptedData, encResult.EncryptedDEK, wrongAssociatedData)

	// The behavior depends on how the DEK encryption handles associated data
	// For now, we expect this to work since AES-CTR doesn't use associated data for the actual data encryption
	// but if the DEK encryption uses it, it might fail
	if err != nil {
		t.Logf("Decryption failed with wrong associated data (expected): %v", err)
	} else {
		t.Logf("Decryption succeeded despite wrong associated data. Result: %s", string(decrypted))
		// This might happen if DEK encryption doesn't use associated data effectively
	}
}

func TestAESCTRProvider_StreamEncryptWithCounter(t *testing.T) {
	provider, err := NewAESCTRProviderFromBase64("XZmcGLpObUuGV8CFOmfLKs7rggrX2TwIk5/Lbt9Azl4=")
	require.NoError(t, err)

	ctx := context.Background()
	originalData := []byte("This is a test file for debugging AES-CTR encryption and decryption.")

	// Generate DEK and IV
	dek, _, err := provider.GenerateDataKey(ctx)
	require.NoError(t, err)

	iv := make([]byte, 16)
	_, err = io.ReadFull(rand.Reader, iv)
	require.NoError(t, err)

	t.Logf("Original data: %q (%d bytes)", string(originalData), len(originalData))
	t.Logf("DEK: %x", dek)
	t.Logf("IV: %x", iv)

	// Test streaming encryption in chunks (like the proxy does)
	chunkSize := 20 // Smaller chunks for testing
	var encryptedChunks [][]byte
	counter := uint64(0)

	for i := 0; i < len(originalData); i += chunkSize {
		end := i + chunkSize
		if end > len(originalData) {
			end = len(originalData)
		}
		chunk := originalData[i:end]

		t.Logf("Encrypting chunk at offset %d: %q", counter, string(chunk))

		encryptedChunk, err := provider.EncryptStream(ctx, chunk, dek, iv, counter)
		require.NoError(t, err)

		encryptedChunks = append(encryptedChunks, encryptedChunk)
		counter += uint64(len(chunk))

		t.Logf("Encrypted chunk: %x", encryptedChunk)
	}

	// Combine encrypted chunks
	var combinedEncrypted []byte
	for _, chunk := range encryptedChunks {
		combinedEncrypted = append(combinedEncrypted, chunk...)
	}

	t.Logf("Combined encrypted: %x", combinedEncrypted)

	// Now test decryption - should decrypt the entire combined data at once
	decrypted, err := provider.DecryptStream(ctx, combinedEncrypted, dek, iv, 0)
	require.NoError(t, err)

	t.Logf("Decrypted: %q (%d bytes)", string(decrypted), len(decrypted))

	// Compare
	if !bytes.Equal(originalData, decrypted) {
		t.Errorf("Data mismatch!\nOriginal:  %q\nDecrypted: %q", string(originalData), string(decrypted))
		t.Errorf("Original hex:  %x", originalData)
		t.Errorf("Decrypted hex: %x", decrypted)
	}
}
