package integration

import (
	"context"
	"testing"

	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption/providers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEncryptionManager_AESGCMIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test")
	}

	// Generate a test key
	key, err := providers.GenerateAESGCMKey()
	require.NoError(t, err)

	// Create encryptor
	encryptor, err := providers.NewAESGCMProvider(key)
	require.NoError(t, err)

	ctx := context.Background()
	testCases := []struct {
		name           string
		data           []byte
		associatedData []byte
	}{
		{
			name:           "small text",
			data:           []byte("Hello, World!"),
			associatedData: []byte("object-key-1"),
		},
		{
			name:           "empty data",
			data:           []byte(""),
			associatedData: []byte("object-key-2"),
		},
		{
			name:           "large data",
			data:           make([]byte, 1024*1024), // 1MB
			associatedData: []byte("object-key-3"),
		},
		{
			name:           "binary data",
			data:           []byte{0x00, 0xFF, 0xAA, 0x55, 0xCC, 0x33},
			associatedData: []byte("object-key-4"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Fill large data with pattern for testing
			if len(tc.data) > 100 {
				for i := range tc.data {
					tc.data[i] = byte(i % 256)
				}
			}

			// Encrypt
			result, err := encryptor.Encrypt(ctx, tc.data, tc.associatedData)
			require.NoError(t, err)
			assert.NotNil(t, result)
			assert.NotEmpty(t, result.EncryptedData)
			assert.Nil(t, result.EncryptedDEK)
			assert.Equal(t, "aes-gcm", result.Metadata["algorithm"])

			// Ensure data is actually encrypted
			if len(tc.data) > 0 {
				assert.NotEqual(t, tc.data, result.EncryptedData)
			}

			// Decrypt
			decrypted, err := encryptor.Decrypt(ctx, result.EncryptedData, nil, tc.associatedData)
			require.NoError(t, err)

			// Handle empty data case (nil vs empty slice)
			if len(tc.data) == 0 {
				assert.Empty(t, decrypted)
			} else {
				assert.Equal(t, tc.data, decrypted)
			}
		})
	}
}

func TestEncryptionManager_CrossCompatibility(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test")
	}

	// Test that different instances with the same key can encrypt/decrypt
	key, err := providers.GenerateAESGCMKey()
	require.NoError(t, err)

	encryptor1, err := providers.NewAESGCMProvider(key)
	require.NoError(t, err)

	encryptor2, err := providers.NewAESGCMProvider(key)
	require.NoError(t, err)

	ctx := context.Background()
	testData := []byte("Cross-compatibility test data")
	associatedData := []byte("shared-object-key")

	// Encrypt with first instance
	result, err := encryptor1.Encrypt(ctx, testData, associatedData)
	require.NoError(t, err)

	// Decrypt with second instance
	decrypted, err := encryptor2.Decrypt(ctx, result.EncryptedData, nil, associatedData)
	require.NoError(t, err)
	assert.Equal(t, testData, decrypted)

	// Encrypt with second instance
	result2, err := encryptor2.Encrypt(ctx, testData, associatedData)
	require.NoError(t, err)

	// Decrypt with first instance
	decrypted2, err := encryptor1.Decrypt(ctx, result2.EncryptedData, nil, associatedData)
	require.NoError(t, err)
	assert.Equal(t, testData, decrypted2)
}

func TestEncryptionManager_SecurityProperties(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test")
	}

	key, err := providers.GenerateAESGCMKey()
	require.NoError(t, err)

	encryptor, err := providers.NewAESGCMProvider(key)
	require.NoError(t, err)

	ctx := context.Background()
	testData := []byte("Sensitive data that needs protection")
	associatedData := []byte("authenticated-data")

	// Test 1: Same plaintext should produce different ciphertexts (due to random nonces)
	result1, err := encryptor.Encrypt(ctx, testData, associatedData)
	require.NoError(t, err)

	result2, err := encryptor.Encrypt(ctx, testData, associatedData)
	require.NoError(t, err)

	assert.NotEqual(t, result1.EncryptedData, result2.EncryptedData, "Same plaintext should produce different ciphertexts")

	// Test 2: Authentication should fail with modified ciphertext
	modifiedCiphertext := make([]byte, len(result1.EncryptedData))
	copy(modifiedCiphertext, result1.EncryptedData)

	// Flip a bit in the ciphertext (not in the nonce)
	if len(modifiedCiphertext) > 16 { // Skip nonce (first 12 bytes) + some margin
		modifiedCiphertext[20] ^= 0x01
	}

	_, err = encryptor.Decrypt(ctx, modifiedCiphertext, nil, associatedData)
	assert.Error(t, err, "Decryption should fail with modified ciphertext")

	// Test 3: Authentication should fail with wrong associated data
	wrongAssociatedData := []byte("wrong-authenticated-data")
	_, err = encryptor.Decrypt(ctx, result1.EncryptedData, nil, wrongAssociatedData)
	assert.Error(t, err, "Decryption should fail with wrong associated data")
}
