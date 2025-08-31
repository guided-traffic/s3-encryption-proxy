package encryption

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAESGCMEncryptor_GenerateKey(t *testing.T) {
	key, err := GenerateAESGCMKey()
	require.NoError(t, err)
	assert.Len(t, key, 32, "AES-256 key should be 32 bytes")
}

func TestAESGCMEncryptor_NewAESGCMEncryptor(t *testing.T) {
	tests := []struct {
		name        string
		keySize     int
		expectError bool
	}{
		{
			name:        "valid 32-byte key",
			keySize:     32,
			expectError: false,
		},
		{
			name:        "invalid 16-byte key",
			keySize:     16,
			expectError: true,
		},
		{
			name:        "invalid 24-byte key",
			keySize:     24,
			expectError: true,
		},
		{
			name:        "invalid 0-byte key",
			keySize:     0,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := make([]byte, tt.keySize)
			encryptor, err := NewAESGCMEncryptor(key)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, encryptor)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, encryptor)
			}
		})
	}
}

func TestAESGCMEncryptor_EncryptDecrypt(t *testing.T) {
	// Generate a test key
	key, err := GenerateAESGCMKey()
	require.NoError(t, err)

	// Create encryptor
	encryptor, err := NewAESGCMEncryptor(key)
	require.NoError(t, err)

	ctx := context.Background()
	testData := []byte("Hello, World! This is a test message for AES-256-GCM encryption.")
	associatedData := []byte("test-object-key")

	// Encrypt
	result, err := encryptor.Encrypt(ctx, testData, associatedData)
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.NotEmpty(t, result.EncryptedData)
	assert.Nil(t, result.EncryptedDEK, "AES-GCM should not use a DEK")
	assert.Equal(t, "aes-gcm", result.Metadata["algorithm"])

	// Ensure encrypted data is different from original
	assert.NotEqual(t, testData, result.EncryptedData)

	// Decrypt
	decrypted, err := encryptor.Decrypt(ctx, result.EncryptedData, nil, associatedData)
	require.NoError(t, err)
	assert.Equal(t, testData, decrypted)
}

func TestAESGCMEncryptor_DecryptWithWrongKey(t *testing.T) {
	// Generate two different keys
	key1, err := GenerateAESGCMKey()
	require.NoError(t, err)

	key2, err := GenerateAESGCMKey()
	require.NoError(t, err)

	// Create encryptors
	encryptor1, err := NewAESGCMEncryptor(key1)
	require.NoError(t, err)

	encryptor2, err := NewAESGCMEncryptor(key2)
	require.NoError(t, err)

	ctx := context.Background()
	testData := []byte("Secret message")
	associatedData := []byte("test-key")

	// Encrypt with first key
	result, err := encryptor1.Encrypt(ctx, testData, associatedData)
	require.NoError(t, err)

	// Try to decrypt with second key (should fail)
	_, err = encryptor2.Decrypt(ctx, result.EncryptedData, nil, associatedData)
	assert.Error(t, err, "Decryption should fail with wrong key")
}

func TestAESGCMEncryptor_DecryptWithWrongAssociatedData(t *testing.T) {
	key, err := GenerateAESGCMKey()
	require.NoError(t, err)

	encryptor, err := NewAESGCMEncryptor(key)
	require.NoError(t, err)

	ctx := context.Background()
	testData := []byte("Secret message")
	associatedData := []byte("correct-associated-data")
	wrongAssociatedData := []byte("wrong-associated-data")

	// Encrypt
	result, err := encryptor.Encrypt(ctx, testData, associatedData)
	require.NoError(t, err)

	// Try to decrypt with wrong associated data (should fail)
	_, err = encryptor.Decrypt(ctx, result.EncryptedData, nil, wrongAssociatedData)
	assert.Error(t, err, "Decryption should fail with wrong associated data")
}

func TestAESGCMEncryptor_DecryptTruncatedData(t *testing.T) {
	key, err := GenerateAESGCMKey()
	require.NoError(t, err)

	encryptor, err := NewAESGCMEncryptor(key)
	require.NoError(t, err)

	ctx := context.Background()
	associatedData := []byte("test-key")

	// Try to decrypt truncated data (shorter than nonce size)
	truncatedData := []byte{1, 2, 3} // Too short for nonce
	_, err = encryptor.Decrypt(ctx, truncatedData, nil, associatedData)
	assert.Error(t, err, "Decryption should fail with truncated data")
}

func TestAESGCMEncryptor_RotateKEK(t *testing.T) {
	key, err := GenerateAESGCMKey()
	require.NoError(t, err)

	encryptor, err := NewAESGCMEncryptor(key)
	require.NoError(t, err)

	ctx := context.Background()

	// KEK rotation should not be applicable for direct encryption
	err = encryptor.RotateKEK(ctx)
	assert.Error(t, err, "KEK rotation should not be applicable for AES-GCM")
}

func TestAESGCMEncryptor_MultipleEncryptions(t *testing.T) {
	key, err := GenerateAESGCMKey()
	require.NoError(t, err)

	encryptor, err := NewAESGCMEncryptor(key)
	require.NoError(t, err)

	ctx := context.Background()
	testData := []byte("Test message")
	associatedData := []byte("test-key")

	// Encrypt the same data multiple times
	result1, err := encryptor.Encrypt(ctx, testData, associatedData)
	require.NoError(t, err)

	result2, err := encryptor.Encrypt(ctx, testData, associatedData)
	require.NoError(t, err)

	// Results should be different due to random nonces
	assert.NotEqual(t, result1.EncryptedData, result2.EncryptedData)

	// Both should decrypt to the same plaintext
	decrypted1, err := encryptor.Decrypt(ctx, result1.EncryptedData, nil, associatedData)
	require.NoError(t, err)

	decrypted2, err := encryptor.Decrypt(ctx, result2.EncryptedData, nil, associatedData)
	require.NoError(t, err)

	assert.Equal(t, testData, decrypted1)
	assert.Equal(t, testData, decrypted2)
}
