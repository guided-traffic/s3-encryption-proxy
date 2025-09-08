package keyencryption

import (
	"context"
	"testing"

	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/keyset"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTinkProvider_EncryptDecrypt(t *testing.T) {
	// Create a KEK handle for testing
	kekHandle, err := keyset.NewHandle(aead.AES256GCMKeyTemplate())
	require.NoError(t, err)

	// Create provider
	provider, err := NewTinkProvider(kekHandle, "test://kek/uri")
	require.NoError(t, err)

	tests := []struct {
		name           string
		data           []byte
		associatedData []byte
	}{
		{
			name:           "simple text",
			data:           []byte("Hello, World!"),
			associatedData: []byte("test-object-key"),
		},
		{
			name:           "empty data",
			data:           []byte(""),
			associatedData: []byte("empty-object"),
		},
		{
			name:           "binary data",
			data:           []byte{0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD},
			associatedData: []byte("binary-object"),
		},
		{
			name:           "large data",
			data:           make([]byte, 1024*1024), // 1MB
			associatedData: []byte("large-object"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()

			// Encrypt the data
			result, err := provider.Encrypt(ctx, tt.data, tt.associatedData)
			require.NoError(t, err)
			require.NotNil(t, result)

			// Verify encryption result
			assert.NotEmpty(t, result.EncryptedData)
			assert.NotEmpty(t, result.EncryptedDEK)
			assert.NotEqual(t, tt.data, result.EncryptedData, "encrypted data should be different from original")
			assert.Contains(t, result.Metadata, "algorithm")
			assert.Contains(t, result.Metadata, "version")
			assert.Equal(t, "envelope-aes-gcm", result.Metadata["algorithm"])

			// Decrypt the data
			decrypted, err := provider.Decrypt(ctx, result.EncryptedData, result.EncryptedDEK, tt.associatedData)
			require.NoError(t, err)

			// Verify decryption
			if len(tt.data) == 0 {
				// For empty data, both nil and empty slice are equivalent
				assert.Empty(t, decrypted, "decrypted data should be empty")
			} else {
				assert.Equal(t, tt.data, decrypted, "decrypted data should match original")
			}
		})
	}
}

func TestTinkProvider_NewWithNilHandle(t *testing.T) {
	provider, err := NewTinkProvider(nil, "test://kek/uri")
	assert.Error(t, err)
	assert.Nil(t, provider)
	assert.Contains(t, err.Error(), "KEK handle cannot be nil")
}

func TestTinkProvider_DecryptWithNilDEK(t *testing.T) {
	kekHandle, err := keyset.NewHandle(aead.AES256GCMKeyTemplate())
	require.NoError(t, err)

	provider, err := NewTinkProvider(kekHandle, "test://kek/uri")
	require.NoError(t, err)

	ctx := context.Background()
	encryptedData := []byte("dummy-encrypted-data")
	associatedData := []byte("test-key")

	// Decrypt without DEK should fail
	_, err = provider.Decrypt(ctx, encryptedData, nil, associatedData)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "encrypted DEK is required")
}

func TestTinkProvider_DecryptWithWrongAssociatedData(t *testing.T) {
	kekHandle, err := keyset.NewHandle(aead.AES256GCMKeyTemplate())
	require.NoError(t, err)

	provider, err := NewTinkProvider(kekHandle, "test://kek/uri")
	require.NoError(t, err)

	ctx := context.Background()
	testData := []byte("test data")
	correctAAD := []byte("correct-aad")
	wrongAAD := []byte("wrong-aad")

	// Encrypt with correct AAD
	result, err := provider.Encrypt(ctx, testData, correctAAD)
	require.NoError(t, err)

	// Decrypt with wrong AAD should fail
	_, err = provider.Decrypt(ctx, result.EncryptedData, result.EncryptedDEK, wrongAAD)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decrypt")
}

func TestTinkProvider_RotateKEK(t *testing.T) {
	kekHandle, err := keyset.NewHandle(aead.AES256GCMKeyTemplate())
	require.NoError(t, err)

	provider, err := NewTinkProvider(kekHandle, "test://kek/uri")
	require.NoError(t, err)

	// KEK rotation should return an error (not implemented)
	err = provider.RotateKEK(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not implemented")
}

func TestTinkProvider_CrossCompatibility(t *testing.T) {
	// Create two different KEK handles
	kekHandle1, err := keyset.NewHandle(aead.AES256GCMKeyTemplate())
	require.NoError(t, err)

	kekHandle2, err := keyset.NewHandle(aead.AES256GCMKeyTemplate())
	require.NoError(t, err)

	// Create two providers with different KEKs
	provider1, err := NewTinkProvider(kekHandle1, "test://kek/uri1")
	require.NoError(t, err)

	provider2, err := NewTinkProvider(kekHandle2, "test://kek/uri2")
	require.NoError(t, err)

	ctx := context.Background()
	testData := []byte("cross-compatibility test")
	associatedData := []byte("test-key")

	// Encrypt with first provider
	result, err := provider1.Encrypt(ctx, testData, associatedData)
	require.NoError(t, err)

	// Decrypt with second provider should fail (different KEK)
	_, err = provider2.Decrypt(ctx, result.EncryptedData, result.EncryptedDEK, associatedData)
	assert.Error(t, err, "decryption with different KEK should fail")
}
