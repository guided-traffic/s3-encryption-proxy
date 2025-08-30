package envelope

import (
	"context"
	"testing"

	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/keyset"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTinkEncryptor_EncryptDecrypt(t *testing.T) {
	// Create a KEK handle for testing
	kekHandle, err := keyset.NewHandle(aead.AES256GCMKeyTemplate())
	require.NoError(t, err)

	// Create encryptor
	encryptor, err := NewTinkEncryptor(kekHandle, nil)
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
			result, err := encryptor.Encrypt(ctx, tt.data, tt.associatedData)
			require.NoError(t, err)
			require.NotNil(t, result)

			// Verify encryption result
			assert.NotEmpty(t, result.EncryptedData)
			assert.NotEmpty(t, result.EncryptedDEK)
			assert.NotEqual(t, tt.data, result.EncryptedData, "encrypted data should be different from original")
			assert.Contains(t, result.Metadata, "algorithm")
			assert.Contains(t, result.Metadata, "version")

			// Decrypt the data
			decrypted, err := encryptor.Decrypt(ctx, result.EncryptedData, result.EncryptedDEK, tt.associatedData)
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

func TestTinkEncryptor_DecryptWithWrongAssociatedData(t *testing.T) {
	// Create a KEK handle for testing
	kekHandle, err := keyset.NewHandle(aead.AES256GCMKeyTemplate())
	require.NoError(t, err)

	// Create encryptor
	encryptor, err := NewTinkEncryptor(kekHandle, nil)
	require.NoError(t, err)

	ctx := context.Background()
	data := []byte("secret data")
	correctAAD := []byte("correct-object-key")
	wrongAAD := []byte("wrong-object-key")

	// Encrypt with correct associated data
	result, err := encryptor.Encrypt(ctx, data, correctAAD)
	require.NoError(t, err)

	// Try to decrypt with wrong associated data
	_, err = encryptor.Decrypt(ctx, result.EncryptedData, result.EncryptedDEK, wrongAAD)
	assert.Error(t, err, "decryption should fail with wrong associated data")
}

func TestTinkEncryptor_DecryptWithCorruptedData(t *testing.T) {
	// Create a KEK handle for testing
	kekHandle, err := keyset.NewHandle(aead.AES256GCMKeyTemplate())
	require.NoError(t, err)

	// Create encryptor
	encryptor, err := NewTinkEncryptor(kekHandle, nil)
	require.NoError(t, err)

	ctx := context.Background()
	data := []byte("secret data")
	aad := []byte("object-key")

	// Encrypt the data
	result, err := encryptor.Encrypt(ctx, data, aad)
	require.NoError(t, err)

	// Corrupt the encrypted data
	corruptedData := make([]byte, len(result.EncryptedData))
	copy(corruptedData, result.EncryptedData)
	corruptedData[0] ^= 0xFF // Flip bits in first byte

	// Try to decrypt corrupted data
	_, err = encryptor.Decrypt(ctx, corruptedData, result.EncryptedDEK, aad)
	assert.Error(t, err, "decryption should fail with corrupted data")

	// Corrupt the encrypted DEK
	corruptedDEK := make([]byte, len(result.EncryptedDEK))
	copy(corruptedDEK, result.EncryptedDEK)
	corruptedDEK[0] ^= 0xFF // Flip bits in first byte

	// Try to decrypt with corrupted DEK
	_, err = encryptor.Decrypt(ctx, result.EncryptedData, corruptedDEK, aad)
	assert.Error(t, err, "decryption should fail with corrupted DEK")
}

func TestNewTinkEncryptor_InvalidInput(t *testing.T) {
	// Test with nil handle
	_, err := NewTinkEncryptor(nil, nil)
	assert.Error(t, err, "should fail with nil KEK handle")
	assert.Contains(t, err.Error(), "KEK handle cannot be nil")
}

// Benchmark encryption performance
func BenchmarkTinkEncryptor_Encrypt(b *testing.B) {
	// Create a KEK handle
	kekHandle, err := keyset.NewHandle(aead.AES256GCMKeyTemplate())
	require.NoError(b, err)

	// Create encryptor
	encryptor, err := NewTinkEncryptor(kekHandle, nil)
	require.NoError(b, err)

	ctx := context.Background()
	data := make([]byte, 1024) // 1KB data
	aad := []byte("benchmark-key")

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := encryptor.Encrypt(ctx, data, aad)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// Benchmark decryption performance
func BenchmarkTinkEncryptor_Decrypt(b *testing.B) {
	// Create a KEK handle
	kekHandle, err := keyset.NewHandle(aead.AES256GCMKeyTemplate())
	require.NoError(b, err)

	// Create encryptor
	encryptor, err := NewTinkEncryptor(kekHandle, nil)
	require.NoError(b, err)

	ctx := context.Background()
	data := make([]byte, 1024) // 1KB data
	aad := []byte("benchmark-key")

	// Pre-encrypt data for benchmark
	result, err := encryptor.Encrypt(ctx, data, aad)
	require.NoError(b, err)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := encryptor.Decrypt(ctx, result.EncryptedData, result.EncryptedDEK, aad)
		if err != nil {
			b.Fatal(err)
		}
	}
}
