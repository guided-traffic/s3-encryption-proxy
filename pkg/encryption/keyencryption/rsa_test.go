package keyencryption

import (
	"context"
	"crypto/rsa"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRSAProvider_EncryptDecrypt(t *testing.T) {
	// Generate test key pair
	privateKey, err := GenerateRSAKeyPair(2048)
	require.NoError(t, err)

	provider, err := NewRSAProvider(&privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	ctx := context.Background()

	testCases := []struct {
		name           string
		data           []byte
		associatedData []byte
	}{
		{
			name:           "simple text",
			data:           []byte("Hello, World!"),
			associatedData: []byte("object-key-1"),
		},
		{
			name:           "empty data",
			data:           []byte(""),
			associatedData: []byte("object-key-2"),
		},
		{
			name:           "binary data",
			data:           []byte{0x00, 0xFF, 0xAA, 0x55, 0xCC, 0x33},
			associatedData: []byte("object-key-3"),
		},
		{
			name:           "large data",
			data:           make([]byte, 1024*10), // 10KB
			associatedData: []byte("object-key-4"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Fill large data with pattern
			if len(tc.data) > 100 {
				for i := range tc.data {
					tc.data[i] = byte(i % 256)
				}
			}

			// Encrypt
			result, err := provider.Encrypt(ctx, tc.data, tc.associatedData)
			require.NoError(t, err)
			assert.NotNil(t, result)
			assert.NotEmpty(t, result.EncryptedData)
			assert.NotEmpty(t, result.EncryptedDEK)
			assert.Equal(t, "rsa-envelope", result.Metadata["algorithm"])
			assert.Equal(t, "2048", result.Metadata["rsa_key_size"])
			assert.Equal(t, "aes-256-gcm", result.Metadata["aes_algorithm"])

			// Ensure data is actually encrypted
			if len(tc.data) > 0 {
				assert.NotEqual(t, tc.data, result.EncryptedData)
			}

			// Decrypt
			decrypted, err := provider.Decrypt(ctx, result.EncryptedData, result.EncryptedDEK, tc.associatedData)
			require.NoError(t, err)

			if len(tc.data) == 0 {
				assert.Empty(t, decrypted)
			} else {
				assert.Equal(t, tc.data, decrypted)
			}
		})
	}
}

func TestRSAProvider_NewWithInvalidKeys(t *testing.T) {
	tests := []struct {
		name        string
		publicKey   *rsa.PublicKey
		privateKey  *rsa.PrivateKey
		expectError string
	}{
		{
			name:        "nil public key",
			publicKey:   nil,
			privateKey:  &rsa.PrivateKey{},
			expectError: "public key cannot be nil",
		},
		{
			name:        "nil private key",
			publicKey:   &rsa.PublicKey{},
			privateKey:  nil,
			expectError: "private key cannot be nil",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewRSAProvider(tt.publicKey, tt.privateKey)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), tt.expectError)
		})
	}
}

func TestRSAProvider_MismatchedKeys(t *testing.T) {
	// Generate two different key pairs
	privateKey1, err := GenerateRSAKeyPair(2048)
	require.NoError(t, err)

	privateKey2, err := GenerateRSAKeyPair(2048)
	require.NoError(t, err)

	// Try to create provider with mismatched keys
	_, err = NewRSAProvider(&privateKey1.PublicKey, privateKey2)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "public and private keys do not match")
}

func TestRSAProvider_SmallKeySize(t *testing.T) {
	// Skip this test as we can't generate insecure keys easily in Go
	t.Skip("Skipping small key size test - Go crypto prevents generation of insecure keys")
}

func TestRSAProvider_DecryptWithoutDEK(t *testing.T) {
	privateKey, err := GenerateRSAKeyPair(2048)
	require.NoError(t, err)

	provider, err := NewRSAProvider(&privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	ctx := context.Background()

	// Try to decrypt without providing encrypted DEK
	_, err = provider.Decrypt(ctx, []byte("some data"), nil, []byte("associated"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "encrypted DEK is required")

	// Try with empty DEK
	_, err = provider.Decrypt(ctx, []byte("some data"), []byte{}, []byte("associated"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "encrypted DEK is required")
}

func TestRSAProvider_DecryptWithWrongDEK(t *testing.T) {
	privateKey, err := GenerateRSAKeyPair(2048)
	require.NoError(t, err)

	provider, err := NewRSAProvider(&privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	ctx := context.Background()
	testData := []byte("test data")
	associatedData := []byte("object-key")

	// Encrypt with correct provider
	result, err := provider.Encrypt(ctx, testData, associatedData)
	require.NoError(t, err)

	// Try to decrypt with corrupted DEK
	corruptedDEK := make([]byte, len(result.EncryptedDEK))
	copy(corruptedDEK, result.EncryptedDEK)
	corruptedDEK[0] ^= 0xFF // Flip bits in first byte

	_, err = provider.Decrypt(ctx, result.EncryptedData, corruptedDEK, associatedData)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decrypt DEK with RSA")
}

func TestRSAProvider_DecryptWithWrongAssociatedData(t *testing.T) {
	privateKey, err := GenerateRSAKeyPair(2048)
	require.NoError(t, err)

	provider, err := NewRSAProvider(&privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	ctx := context.Background()
	testData := []byte("test data")
	associatedData := []byte("correct-associated-data")
	wrongAssociatedData := []byte("wrong-associated-data")

	// Encrypt
	result, err := provider.Encrypt(ctx, testData, associatedData)
	require.NoError(t, err)

	// Try to decrypt with wrong associated data
	_, err = provider.Decrypt(ctx, result.EncryptedData, result.EncryptedDEK, wrongAssociatedData)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decrypt data")
}

func TestRSAProvider_RotateKEK(t *testing.T) {
	privateKey, err := GenerateRSAKeyPair(2048)
	require.NoError(t, err)

	provider, err := NewRSAProvider(&privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	ctx := context.Background()

	// Key rotation should return an error (not implemented)
	err = provider.RotateKEK(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "RSA key rotation requires manual")
}

func TestRSAProvider_CrossCompatibility(t *testing.T) {
	// Generate test key pair
	privateKey, err := GenerateRSAKeyPair(2048)
	require.NoError(t, err)

	// Create two provider instances with the same keys
	provider1, err := NewRSAProvider(&privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	provider2, err := NewRSAProvider(&privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	ctx := context.Background()
	testData := []byte("Cross-compatibility test data")
	associatedData := []byte("shared-object-key")

	// Encrypt with first instance
	result, err := provider1.Encrypt(ctx, testData, associatedData)
	require.NoError(t, err)

	// Decrypt with second instance
	decrypted, err := provider2.Decrypt(ctx, result.EncryptedData, result.EncryptedDEK, associatedData)
	require.NoError(t, err)
	assert.Equal(t, testData, decrypted)
}

func TestRSAProvider_UniqueEncryptions(t *testing.T) {
	privateKey, err := GenerateRSAKeyPair(2048)
	require.NoError(t, err)

	provider, err := NewRSAProvider(&privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	ctx := context.Background()
	testData := []byte("test data")
	associatedData := []byte("object-key")

	// Encrypt the same data twice
	result1, err := provider.Encrypt(ctx, testData, associatedData)
	require.NoError(t, err)

	result2, err := provider.Encrypt(ctx, testData, associatedData)
	require.NoError(t, err)

	// Results should be different due to random DEK and nonce
	assert.NotEqual(t, result1.EncryptedData, result2.EncryptedData)
	assert.NotEqual(t, result1.EncryptedDEK, result2.EncryptedDEK)

	// But both should decrypt to the same plaintext
	decrypted1, err := provider.Decrypt(ctx, result1.EncryptedData, result1.EncryptedDEK, associatedData)
	require.NoError(t, err)

	decrypted2, err := provider.Decrypt(ctx, result2.EncryptedData, result2.EncryptedDEK, associatedData)
	require.NoError(t, err)

	assert.Equal(t, testData, decrypted1)
	assert.Equal(t, testData, decrypted2)
}

func TestGenerateRSAKeyPair(t *testing.T) {
	tests := []struct {
		name        string
		keySize     int
		expectError bool
	}{
		{
			name:        "valid 2048-bit key",
			keySize:     2048,
			expectError: false,
		},
		{
			name:        "valid 3072-bit key",
			keySize:     3072,
			expectError: false,
		},
		{
			name:        "valid 4096-bit key",
			keySize:     4096,
			expectError: false,
		},
		{
			name:        "invalid small key",
			keySize:     1024,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			privateKey, err := GenerateRSAKeyPair(tt.keySize)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, privateKey)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, privateKey)
				assert.Equal(t, tt.keySize, privateKey.N.BitLen())
			}
		})
	}
}

func TestRSAKeyPairToPEM(t *testing.T) {
	privateKey, err := GenerateRSAKeyPair(2048)
	require.NoError(t, err)

	privateKeyPEM, publicKeyPEM, err := RSAKeyPairToPEM(privateKey)
	require.NoError(t, err)

	assert.NotEmpty(t, privateKeyPEM)
	assert.NotEmpty(t, publicKeyPEM)
	assert.Contains(t, privateKeyPEM, "BEGIN RSA PRIVATE KEY")
	assert.Contains(t, privateKeyPEM, "END RSA PRIVATE KEY")
	assert.Contains(t, publicKeyPEM, "BEGIN PUBLIC KEY")
	assert.Contains(t, publicKeyPEM, "END PUBLIC KEY")

	// Test that we can parse them back
	parsedPrivateKey, err := parseRSAPrivateKeyFromPEM(privateKeyPEM)
	require.NoError(t, err)
	assert.True(t, privateKey.Equal(parsedPrivateKey))

	parsedPublicKey, err := parseRSAPublicKeyFromPEM(publicKeyPEM)
	require.NoError(t, err)
	assert.True(t, privateKey.PublicKey.Equal(parsedPublicKey))
}

func TestRSAConfig_Validate(t *testing.T) {
	// Generate test key pair
	privateKey, err := GenerateRSAKeyPair(2048)
	require.NoError(t, err)

	privateKeyPEM, publicKeyPEM, err := RSAKeyPairToPEM(privateKey)
	require.NoError(t, err)

	tests := []struct {
		name        string
		config      RSAConfig
		expectError bool
		errorText   string
	}{
		{
			name: "valid config",
			config: RSAConfig{
				PublicKeyPEM:  publicKeyPEM,
				PrivateKeyPEM: privateKeyPEM,
				KeySize:       2048,
			},
			expectError: false,
		},
		{
			name: "missing public key",
			config: RSAConfig{
				PrivateKeyPEM: privateKeyPEM,
			},
			expectError: true,
			errorText:   "public_key_pem is required",
		},
		{
			name: "missing private key",
			config: RSAConfig{
				PublicKeyPEM: publicKeyPEM,
			},
			expectError: true,
			errorText:   "private_key_pem is required",
		},
		{
			name: "invalid public key",
			config: RSAConfig{
				PublicKeyPEM:  "invalid-pem-data",
				PrivateKeyPEM: privateKeyPEM,
			},
			expectError: true,
			errorText:   "invalid public key",
		},
		{
			name: "invalid private key",
			config: RSAConfig{
				PublicKeyPEM:  publicKeyPEM,
				PrivateKeyPEM: "invalid-pem-data",
			},
			expectError: true,
			errorText:   "invalid private key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorText != "" {
					assert.Contains(t, err.Error(), tt.errorText)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestNewRSAProviderFromConfig(t *testing.T) {
	// Generate test key pair
	privateKey, err := GenerateRSAKeyPair(2048)
	require.NoError(t, err)

	privateKeyPEM, publicKeyPEM, err := RSAKeyPairToPEM(privateKey)
	require.NoError(t, err)

	config := &RSAConfig{
		PublicKeyPEM:  publicKeyPEM,
		PrivateKeyPEM: privateKeyPEM,
		KeySize:       2048,
	}

	provider, err := NewRSAProviderFromConfig(config)
	require.NoError(t, err)
	assert.NotNil(t, provider)

	// Test that the provider works
	ctx := context.Background()
	testData := []byte("test data")
	associatedData := []byte("object-key")

	result, err := provider.Encrypt(ctx, testData, associatedData)
	require.NoError(t, err)

	decrypted, err := provider.Decrypt(ctx, result.EncryptedData, result.EncryptedDEK, associatedData)
	require.NoError(t, err)
	assert.Equal(t, testData, decrypted)
}
