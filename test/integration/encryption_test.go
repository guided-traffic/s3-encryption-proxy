package integration

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption/factory"
	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption/keyencryption"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEncryptionManager_AESGCMIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test")
	}

	// Create factory
	factoryInstance := factory.NewFactory()

	// Generate a test key and create AES key encryptor
	key := make([]byte, 32) // AES-256 key
	_, err := rand.Read(key)
	require.NoError(t, err)

	aesKeyEncryptor, err := keyencryption.NewAESKeyEncryptor(key)
	require.NoError(t, err)

	// Register the key encryptor with the factory
	factoryInstance.RegisterKeyEncryptor(aesKeyEncryptor)

	// Create envelope encryptor for whole files (uses AES-GCM)
	envelopeEncryptor, err := factoryInstance.CreateEnvelopeEncryptor(factory.ContentTypeWhole, aesKeyEncryptor.Fingerprint())
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

			// Encrypt using the envelope encryptor
			encryptedData, encryptedDEK, metadata, err := envelopeEncryptor.EncryptData(ctx, tc.data, tc.associatedData)
			require.NoError(t, err)
			assert.NotEmpty(t, encryptedData)
			assert.NotEmpty(t, encryptedDEK)
			assert.NotNil(t, metadata)
			assert.Equal(t, "envelope-aes-256-gcm", metadata["algorithm"])

			// Ensure data is actually encrypted
			if len(tc.data) > 0 {
				assert.NotEqual(t, tc.data, encryptedData)
			}

			// Decrypt using the envelope encryptor
			decryptedData, err := envelopeEncryptor.DecryptData(ctx, encryptedData, encryptedDEK, tc.associatedData)
			require.NoError(t, err)

			// Handle empty data case (nil vs empty slice)
			if len(tc.data) == 0 {
				assert.Empty(t, decryptedData)
			} else {
				assert.Equal(t, tc.data, decryptedData)
			}
		})
	}
}

func TestEncryptionManager_RSAEnvelopeIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test")
	}

	// Generate test RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Create factory
	factoryInstance := factory.NewFactory()

	// Create RSA key encryptor
	rsaKeyEncryptor, err := keyencryption.NewRSAProvider(&privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	// Register the key encryptor with the factory
	factoryInstance.RegisterKeyEncryptor(rsaKeyEncryptor)

	// Create envelope encryptor for whole files (uses AES-GCM with RSA envelope)
	envelopeEncryptor, err := factoryInstance.CreateEnvelopeEncryptor(factory.ContentTypeWhole, rsaKeyEncryptor.Fingerprint())
	require.NoError(t, err)

	testCases := []struct {
		name           string
		data           []byte
		associatedData []byte
	}{
		{
			name:           "small text",
			data:           []byte("Hello, RSA Envelope World!"),
			associatedData: []byte("rsa-object-key-1"),
		},
		{
			name:           "empty data",
			data:           []byte(""),
			associatedData: []byte("rsa-object-key-2"),
		},
		{
			name:           "large data",
			data:           make([]byte, 1024*100), // 100KB
			associatedData: []byte("rsa-object-key-3"),
		},
		{
			name:           "binary data",
			data:           []byte{0x00, 0xFF, 0xAA, 0x55, 0xCC, 0x33, 0x99, 0x66},
			associatedData: []byte("rsa-object-key-4"),
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
			encryptedData, encryptedDEK, metadata, err := envelopeEncryptor.EncryptData(context.Background(), tc.data, tc.associatedData)
			require.NoError(t, err)
			assert.NotEmpty(t, encryptedData)
			assert.NotEmpty(t, encryptedDEK)
			assert.NotEmpty(t, metadata)

			// Decrypt
			decryptedData, err := envelopeEncryptor.DecryptData(context.Background(), encryptedData, encryptedDEK, tc.associatedData)
			require.NoError(t, err)

			// Handle empty data case (nil vs empty slice)
			if len(tc.data) == 0 {
				assert.Empty(t, decryptedData)
			} else {
				assert.Equal(t, tc.data, decryptedData)
			}
		})
	}
}

func TestEncryptionManager_CrossCompatibility(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test")
	}

	// Test that different instances with the same key can encrypt/decrypt
	// Generate AES key using crypto/rand
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)

	// Create factory
	factoryInstance := factory.NewFactory()

	// Create AES key encryptor
	aesKeyEncryptor, err := keyencryption.NewAESKeyEncryptor(key)
	require.NoError(t, err)

	// Register the key encryptor with the factory
	factoryInstance.RegisterKeyEncryptor(aesKeyEncryptor)

	// Create two envelope encryptors with the same key
	envelopeEncryptor1, err := factoryInstance.CreateEnvelopeEncryptor(factory.ContentTypeWhole, aesKeyEncryptor.Fingerprint())
	require.NoError(t, err)

	envelopeEncryptor2, err := factoryInstance.CreateEnvelopeEncryptor(factory.ContentTypeWhole, aesKeyEncryptor.Fingerprint())
	require.NoError(t, err)

	testData := []byte("Cross-compatibility test data")
	associatedData := []byte("shared-object-key")

	// Encrypt with first instance
	encryptedData1, encryptedDEK1, _, err := envelopeEncryptor1.EncryptData(context.Background(), testData, associatedData)
	require.NoError(t, err)

	// Decrypt with second instance
	decryptedData1, err := envelopeEncryptor2.DecryptData(context.Background(), encryptedData1, encryptedDEK1, associatedData)
	require.NoError(t, err)
	assert.Equal(t, testData, decryptedData1)

	// Encrypt with second instance
	encryptedData2, encryptedDEK2, _, err := envelopeEncryptor2.EncryptData(context.Background(), testData, associatedData)
	require.NoError(t, err)

	// Decrypt with first instance
	decryptedData2, err := envelopeEncryptor1.DecryptData(context.Background(), encryptedData2, encryptedDEK2, associatedData)
	require.NoError(t, err)
	assert.Equal(t, testData, decryptedData2)
}

func TestEncryptionManager_SecurityProperties(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test")
	}

	// Generate AES key using crypto/rand
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)

	// Create factory
	factoryInstance := factory.NewFactory()

	// Create AES key encryptor
	aesKeyEncryptor, err := keyencryption.NewAESKeyEncryptor(key)
	require.NoError(t, err)

	// Register the key encryptor with the factory
	factoryInstance.RegisterKeyEncryptor(aesKeyEncryptor)

	// Create envelope encryptor for whole files (uses AES-GCM)
	envelopeEncryptor, err := factoryInstance.CreateEnvelopeEncryptor(factory.ContentTypeWhole, aesKeyEncryptor.Fingerprint())
	require.NoError(t, err)

	testData := []byte("Sensitive data that needs protection")
	associatedData := []byte("test-object-key")

	// Test 1: Same plaintext should produce different ciphertexts (due to random nonces)
	encryptedData1, encryptedDEK1, _, err := envelopeEncryptor.EncryptData(context.Background(), testData, associatedData)
	require.NoError(t, err)

	encryptedData2, _, _, err := envelopeEncryptor.EncryptData(context.Background(), testData, associatedData)
	require.NoError(t, err)

	assert.NotEqual(t, encryptedData1, encryptedData2, "Same plaintext should produce different ciphertexts")

	// Test 2: Authentication should fail with modified ciphertext
	modifiedCiphertext := make([]byte, len(encryptedData1))
	copy(modifiedCiphertext, encryptedData1)

	// Flip a bit in the ciphertext (not in the nonce)
	if len(modifiedCiphertext) > 16 { // Skip nonce (first 12 bytes) + some margin
		modifiedCiphertext[20] ^= 0x01
	}

	_, err = envelopeEncryptor.DecryptData(context.Background(), modifiedCiphertext, encryptedDEK1, associatedData)
	assert.Error(t, err, "Decryption should fail with modified ciphertext")

	// Test with valid data to ensure decryption still works
	decryptedData, err := envelopeEncryptor.DecryptData(context.Background(), encryptedData1, encryptedDEK1, associatedData)
	require.NoError(t, err)
	assert.Equal(t, testData, decryptedData)
}
