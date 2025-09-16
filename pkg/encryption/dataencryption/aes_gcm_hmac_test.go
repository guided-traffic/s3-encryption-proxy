package dataencryption

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"testing"

	"github.com/guided-traffic/s3-encryption-proxy/internal/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAESGCMProvider_HMACIntegration(t *testing.T) {
	provider := NewAESGCMDataEncryptor()
	ctx := context.Background()
	testData := []byte("Hello, World! This is a test message for AES-256-GCM encryption with HMAC integrity verification.")
	associatedData := []byte("test-object-key")

	// Check that provider implements HMACProvider interface
	hmacProvider, ok := provider.(interface {
		EncryptWithHMAC(ctx context.Context, data []byte, dek []byte, hmacKey []byte, associatedData []byte) (encryptedData []byte, hmac []byte, err error)
		DecryptWithHMAC(ctx context.Context, encryptedData []byte, dek []byte, hmacKey []byte, expectedHMAC []byte, associatedData []byte) (data []byte, err error)
	})
	require.True(t, ok, "AES-GCM provider should implement HMACProvider interface")

	// Generate a DEK for this test
	dek, err := provider.GenerateDEK(ctx)
	require.NoError(t, err)
	require.Len(t, dek, 32, "DEK should be 32 bytes")

	// Derive HMAC key from DEK
	hmacKey, err := crypto.DeriveIntegrityKey(dek)
	require.NoError(t, err)
	require.Len(t, hmacKey, 32, "HMAC key should be 32 bytes")

	t.Run("EncryptWithHMAC", func(t *testing.T) {
		encryptedData, calculatedHMAC, err := hmacProvider.EncryptWithHMAC(ctx, testData, dek, hmacKey, associatedData)
		require.NoError(t, err)
		assert.NotEmpty(t, encryptedData)
		assert.NotEmpty(t, calculatedHMAC)
		assert.Len(t, calculatedHMAC, 32, "HMAC should be 32 bytes (SHA256)")

		// Ensure encrypted data is different from original
		assert.NotEqual(t, testData, encryptedData)

		// Verify that HMAC is calculated over original data
		expectedHMAC := hmac.New(sha256.New, hmacKey)
		expectedHMAC.Write(testData)
		expectedResult := expectedHMAC.Sum(nil)
		assert.Equal(t, expectedResult, calculatedHMAC, "HMAC should be calculated over original data")
	})

	t.Run("DecryptWithHMAC", func(t *testing.T) {
		// First encrypt data with HMAC
		encryptedData, calculatedHMAC, err := hmacProvider.EncryptWithHMAC(ctx, testData, dek, hmacKey, associatedData)
		require.NoError(t, err)

		// Then decrypt and verify HMAC
		decryptedData, err := hmacProvider.DecryptWithHMAC(ctx, encryptedData, dek, hmacKey, calculatedHMAC, associatedData)
		require.NoError(t, err)
		assert.Equal(t, testData, decryptedData, "Decrypted data should match original")
	})

	t.Run("HMACMismatch", func(t *testing.T) {
		// First encrypt data with HMAC
		encryptedData, _, err := hmacProvider.EncryptWithHMAC(ctx, testData, dek, hmacKey, associatedData)
		require.NoError(t, err)

		// Create wrong HMAC
		wrongHMAC := make([]byte, 32)
		copy(wrongHMAC, []byte("wrong-hmac-value-32-bytes-long!!"))

		// Decrypt should fail with wrong HMAC
		_, err = hmacProvider.DecryptWithHMAC(ctx, encryptedData, dek, hmacKey, wrongHMAC, associatedData)
		assert.Error(t, err, "Should fail with wrong HMAC")
		assert.Contains(t, err.Error(), "HMAC verification failed", "Error should mention HMAC verification failure")
	})

	t.Run("InvalidDEKSize", func(t *testing.T) {
		shortDEK := []byte("short")
		_, _, err := hmacProvider.EncryptWithHMAC(ctx, testData, shortDEK, hmacKey, associatedData)
		assert.Error(t, err, "Should fail with invalid DEK size")
		assert.Contains(t, err.Error(), "invalid DEK size", "Error should mention DEK size")
	})

	t.Run("InvalidHMACKeySize", func(t *testing.T) {
		shortHMACKey := []byte("short")
		_, _, err := hmacProvider.EncryptWithHMAC(ctx, testData, dek, shortHMACKey, associatedData)
		assert.Error(t, err, "Should fail with invalid HMAC key size")
		assert.Contains(t, err.Error(), "invalid HMAC key size", "Error should mention HMAC key size")
	})

	t.Run("RoundTripCompatibility", func(t *testing.T) {
		// Encrypt with standard method
		standardEncrypted, err := provider.Encrypt(ctx, testData, dek, associatedData)
		require.NoError(t, err)

		// Decrypt with standard method
		standardDecrypted, err := provider.Decrypt(ctx, standardEncrypted, dek, associatedData)
		require.NoError(t, err)
		assert.Equal(t, testData, standardDecrypted, "Standard round-trip should work")

		// Encrypt with HMAC method
		hmacEncrypted, calculatedHMAC, err := hmacProvider.EncryptWithHMAC(ctx, testData, dek, hmacKey, associatedData)
		require.NoError(t, err)

		// Decrypt with HMAC method
		hmacDecrypted, err := hmacProvider.DecryptWithHMAC(ctx, hmacEncrypted, dek, hmacKey, calculatedHMAC, associatedData)
		require.NoError(t, err)
		assert.Equal(t, testData, hmacDecrypted, "HMAC round-trip should work")

		// Note: Cross-compatibility (HMAC-encrypted -> standard-decrypted) should work
		// because EncryptWithHMAC uses the same encryption as Encrypt
		crossDecrypted, err := provider.Decrypt(ctx, hmacEncrypted, dek, associatedData)
		require.NoError(t, err)
		assert.Equal(t, testData, crossDecrypted, "HMAC-encrypted data should be standard-decryptable")
	})
}

func TestAESGCMProvider_HMACProvider_Interface(t *testing.T) {
	provider := NewAESGCMDataEncryptor()

	// Test that provider implements HMACProvider interface
	_, implementsHMACProvider := provider.(interface {
		EncryptWithHMAC(ctx context.Context, data []byte, dek []byte, hmacKey []byte, associatedData []byte) (encryptedData []byte, hmac []byte, err error)
		DecryptWithHMAC(ctx context.Context, encryptedData []byte, dek []byte, hmacKey []byte, expectedHMAC []byte, associatedData []byte) (data []byte, err error)
	})

	assert.True(t, implementsHMACProvider, "AES-GCM provider should implement HMACProvider interface")
}
