package envelope

import (
	"context"
	"encoding/base64"
	"testing"

	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption/dataencryption"
	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption/keyencryption"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEnvelopeEncryptor_HMACIntegration(t *testing.T) {
	// Create test encryptors
	aesKey := []byte("abcdefghijklmnopqrstuvwxyz123456") // 32 bytes
	keyEncryptor, err := keyencryption.NewAESKeyEncryptor(aesKey)
	require.NoError(t, err)

	dataEncryptor := dataencryption.NewAESGCMDataEncryptor()

	// Create envelope encryptor with prefix
	envelopeEncryptor := NewEnvelopeEncryptorWithPrefix(keyEncryptor, dataEncryptor, "s3ep-")

	ctx := context.Background()
	testData := []byte("Hello, World! This is a test message for envelope encryption with HMAC integrity verification.")
	associatedData := []byte("test-object-key")

	t.Run("EncryptDataWithHMAC", func(t *testing.T) {
		encryptedData, encryptedDEK, metadata, err := envelopeEncryptor.EncryptDataWithHMAC(ctx, testData, associatedData)
		require.NoError(t, err)
		assert.NotEmpty(t, encryptedData)
		assert.NotEmpty(t, encryptedDEK)
		assert.NotEmpty(t, metadata)

		// Verify that HMAC is included in metadata
		hmacBase64, exists := metadata["s3ep-hmac"]
		assert.True(t, exists, "HMAC should be present in metadata")
		assert.NotEmpty(t, hmacBase64, "HMAC should not be empty")

		// Verify HMAC can be decoded
		hmacBytes, err := base64.StdEncoding.DecodeString(hmacBase64)
		require.NoError(t, err)
		assert.Len(t, hmacBytes, 32, "HMAC should be 32 bytes (SHA256)")

		// Verify other metadata fields are present
		assert.Equal(t, "aes-256-gcm", metadata["s3ep-dek-algorithm"])
		assert.Equal(t, keyEncryptor.Fingerprint(), metadata["s3ep-kek-fingerprint"])
		assert.NotEmpty(t, metadata["s3ep-encrypted-dek"])
		assert.NotEmpty(t, metadata["s3ep-kek-algorithm"])

		t.Logf("✅ HMAC metadata: %s", hmacBase64[:16]+"...")
	})

	t.Run("DecryptDataWithHMAC", func(t *testing.T) {
		// First encrypt with HMAC
		encryptedData, encryptedDEK, metadata, err := envelopeEncryptor.EncryptDataWithHMAC(ctx, testData, associatedData)
		require.NoError(t, err)

		// Extract HMAC from metadata
		hmacBase64, exists := metadata["s3ep-hmac"]
		require.True(t, exists, "HMAC should be present in metadata")
		expectedHMAC, err := base64.StdEncoding.DecodeString(hmacBase64)
		require.NoError(t, err)

		// Decrypt with HMAC verification
		decryptedData, err := envelopeEncryptor.DecryptDataWithHMAC(ctx, encryptedData, encryptedDEK, expectedHMAC, associatedData)
		require.NoError(t, err)
		assert.Equal(t, testData, decryptedData, "Decrypted data should match original")

		t.Logf("✅ Successfully decrypted with HMAC verification")
	})

	t.Run("HMACMismatch", func(t *testing.T) {
		// First encrypt with HMAC
		encryptedData, encryptedDEK, _, err := envelopeEncryptor.EncryptDataWithHMAC(ctx, testData, associatedData)
		require.NoError(t, err)

		// Create wrong HMAC
		wrongHMAC := make([]byte, 32)
		copy(wrongHMAC, []byte("wrong-hmac-value-32-bytes-long!!"))

		// Decrypt should fail with wrong HMAC
		_, err = envelopeEncryptor.DecryptDataWithHMAC(ctx, encryptedData, encryptedDEK, wrongHMAC, associatedData)
		assert.Error(t, err, "Should fail with wrong HMAC")
		assert.Contains(t, err.Error(), "HMAC verification failed", "Error should mention HMAC verification failure")

		t.Logf("✅ Correctly rejected wrong HMAC")
	})

	t.Run("BackwardCompatibility", func(t *testing.T) {
		// Encrypt with standard method (no HMAC)
		encryptedData, encryptedDEK, metadata, err := envelopeEncryptor.EncryptData(ctx, testData, associatedData)
		require.NoError(t, err)

		// Verify no HMAC in metadata
		_, exists := metadata["s3ep-hmac"]
		assert.False(t, exists, "Standard encryption should not include HMAC")

		// Decrypt with HMAC method but no expected HMAC (should fall back to standard)
		decryptedData, err := envelopeEncryptor.DecryptDataWithHMAC(ctx, encryptedData, encryptedDEK, nil, associatedData)
		require.NoError(t, err)
		assert.Equal(t, testData, decryptedData, "Backward compatibility should work")

		// Decrypt with standard method
		decryptedData2, err := envelopeEncryptor.DecryptData(ctx, encryptedData, encryptedDEK, associatedData)
		require.NoError(t, err)
		assert.Equal(t, testData, decryptedData2, "Standard decryption should still work")

		t.Logf("✅ Backward compatibility verified")
	})

	t.Run("RoundTripWithHMAC", func(t *testing.T) {
		// Full round-trip with HMAC
		encryptedData, encryptedDEK, metadata, err := envelopeEncryptor.EncryptDataWithHMAC(ctx, testData, associatedData)
		require.NoError(t, err)

		// Extract HMAC from metadata (simulating real-world usage)
		hmacBase64, exists := metadata["s3ep-hmac"]
		require.True(t, exists, "HMAC should be present")
		expectedHMAC, err := base64.StdEncoding.DecodeString(hmacBase64)
		require.NoError(t, err)

		// Decrypt
		decryptedData, err := envelopeEncryptor.DecryptDataWithHMAC(ctx, encryptedData, encryptedDEK, expectedHMAC, associatedData)
		require.NoError(t, err)
		assert.Equal(t, testData, decryptedData, "Full round-trip should work")

		t.Logf("✅ Full HMAC round-trip successful")
	})

	t.Run("DifferentDataProducesDifferentHMAC", func(t *testing.T) {
		testData1 := []byte("First test message")
		testData2 := []byte("Second test message")

		// Encrypt both messages
		_, _, metadata1, err := envelopeEncryptor.EncryptDataWithHMAC(ctx, testData1, associatedData)
		require.NoError(t, err)

		_, _, metadata2, err := envelopeEncryptor.EncryptDataWithHMAC(ctx, testData2, associatedData)
		require.NoError(t, err)

		// HMACs should be different
		hmac1 := metadata1["s3ep-hmac"]
		hmac2 := metadata2["s3ep-hmac"]
		assert.NotEqual(t, hmac1, hmac2, "Different data should produce different HMACs")

		t.Logf("✅ Different HMACs for different data: %s vs %s", hmac1[:8]+"...", hmac2[:8]+"...")
	})
}

func TestEnvelopeEncryptor_HMACWithNonHMACProvider(t *testing.T) {
	// Create test with AES-CTR (which doesn't support HMAC in this test)
	aesKey := []byte("abcdefghijklmnopqrstuvwxyz123456") // 32 bytes
	keyEncryptor, err := keyencryption.NewAESKeyEncryptor(aesKey)
	require.NoError(t, err)

	dataEncryptor := dataencryption.NewAESCTRDataEncryptor()

	// Create envelope encryptor
	envelopeEncryptor := NewEnvelopeEncryptorWithPrefix(keyEncryptor, dataEncryptor, "s3ep-")

	ctx := context.Background()
	testData := []byte("Test data for non-HMAC provider")
	associatedData := []byte("test-object-key")

	t.Run("EncryptDataWithHMAC_FallsBackToStandard", func(t *testing.T) {
		encryptedData, encryptedDEK, metadata, err := envelopeEncryptor.EncryptDataWithHMAC(ctx, testData, associatedData)
		require.NoError(t, err)
		assert.NotEmpty(t, encryptedData)
		assert.NotEmpty(t, encryptedDEK)
		assert.NotEmpty(t, metadata)

		// Verify that HMAC IS included because AES-CTR now supports it
		_, exists := metadata["s3ep-hmac"]
		assert.True(t, exists, "HMAC should be present for AES-CTR provider since it now implements HMACProvider")

		// Should still have other metadata
		assert.Equal(t, "aes-256-ctr", metadata["s3ep-dek-algorithm"])

		t.Logf("✅ AES-CTR provider correctly includes HMAC")
	})

	t.Run("DecryptDataWithHMAC_FallsBackToStandard", func(t *testing.T) {
		// This test can't work with AES-CTR because it requires special handling via Manager
		// But the test verifies that the fallback mechanism works conceptually
		// For AES-CTR, decryption must go through the encryption manager with IV metadata

		// Instead, test that the fallback is triggered correctly by checking error type
		encryptedData := []byte("dummy-encrypted-data")
		encryptedDEK := []byte("dummy-encrypted-dek")

		// This should attempt standard decryption and fail appropriately for AES-CTR
		_, err := envelopeEncryptor.DecryptDataWithHMAC(ctx, encryptedData, encryptedDEK, nil, associatedData)
		assert.Error(t, err, "Should fail because AES-CTR requires special handling")
		assert.Contains(t, err.Error(), "AES-CTR decryption should be handled through the Encryption Manager", "Should get expected AES-CTR error")

		t.Logf("✅ Non-HMAC provider correctly attempted fallback (AES-CTR requires Manager)")
	})
}
