package dataencryption

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"testing"

	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAESCTRProvider_HMACStreamingIntegration(t *testing.T) {
	provider := NewAESCTRDataEncryptor()

	// Type assertion to HMACProviderStreaming
	hmacProvider, ok := provider.(encryption.HMACProviderStreaming)
	require.True(t, ok, "AESCTRDataEncryptor should implement HMACProviderStreaming interface")

	// Generate test DEK
	dek := make([]byte, 32)
	_, err := rand.Read(dek)
	require.NoError(t, err)

	testData := []byte("Test data for AES-CTR HMAC streaming integration")
	ctx := context.Background()

	t.Run("EncryptStreamWithHMAC", func(t *testing.T) {
		reader := bufio.NewReader(bytes.NewReader(testData))

		encryptedReader, getHMAC, err := hmacProvider.EncryptStreamWithHMAC(ctx, reader, dek, nil, nil)
		require.NoError(t, err)
		assert.NotNil(t, encryptedReader)
		assert.NotNil(t, getHMAC)

		// Read encrypted data
		var encryptedBuffer bytes.Buffer
		_, err = io.Copy(&encryptedBuffer, encryptedReader)
		require.NoError(t, err)
		ciphertext := encryptedBuffer.Bytes()

		// Get HMAC
		hmacSum := getHMAC()

		assert.NotEqual(t, testData, ciphertext, "Ciphertext should differ from plaintext")
		assert.Len(t, hmacSum, 32, "HMAC should be 32 bytes (SHA256)")
		assert.NotEmpty(t, hmacSum, "HMAC should not be empty")
	})
		assert.Contains(t, err.Error(), "AES-CTR HMAC decryption should be handled through the Encryption Manager")
	})

	t.Run("HMACConsistency", func(t *testing.T) {
		// Same data should produce same HMAC with same DEK
		_, hmac1, err := hmacProvider.EncryptWithHMAC(ctx, testData, dek, nil, nil)
		require.NoError(t, err)

		_, hmac2, err := hmacProvider.EncryptWithHMAC(ctx, testData, dek, nil, nil)
		require.NoError(t, err)

		assert.Equal(t, hmac1, hmac2, "Same data and DEK should produce same HMAC")
	})

	t.Run("DifferentDataProducesDifferentHMAC", func(t *testing.T) {
		data1 := []byte("First test data")
		data2 := []byte("Second test data")

		_, hmac1, err := hmacProvider.EncryptWithHMAC(ctx, data1, dek, nil, nil)
		require.NoError(t, err)

		_, hmac2, err := hmacProvider.EncryptWithHMAC(ctx, data2, dek, nil, nil)
		require.NoError(t, err)

		assert.NotEqual(t, hmac1, hmac2, "Different data should produce different HMAC")
	})

	t.Run("InvalidDEKSize", func(t *testing.T) {
		invalidDEK := make([]byte, 16) // Wrong size
		_, _, err := hmacProvider.EncryptWithHMAC(ctx, testData, invalidDEK, nil, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid DEK size")
	})
}

func TestAESCTRProvider_HMACProvider_Interface(t *testing.T) {
	provider := NewAESCTRDataEncryptor()

	// Verify that AESCTRDataEncryptor implements HMACProvider interface
	_, ok := provider.(encryption.HMACProvider)
	assert.True(t, ok, "AESCTRDataEncryptor should implement HMACProvider interface")
}

func TestAESCTRStreamingDataEncryptor_HMACIntegration(t *testing.T) {
	// Generate test DEK
	dek := make([]byte, 32)
	_, err := rand.Read(dek)
	require.NoError(t, err)

	t.Run("StreamingEncryptionWithHMAC", func(t *testing.T) {
		encryptor, err := NewAESCTRStreamingDataEncryptorWithHMAC(dek)
		require.NoError(t, err)
		assert.True(t, encryptor.hmacEnabled, "HMAC should be enabled")

		// Simulate multipart upload with multiple parts
		part1 := []byte("First part of the data")
		part2 := []byte("Second part of the data")
		part3 := []byte("Final part of the data")

		// Encrypt parts sequentially
		cipherPart1, err := encryptor.EncryptPart(part1)
		require.NoError(t, err)
		assert.NotEqual(t, part1, cipherPart1)

		cipherPart2, err := encryptor.EncryptPart(part2)
		require.NoError(t, err)
		assert.NotEqual(t, part2, cipherPart2)

		cipherPart3, err := encryptor.EncryptPart(part3)
		require.NoError(t, err)
		assert.NotEqual(t, part3, cipherPart3)

		// Get final HMAC
		finalHMAC := encryptor.GetStreamingHMAC()
		assert.Len(t, finalHMAC, 32, "HMAC should be 32 bytes")
		assert.NotEmpty(t, finalHMAC, "HMAC should not be empty")

		// Test decryption with HMAC verification
		decryptor, err := NewAESCTRStreamingDataDecryptorWithHMAC(dek, encryptor.GetIV(), 0)
		require.NoError(t, err)

		// Decrypt parts in order
		plainPart1, err := decryptor.DecryptPart(cipherPart1)
		require.NoError(t, err)
		assert.Equal(t, part1, plainPart1)

		plainPart2, err := decryptor.DecryptPart(cipherPart2)
		require.NoError(t, err)
		assert.Equal(t, part2, plainPart2)

		plainPart3, err := decryptor.DecryptPart(cipherPart3)
		require.NoError(t, err)
		assert.Equal(t, part3, plainPart3)

		// Verify final HMAC
		err = decryptor.VerifyStreamingHMAC(finalHMAC)
		assert.NoError(t, err, "HMAC verification should succeed")
	})

	t.Run("StreamingHMACVerificationFailure", func(t *testing.T) {
		encryptor, err := NewAESCTRStreamingDataEncryptorWithHMAC(dek)
		require.NoError(t, err)

		// Encrypt some data
		part := []byte("Test data for HMAC failure")
		cipherPart, err := encryptor.EncryptPart(part)
		require.NoError(t, err)

		// Get correct HMAC
		correctHMAC := encryptor.GetStreamingHMAC()

		// Create decryptor and decrypt
		decryptor, err := NewAESCTRStreamingDataDecryptorWithHMAC(dek, encryptor.GetIV(), 0)
		require.NoError(t, err)

		_, err = decryptor.DecryptPart(cipherPart)
		require.NoError(t, err)

		// Verify with wrong HMAC
		wrongHMAC := make([]byte, 32)
		copy(wrongHMAC, correctHMAC)
		wrongHMAC[0] ^= 1 // Flip one bit

		err = decryptor.VerifyStreamingHMAC(wrongHMAC)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "HMAC verification failed")
	})

	t.Run("StreamingWithoutHMAC", func(t *testing.T) {
		// Regular streaming encryptor without HMAC
		encryptor, err := NewAESCTRStreamingDataEncryptor(dek)
		require.NoError(t, err)
		assert.False(t, encryptor.hmacEnabled, "HMAC should not be enabled")

		// Encrypt some data
		part := []byte("Test data without HMAC")
		_, err = encryptor.EncryptPart(part)
		require.NoError(t, err)

		// Should return nil HMAC
		hmacSum := encryptor.GetStreamingHMAC()
		assert.Nil(t, hmacSum, "HMAC should be nil when not enabled")

		// Verification should fail
		err = encryptor.VerifyStreamingHMAC([]byte("dummy"))
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "HMAC verification not enabled")
	})
}
