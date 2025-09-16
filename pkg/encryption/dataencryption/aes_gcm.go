package dataencryption

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"

	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption"
)

// AESGCMDataEncryptor implements encryption.DataEncryptor using AES-256-GCM
// This handles ONLY data encryption/decryption with provided DEKs
type AESGCMDataEncryptor struct{}

// NewAESGCMDataEncryptor creates a new AES-GCM data encryptor
func NewAESGCMDataEncryptor() encryption.DataEncryptor {
	return &AESGCMDataEncryptor{}
}

// Encrypt encrypts data using AES-256-GCM with the provided DEK
func (e *AESGCMDataEncryptor) Encrypt(_ context.Context, data []byte, dek []byte, associatedData []byte) ([]byte, error) {
	if len(dek) != 32 {
		return nil, fmt.Errorf("invalid DEK size: expected 32 bytes, got %d", len(dek))
	}

	// Create AES cipher with DEK
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Generate random nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt data
	ciphertext := gcm.Seal(nil, nonce, data, associatedData)

	// Prepend nonce to ciphertext
	result := make([]byte, len(nonce)+len(ciphertext))
	copy(result[:len(nonce)], nonce)
	copy(result[len(nonce):], ciphertext)

	return result, nil
}

// Decrypt decrypts data using AES-256-GCM with the provided DEK
func (e *AESGCMDataEncryptor) Decrypt(_ context.Context, encryptedData []byte, dek []byte, associatedData []byte) ([]byte, error) {
	if len(dek) != 32 {
		return nil, fmt.Errorf("invalid DEK size: expected 32 bytes, got %d", len(dek))
	}

	// Create AES cipher with DEK
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(encryptedData) < nonceSize {
		return nil, fmt.Errorf("encrypted data too short: expected at least %d bytes, got %d", nonceSize, len(encryptedData))
	}

	// Extract nonce and ciphertext
	nonce := encryptedData[:nonceSize]
	ciphertext := encryptedData[nonceSize:]

	// Decrypt data
	plaintext, err := gcm.Open(nil, nonce, ciphertext, associatedData)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data: %w", err)
	}

	return plaintext, nil
}

// GenerateDEK generates a new 256-bit AES key
func (e *AESGCMDataEncryptor) GenerateDEK(_ context.Context) ([]byte, error) {
	dek := make([]byte, 32) // 256-bit key
	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		return nil, fmt.Errorf("failed to generate DEK: %w", err)
	}
	return dek, nil
}

// Algorithm returns the algorithm identifier
func (e *AESGCMDataEncryptor) Algorithm() string {
	return "aes-256-gcm"
}

// EncryptWithHMAC encrypts data and calculates HMAC in parallel for integrity verification
// This implements the HMACProvider interface for optional integrity verification
func (e *AESGCMDataEncryptor) EncryptWithHMAC(ctx context.Context, data []byte, dek []byte, hmacKey []byte, associatedData []byte) ([]byte, []byte, error) {
	if len(dek) != 32 {
		return nil, nil, fmt.Errorf("invalid DEK size: expected 32 bytes, got %d", len(dek))
	}

	if len(hmacKey) != 32 {
		return nil, nil, fmt.Errorf("invalid HMAC key size: expected 32 bytes, got %d", len(hmacKey))
	}

	// Step 1: Calculate HMAC over the original (unencrypted) data
	h := hmac.New(sha256.New, hmacKey)
	h.Write(data)
	calculatedHMAC := h.Sum(nil)

	// Step 2: Encrypt data using standard AES-GCM process
	encryptedData, err := e.Encrypt(ctx, data, dek, associatedData)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encrypt data: %w", err)
	}

	return encryptedData, calculatedHMAC, nil
}

// DecryptWithHMAC decrypts data and verifies HMAC for integrity verification
// This implements the HMACProvider interface for optional integrity verification
func (e *AESGCMDataEncryptor) DecryptWithHMAC(ctx context.Context, encryptedData []byte, dek []byte, hmacKey []byte, expectedHMAC []byte, associatedData []byte) ([]byte, error) {
	if len(dek) != 32 {
		return nil, fmt.Errorf("invalid DEK size: expected 32 bytes, got %d", len(dek))
	}

	if len(hmacKey) != 32 {
		return nil, fmt.Errorf("invalid HMAC key size: expected 32 bytes, got %d", len(hmacKey))
	}

	// Step 1: Decrypt data using standard AES-GCM process
	decryptedData, err := e.Decrypt(ctx, encryptedData, dek, associatedData)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data: %w", err)
	}

	// Step 2: Calculate HMAC over the decrypted data
	h := hmac.New(sha256.New, hmacKey)
	h.Write(decryptedData)
	calculatedHMAC := h.Sum(nil)

	// Step 3: Verify HMAC matches expected value
	if !hmac.Equal(calculatedHMAC, expectedHMAC) {
		return nil, fmt.Errorf("HMAC verification failed: integrity check failed")
	}

	return decryptedData, nil
}
