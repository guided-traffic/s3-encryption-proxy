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

	"github.com/guided-traffic/s3-encryption-proxy/internal/crypto"
	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption"
)

// AESCTRDataEncryptor implements encryption.DataEncryptor using AES-256-CTR
// This handles ONLY data encryption/decryption with provided DEKs
// It also implements IVProvider to provide the IV for metadata storage
// and HMACProvider for integrity verification
type AESCTRDataEncryptor struct {
	lastIV []byte // Store the last used IV for metadata
}

// NewAESCTRDataEncryptor creates a new AES-CTR data encryptor
func NewAESCTRDataEncryptor() encryption.DataEncryptor {
	return &AESCTRDataEncryptor{
		lastIV: nil,
	}
}

// Encrypt encrypts data using AES-256-CTR with the provided DEK
func (e *AESCTRDataEncryptor) Encrypt(_ context.Context, data []byte, dek []byte, _ []byte) ([]byte, error) {
	if len(dek) != 32 {
		return nil, fmt.Errorf("invalid DEK size: expected 32 bytes, got %d", len(dek))
	}

	// Create AES cipher with DEK
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	// Generate random IV (16 bytes for AES)
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, fmt.Errorf("failed to generate IV: %w", err)
	}

	// Store the IV for metadata (IVProvider interface)
	e.lastIV = append([]byte(nil), iv...) // Copy the IV

	// Create CTR mode cipher
	// #nosec G407 - IV is randomly generated, not hardcoded
	stream := cipher.NewCTR(block, iv)

	// Encrypt the data
	ciphertext := make([]byte, len(data))
	stream.XORKeyStream(ciphertext, data)

	// Return ONLY the ciphertext - IV will be stored in metadata via IVProvider interface
	return ciphertext, nil
}

// Decrypt decrypts data using AES-256-CTR with the provided DEK
// NOTE: This method should not be used directly for AES-CTR decryption anymore
// The Encryption Manager handles AES-CTR decryption with IV from metadata
func (e *AESCTRDataEncryptor) Decrypt(_ context.Context, _ []byte, _ []byte, _ []byte) ([]byte, error) {
	return nil, fmt.Errorf("AES-CTR decryption should be handled through the Encryption Manager with IV from metadata")
}

// GenerateDEK generates a new 256-bit AES key
func (e *AESCTRDataEncryptor) GenerateDEK(_ context.Context) ([]byte, error) {
	dek := make([]byte, 32) // 256-bit key
	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		return nil, fmt.Errorf("failed to generate DEK: %w", err)
	}
	return dek, nil
}

// Algorithm returns the algorithm identifier
func (e *AESCTRDataEncryptor) Algorithm() string {
	return "aes-256-ctr"
}

// GetLastIV implements the IVProvider interface
// Returns the IV used in the last encryption operation for metadata storage
func (e *AESCTRDataEncryptor) GetLastIV() []byte {
	if e.lastIV == nil {
		return nil
	}
	// Return a copy to prevent external modification
	return append([]byte(nil), e.lastIV...)
}

// EncryptWithHMAC implements the HMACProvider interface for AES-CTR
// For AES-CTR, this is primarily used for single-part objects
// Multipart streaming should use AESCTRStreamingDataEncryptor with HMAC
func (e *AESCTRDataEncryptor) EncryptWithHMAC(ctx context.Context, data []byte, dek []byte, hmacKey []byte, additionalData []byte) ([]byte, []byte, error) {
	if len(dek) != 32 {
		return nil, nil, fmt.Errorf("invalid DEK size: expected 32 bytes, got %d", len(dek))
	}

	// Use provided HMAC key or derive from DEK if not provided
	var actualHMACKey []byte
	if hmacKey != nil {
		actualHMACKey = hmacKey
	} else {
		// Derive HMAC key from DEK using HKDF
		var err error
		actualHMACKey, err = crypto.DeriveIntegrityKey(dek)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to derive HMAC key: %w", err)
		}
	}

	// Calculate HMAC over original (unencrypted) data
	h := hmac.New(sha256.New, actualHMACKey)
	h.Write(data)
	hmacSum := h.Sum(nil)

	// Encrypt the data using standard AES-CTR
	ciphertext, err := e.Encrypt(ctx, data, dek, additionalData)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encrypt data: %w", err)
	}

	return ciphertext, hmacSum, nil
}

// DecryptWithHMAC implements the HMACProvider interface for AES-CTR
// NOTE: This method should not be used directly for AES-CTR decryption
// The Encryption Manager handles AES-CTR decryption with IV from metadata
func (e *AESCTRDataEncryptor) DecryptWithHMAC(ctx context.Context, encryptedData []byte, dek []byte, hmacKey []byte, expectedHMAC []byte, additionalData []byte) ([]byte, error) {
	return nil, fmt.Errorf("AES-CTR HMAC decryption should be handled through the Encryption Manager with IV from metadata")
}
