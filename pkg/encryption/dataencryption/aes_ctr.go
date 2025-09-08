package dataencryption

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"

	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption"
)

// AESCTRDataEncryptor implements encryption.DataEncryptor using AES-256-CTR
// This handles ONLY data encryption/decryption with provided DEKs
type AESCTRDataEncryptor struct{}

// NewAESCTRDataEncryptor creates a new AES-CTR data encryptor
func NewAESCTRDataEncryptor() encryption.DataEncryptor {
	return &AESCTRDataEncryptor{}
}

// NewAESCTRProvider is an alias for NewAESCTRDataEncryptor for backward compatibility
func NewAESCTRProvider(key []byte) (encryption.DataEncryptor, error) {
	// AES-CTR DataEncryptor doesn't need a fixed key - it uses provided DEKs
	// But for testing purposes, we validate the key format
	if len(key) != 32 {
		return nil, fmt.Errorf("invalid key size: expected 32 bytes, got %d", len(key))
	}
	return NewAESCTRDataEncryptor(), nil
}

// Encrypt encrypts data using AES-256-CTR with the provided DEK
func (e *AESCTRDataEncryptor) Encrypt(ctx context.Context, data []byte, dek []byte, associatedData []byte) ([]byte, error) {
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

	// Create CTR mode cipher
	stream := cipher.NewCTR(block, iv)

	// Encrypt the data
	ciphertext := make([]byte, len(data))
	stream.XORKeyStream(ciphertext, data)

	// Prepend IV to ciphertext
	result := make([]byte, len(iv)+len(ciphertext))
	copy(result, iv)
	copy(result[len(iv):], ciphertext)

	return result, nil
}

// Decrypt decrypts data using AES-256-CTR with the provided DEK
func (e *AESCTRDataEncryptor) Decrypt(ctx context.Context, encryptedData []byte, dek []byte, associatedData []byte) ([]byte, error) {
	if len(dek) != 32 {
		return nil, fmt.Errorf("invalid DEK size: expected 32 bytes, got %d", len(dek))
	}

	if len(encryptedData) < aes.BlockSize {
		return nil, fmt.Errorf("encrypted data too short: expected at least %d bytes, got %d", aes.BlockSize, len(encryptedData))
	}

	// Create AES cipher with DEK
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	// Extract IV and ciphertext
	iv := encryptedData[:aes.BlockSize]
	ciphertext := encryptedData[aes.BlockSize:]

	// Create CTR mode cipher
	stream := cipher.NewCTR(block, iv)

	// Decrypt the data
	plaintext := make([]byte, len(ciphertext))
	stream.XORKeyStream(plaintext, ciphertext)

	return plaintext, nil
}

// GenerateDEK generates a new 256-bit AES key
func (e *AESCTRDataEncryptor) GenerateDEK(ctx context.Context) ([]byte, error) {
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

// NewAESCTRProviderFromBase64 creates a new AES-CTR provider from a base64-encoded key
func NewAESCTRProviderFromBase64(keyB64 string) (encryption.DataEncryptor, error) {
	key, err := base64.StdEncoding.DecodeString(keyB64)
	if err != nil {
		return nil, fmt.Errorf("invalid base64 in AES key: %w", err)
	}

	return NewAESCTRProvider(key)
}
