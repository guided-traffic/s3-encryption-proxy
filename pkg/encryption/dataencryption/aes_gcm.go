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

// AESGCMDataEncryptor implements encryption.DataEncryptor using AES-256-GCM
// This handles ONLY data encryption/decryption with provided DEKs
type AESGCMDataEncryptor struct{}

// NewAESGCMDataEncryptor creates a new AES-GCM data encryptor
func NewAESGCMDataEncryptor() encryption.DataEncryptor {
	return &AESGCMDataEncryptor{}
}

// NewAESGCMProvider is an alias for NewAESGCMDataEncryptor for backward compatibility
func NewAESGCMProvider(key []byte) (encryption.DataEncryptor, error) {
	// AES-GCM DataEncryptor doesn't need a fixed key - it uses provided DEKs
	// But for testing purposes, we validate the key format
	if len(key) != 32 {
		return nil, fmt.Errorf("invalid key size: expected 32 bytes, got %d", len(key))
	}
	return NewAESGCMDataEncryptor(), nil
}

// NewAESGCMProviderFromBase64 creates a new AES-GCM provider from a base64-encoded key
func NewAESGCMProviderFromBase64(keyB64 string) (encryption.DataEncryptor, error) {
	key, err := base64.StdEncoding.DecodeString(keyB64)
	if err != nil {
		return nil, fmt.Errorf("invalid base64 in AES key: %w", err)
	}

	return NewAESGCMProvider(key)
}

// Encrypt encrypts data using AES-256-GCM with the provided DEK
func (e *AESGCMDataEncryptor) Encrypt(ctx context.Context, data []byte, dek []byte, associatedData []byte) ([]byte, error) {
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
func (e *AESGCMDataEncryptor) Decrypt(ctx context.Context, encryptedData []byte, dek []byte, associatedData []byte) ([]byte, error) {
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
func (e *AESGCMDataEncryptor) GenerateDEK(ctx context.Context) ([]byte, error) {
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
