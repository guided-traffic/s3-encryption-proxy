package encryption

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
)

// AESGCMEncryptor implements direct AES-256-GCM encryption (without envelope encryption)
type AESGCMEncryptor struct {
	key []byte // 32 bytes for AES-256
}

// NewAESGCMEncryptor creates a new AES-256-GCM encryptor
func NewAESGCMEncryptor(key []byte) (*AESGCMEncryptor, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("key must be exactly 32 bytes for AES-256, got %d bytes", len(key))
	}

	return &AESGCMEncryptor{
		key: key,
	}, nil
}

// NewAESGCMEncryptorFromBase64 creates a new AES-256-GCM encryptor from base64 encoded key
func NewAESGCMEncryptorFromBase64(keyBase64 string) (*AESGCMEncryptor, error) {
	key, err := base64.StdEncoding.DecodeString(keyBase64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64 key: %w", err)
	}

	return NewAESGCMEncryptor(key)
}

// GenerateKey generates a new random 256-bit key for AES-256-GCM
func GenerateAESGCMKey() ([]byte, error) {
	key := make([]byte, 32) // 256 bits
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("failed to generate random key: %w", err)
	}
	return key, nil
}

// Encrypt encrypts data using AES-256-GCM
func (e *AESGCMEncryptor) Encrypt(ctx context.Context, data []byte, associatedData []byte) (*EncryptionResult, error) {
	// Create AES cipher
	block, err := aes.NewCipher(e.key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM mode: %w", err)
	}

	// Generate random nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt data
	ciphertext := gcm.Seal(nil, nonce, data, associatedData)

	// Prepend nonce to ciphertext
	encryptedData := make([]byte, len(nonce)+len(ciphertext))
	copy(encryptedData[:len(nonce)], nonce)
	copy(encryptedData[len(nonce):], ciphertext)

	return &EncryptionResult{
		EncryptedData: encryptedData,
		EncryptedDEK:  nil, // No DEK in direct encryption
		Metadata: map[string]string{
			"algorithm":  "aes-gcm",
			"version":    "1.0",
			"nonce_size": fmt.Sprintf("%d", gcm.NonceSize()),
		},
	}, nil
}

// Decrypt decrypts data using AES-256-GCM
func (e *AESGCMEncryptor) Decrypt(ctx context.Context, encryptedData []byte, encryptedDEK []byte, associatedData []byte) ([]byte, error) {
	// Create AES cipher
	block, err := aes.NewCipher(e.key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM mode: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(encryptedData) < nonceSize {
		return nil, fmt.Errorf("encrypted data too short, expected at least %d bytes, got %d", nonceSize, len(encryptedData))
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

// RotateKEK is not applicable for direct AES-GCM encryption
func (e *AESGCMEncryptor) RotateKEK(ctx context.Context) error {
	return fmt.Errorf("key rotation not applicable for direct AES-GCM encryption")
}
