package providers

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

// AESGCMProvider implements direct AES-256-GCM encryption
type AESGCMProvider struct {
	key []byte
}

// NewAESGCMProvider creates a new AES-GCM encryption provider
func NewAESGCMProvider(key []byte) (*AESGCMProvider, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("AES-256 key must be exactly 32 bytes, got %d", len(key))
	}

	// Validate key by creating a cipher
	if _, err := aes.NewCipher(key); err != nil {
		return nil, fmt.Errorf("invalid AES key: %w", err)
	}

	return &AESGCMProvider{
		key: key,
	}, nil
}

// NewAESGCMProviderFromBase64 creates a new AES-GCM provider from a base64-encoded key
func NewAESGCMProviderFromBase64(base64Key string) (*AESGCMProvider, error) {
	key, err := base64.StdEncoding.DecodeString(base64Key)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64 key: %w", err)
	}

	return NewAESGCMProvider(key)
}

// Encrypt encrypts data using AES-256-GCM
func (p *AESGCMProvider) Encrypt(ctx context.Context, data []byte, associatedData []byte) (*encryption.EncryptionResult, error) {
	// Create AES cipher
	block, err := aes.NewCipher(p.key)
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

	return &encryption.EncryptionResult{
		EncryptedData: encryptedData,
		EncryptedDEK:  nil, // No DEK in direct encryption
		Metadata: map[string]string{
			"algorithm":  "aes256-gcm",
			"version":    "1.0",
			"nonce_size": fmt.Sprintf("%d", gcm.NonceSize()),
		},
	}, nil
}

// Decrypt decrypts data using AES-256-GCM
func (p *AESGCMProvider) Decrypt(ctx context.Context, encryptedData []byte, encryptedDEK []byte, associatedData []byte) ([]byte, error) {
	// Note: encryptedDEK is ignored for direct AES-GCM encryption

	// Create AES cipher
	block, err := aes.NewCipher(p.key)
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
func (p *AESGCMProvider) RotateKEK(ctx context.Context) error {
	return fmt.Errorf("key rotation is not supported for direct AES-GCM encryption")
}

// GenerateAESGCMKey generates a new random 256-bit AES key
func GenerateAESGCMKey() ([]byte, error) {
	key := make([]byte, 32) // 256 bits
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("failed to generate random key: %w", err)
	}
	return key, nil
}
