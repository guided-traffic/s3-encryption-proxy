package encryption

import (
	"context"
)

// EncryptionResult holds the result of an encryption operation
type EncryptionResult struct {
	EncryptedData []byte
	EncryptedDEK  []byte
	Metadata      map[string]string
}

// Encryptor defines the interface for encryption operations
type Encryptor interface {
	// Encrypt encrypts data
	// Returns encrypted data and encrypted DEK (if applicable)
	Encrypt(ctx context.Context, data []byte, associatedData []byte) (*EncryptionResult, error)

	// Decrypt decrypts data using the provided encrypted DEK (if applicable)
	Decrypt(ctx context.Context, encryptedData []byte, encryptedDEK []byte, associatedData []byte) ([]byte, error)

	// RotateKEK rotates the Key Encryption Key (if applicable)
	RotateKEK(ctx context.Context) error
}

// EncryptionType represents the type of encryption to use
type EncryptionType string

const (
	// EncryptionTypeTink uses Google Tink with envelope encryption
	EncryptionTypeTink EncryptionType = "tink"
	
	// EncryptionTypeAESGCM uses direct AES-256-GCM encryption
	EncryptionTypeAESGCM EncryptionType = "aes256-gcm"
)
