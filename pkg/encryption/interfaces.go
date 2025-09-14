package encryption

import (
	"context"
)

// KeyEncryptor handles Key Encryption Key (KEK) operations for encrypting/decrypting Data Encryption Keys (DEK)
type KeyEncryptor interface {
	// EncryptDEK encrypts a Data Encryption Key with the Key Encryption Key
	// Returns the encrypted DEK and an identifier for the KEK used
	EncryptDEK(ctx context.Context, dek []byte) (encryptedDEK []byte, keyID string, err error)

	// DecryptDEK decrypts a Data Encryption Key using the Key Encryption Key
	// keyID identifies which KEK to use for decryption
	DecryptDEK(ctx context.Context, encryptedDEK []byte, keyID string) (dek []byte, err error)

	// Name returns a short unique name for this KeyEncryptor type
	// Used to identify the encryption provider (e.g., "aes", "rsa")
	Name() string

	// Fingerprint returns a unique identifier for this KeyEncryptor
	// Used to match encrypted DEKs with the correct KeyEncryptor
	Fingerprint() string

	// RotateKEK rotates the Key Encryption Key (implementation dependent)
	RotateKEK(ctx context.Context) error
}

// DataEncryptor handles encryption/decryption of data using Data Encryption Keys (DEK)
type DataEncryptor interface {
	// Encrypt encrypts data using the provided DEK
	// associatedData is used for authenticated encryption
	Encrypt(ctx context.Context, data []byte, dek []byte, associatedData []byte) (encryptedData []byte, err error)

	// Decrypt decrypts data using the provided DEK
	// associatedData must match the value used during encryption
	Decrypt(ctx context.Context, encryptedData []byte, dek []byte, associatedData []byte) (data []byte, err error)

	// GenerateDEK generates a new Data Encryption Key suitable for this DataEncryptor
	GenerateDEK(ctx context.Context) (dek []byte, err error)

	// Algorithm returns the encryption algorithm identifier
	Algorithm() string
}

// IVProvider is an optional interface that DataEncryptors can implement to provide IV for metadata
type IVProvider interface {
	// GetLastIV returns the IV used in the last encryption operation
	// This is used to store the IV in metadata for some encryption modes
	GetLastIV() []byte
}

// EnvelopeEncryptor combines KeyEncryptor and DataEncryptor for envelope encryption patterns
type EnvelopeEncryptor interface {
	// EncryptData performs envelope encryption:
	// 1. Generates a new DEK
	// 2. Encrypts data with the DEK
	// 3. Encrypts the DEK with KEK
	// Returns encrypted data, encrypted DEK, and metadata
	EncryptData(ctx context.Context, data []byte, associatedData []byte) (encryptedData []byte, encryptedDEK []byte, metadata map[string]string, err error)

	// DecryptData performs envelope decryption:
	// 1. Decrypts the DEK with KEK
	// 2. Decrypts data with the DEK
	DecryptData(ctx context.Context, encryptedData []byte, encryptedDEK []byte, associatedData []byte) (data []byte, err error)

	// Fingerprint returns a unique identifier for this envelope encryption configuration
	Fingerprint() string

	// RotateKEK rotates the Key Encryption Key
	RotateKEK(ctx context.Context) error
}

// EncryptionProvider is a unified interface that can represent envelope encryption
type EncryptionProvider interface {
	// Encrypt encrypts data using envelope encryption
	Encrypt(ctx context.Context, data []byte, associatedData []byte) (*EncryptionResult, error)

	// Decrypt decrypts data using envelope encryption
	Decrypt(ctx context.Context, encryptedData []byte, encryptedDEK []byte, associatedData []byte) ([]byte, error)

	// Fingerprint returns a unique identifier for this provider
	Fingerprint() string

	// RotateKeys rotates encryption keys (implementation dependent)
	RotateKeys(ctx context.Context) error
}

// EncryptionResult holds the result of an encryption operation
type EncryptionResult struct {
	EncryptedData []byte
	EncryptedDEK  []byte // Encrypted Data Encryption Key
	Metadata      map[string]string
}

// EncryptionType represents the type of encryption to use
type EncryptionType string

const (
	// EncryptionTypeTink uses Google Tink with envelope encryption
	EncryptionTypeTink EncryptionType = "tink"

	// EncryptionTypeAESGCM uses direct AES-256-GCM encryption
	EncryptionTypeAESGCM EncryptionType = "aes-gcm"

	// EncryptionTypeRSAEnvelope uses RSA envelope encryption
	EncryptionTypeRSAEnvelope EncryptionType = "rsa-envelope"

	// EncryptionTypeAESCTR uses AES-CTR envelope encryption
	EncryptionTypeAESCTR EncryptionType = "aes-ctr"

	// EncryptionTypeNone uses no encryption (testing only)
	EncryptionTypeNone EncryptionType = "none"
)
