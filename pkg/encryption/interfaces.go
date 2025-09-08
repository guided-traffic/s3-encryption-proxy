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

// DirectEncryptor handles direct encryption without envelope patterns (e.g., single key for all data)
type DirectEncryptor interface {
	// Encrypt encrypts data directly with a master key
	Encrypt(ctx context.Context, data []byte, associatedData []byte) (encryptedData []byte, metadata map[string]string, err error)

	// Decrypt decrypts data directly with a master key
	Decrypt(ctx context.Context, encryptedData []byte, associatedData []byte) (data []byte, err error)

	// Fingerprint returns a unique identifier for this direct encryption configuration
	Fingerprint() string

	// RotateKey rotates the master key (implementation dependent)
	RotateKey(ctx context.Context) error
}

// EncryptionProvider is a unified interface that can represent either envelope or direct encryption
type EncryptionProvider interface {
	// Encrypt encrypts data using the provider's method (envelope or direct)
	Encrypt(ctx context.Context, data []byte, associatedData []byte) (*EncryptionResult, error)

	// Decrypt decrypts data using the provider's method (envelope or direct)
	Decrypt(ctx context.Context, encryptedData []byte, encryptedDEK []byte, associatedData []byte) ([]byte, error)

	// Fingerprint returns a unique identifier for this provider
	Fingerprint() string

	// RotateKeys rotates encryption keys (implementation dependent)
	RotateKeys(ctx context.Context) error

	// Type returns the provider type (envelope or direct)
	Type() ProviderType
}

// ProviderType distinguishes between envelope and direct encryption providers
type ProviderType string

const (
	ProviderTypeEnvelope ProviderType = "envelope"
	ProviderTypeDirect   ProviderType = "direct"
)

// EncryptionResult holds the result of an encryption operation
type EncryptionResult struct {
	EncryptedData []byte
	EncryptedDEK  []byte            // nil for direct encryption providers
	Metadata      map[string]string
}

// Encryptor defines the legacy interface for backward compatibility
// Deprecated: Use EncryptionProvider instead
type Encryptor interface {
	// Encrypt encrypts data
	// Returns encrypted data and encrypted DEK (if applicable)
	Encrypt(ctx context.Context, data []byte, associatedData []byte) (*EncryptionResult, error)

	// Decrypt decrypts data using the provided encrypted DEK (if applicable)
	Decrypt(ctx context.Context, encryptedData []byte, encryptedDEK []byte, associatedData []byte) ([]byte, error)

	// Fingerprint returns a unique fingerprint for this encryption provider
	// Used to identify which provider was used for encryption during decryption
	Fingerprint() string

	// RotateKEK rotates the Key Encryption Key (if applicable)
	RotateKEK(ctx context.Context) error
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
