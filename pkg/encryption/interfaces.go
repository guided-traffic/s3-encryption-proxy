package encryption

import (
	"bufio"
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

// DataEncryptor handles streaming encryption/decryption of data using Data Encryption Keys (DEK)
// This unified interface works with io.Reader/io.Writer for both small and large data
// For small data, use bytes.NewReader() and bytes.Buffer to wrap []byte data
type DataEncryptor interface {
	// EncryptStream encrypts data from a reader and returns an encrypted reader
	// The returned reader provides encrypted data on-demand as it's read
	// dek is the Data Encryption Key, associatedData is used for authenticated encryption
	EncryptStream(ctx context.Context, reader *bufio.Reader, dek []byte, associatedData []byte) (*bufio.Reader, error)

	// DecryptStream decrypts data from an encrypted reader and returns a decrypted reader
	// The returned reader provides decrypted data on-demand as it's read
	// dek is the Data Encryption Key, iv is the initialization vector from metadata
	// associatedData must match the value used during encryption
	DecryptStream(ctx context.Context, encryptedReader *bufio.Reader, dek []byte, iv []byte, associatedData []byte) (*bufio.Reader, error)

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
// All operations now work with streaming interfaces using io.Reader/io.Writer
type EnvelopeEncryptor interface {
	// EncryptDataStream performs envelope encryption on streaming data:
	// 1. Generates a new DEK
	// 2. Encrypts data stream with the DEK
	// 3. Encrypts the DEK with KEK
	// Returns encrypted data reader, encrypted DEK, and metadata
	EncryptDataStream(ctx context.Context, dataReader *bufio.Reader, associatedData []byte) (*bufio.Reader, []byte, map[string]string, error)

	// DecryptDataStream performs envelope decryption on streaming data:
	// 1. Decrypts the DEK with KEK
	// 2. Decrypts data stream with the DEK
	DecryptDataStream(ctx context.Context, encryptedDataReader *bufio.Reader, encryptedDEK []byte, iv []byte, associatedData []byte) (*bufio.Reader, error)

	// Fingerprint returns a unique identifier for this envelope encryption configuration
	Fingerprint() string

	// RotateKEK rotates the Key Encryption Key
	RotateKEK(ctx context.Context) error
}

// EncryptionProvider is a unified interface that can represent envelope encryption
// EncryptionProvider defines the interface for encryption providers using streaming
//
//nolint:revive // Exported type name matches domain context
type EncryptionProvider interface {
	// Encrypt encrypts data using envelope encryption with streaming
	Encrypt(ctx context.Context, dataReader *bufio.Reader, associatedData []byte) (*bufio.Reader, []byte, map[string]string, error)

	// Decrypt decrypts data using envelope encryption with streaming
	Decrypt(ctx context.Context, encryptedDataReader *bufio.Reader, encryptedDEK []byte, iv []byte, associatedData []byte) (*bufio.Reader, error)

	// Fingerprint returns a unique identifier for this provider
	Fingerprint() string

	// RotateKeys rotates encryption keys (implementation dependent)
	RotateKeys(ctx context.Context) error
}

// EncryptionType represents the type of encryption to use
// EncryptionType defines the type of encryption to use
//
//nolint:revive // Exported type name matches domain context
type EncryptionType string

const (
	// EncryptionTypeTink uses Google Tink with envelope encryption
	EncryptionTypeTink EncryptionType = "tink"

	// EncryptionTypeAESGCM uses direct aes-gcm encryption
	EncryptionTypeAESGCM EncryptionType = "aes-gcm"

	// EncryptionTypeRSAEnvelope uses RSA envelope encryption
	EncryptionTypeRSAEnvelope EncryptionType = "rsa-envelope"

	// EncryptionTypeAESCTR uses AES-CTR envelope encryption
	EncryptionTypeAESCTR EncryptionType = "aes-ctr"

	// EncryptionTypeNone uses no encryption (testing only)
	EncryptionTypeNone EncryptionType = "none"
)
