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

// DataEncryptorStreaming handles streaming encryption/decryption of data using Data Encryption Keys (DEK)
// This interface is designed for processing large amounts of data efficiently with buffered I/O
type DataEncryptorStreaming interface {
	// EncryptStream encrypts data from a reader and returns an encrypted reader
	// The returned reader provides encrypted data on-demand as it's read
	// dek is the Data Encryption Key, associatedData is used for authenticated encryption
	EncryptStream(ctx context.Context, reader *bufio.Reader, dek []byte, associatedData []byte) (*bufio.Reader, error)

	// DecryptStream decrypts data from an encrypted reader and returns a decrypted reader
	// The returned reader provides decrypted data on-demand as it's read
	// dek is the Data Encryption Key, iv is the initialization vector from metadata
	// associatedData must match the value used during encryption
	DecryptStream(ctx context.Context, encryptedReader *bufio.Reader, dek []byte, iv []byte, associatedData []byte) (*bufio.Reader, error)

	// GenerateDEK generates a new Data Encryption Key suitable for this DataEncryptorStreaming
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

// HMACProvider is an optional interface that DataEncryptors can implement to support HMAC integrity verification
type HMACProvider interface {
	// EncryptWithHMAC encrypts data and calculates HMAC in parallel for integrity verification
	// hmacKey is derived from the DEK using HKDF for integrity verification
	// Returns encrypted data and calculated HMAC over the original (unencrypted) data
	EncryptWithHMAC(ctx context.Context, data []byte, dek []byte, hmacKey []byte, associatedData []byte) (encryptedData []byte, hmac []byte, err error)

	// DecryptWithHMAC decrypts data and verifies HMAC for integrity verification
	// hmacKey is derived from the DEK using HKDF for integrity verification
	// expectedHMAC is the HMAC value stored in metadata to verify against
	// Returns decrypted data or error if HMAC verification fails
	DecryptWithHMAC(ctx context.Context, encryptedData []byte, dek []byte, hmacKey []byte, expectedHMAC []byte, associatedData []byte) (data []byte, err error)
}

// HMACProviderStreaming is an optional interface that DataEncryptorStreaming can implement to support streaming HMAC integrity verification
type HMACProviderStreaming interface {
	// EncryptStreamWithHMAC encrypts data from a reader and calculates HMAC in parallel for integrity verification
	// The returned reader provides encrypted data on-demand as it's read, while HMAC is calculated incrementally
	// hmacKey is derived from the DEK using HKDF for integrity verification
	// Returns encrypted reader and a function to get the final HMAC once all data has been read
	EncryptStreamWithHMAC(ctx context.Context, reader *bufio.Reader, dek []byte, hmacKey []byte, associatedData []byte) (*bufio.Reader, func() []byte, error)

	// DecryptStreamWithHMAC decrypts data from an encrypted reader and verifies HMAC for integrity verification
	// The returned reader provides decrypted data on-demand as it's read, while HMAC is verified incrementally
	// hmacKey is derived from the DEK using HKDF for integrity verification
	// expectedHMAC is the HMAC value stored in metadata to verify against
	// Returns decrypted reader and error if HMAC verification fails during streaming
	DecryptStreamWithHMAC(ctx context.Context, encryptedReader *bufio.Reader, dek []byte, hmacKey []byte, expectedHMAC []byte, associatedData []byte) (*bufio.Reader, error)
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

	// EncryptDataWithHMAC performs envelope encryption with HMAC integrity verification
	// Same as EncryptData but also calculates HMAC for integrity verification if provider supports it
	EncryptDataWithHMAC(ctx context.Context, data []byte, associatedData []byte) (encryptedData []byte, encryptedDEK []byte, metadata map[string]string, err error)

	// DecryptDataWithHMAC performs envelope decryption with HMAC integrity verification
	// Same as DecryptData but also verifies HMAC for integrity verification if provider supports it
	DecryptDataWithHMAC(ctx context.Context, encryptedData []byte, encryptedDEK []byte, expectedHMAC []byte, associatedData []byte) (data []byte, err error)

	// Fingerprint returns a unique identifier for this envelope encryption configuration
	Fingerprint() string

	// RotateKEK rotates the Key Encryption Key
	RotateKEK(ctx context.Context) error
}

// EncryptionProvider is a unified interface that can represent envelope encryption
// EncryptionProvider defines the interface for encryption providers
//
//nolint:revive // Exported type name matches domain context
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
// EncryptionResult represents the result of an encryption operation
//
//nolint:revive // Exported type name matches domain context
type EncryptionResult struct {
	EncryptedData []byte
	EncryptedDEK  []byte // Encrypted Data Encryption Key
	Metadata      map[string]string
}

// EncryptionType represents the type of encryption to use
// EncryptionType defines the type of encryption to use
//
//nolint:revive // Exported type name matches domain context
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
