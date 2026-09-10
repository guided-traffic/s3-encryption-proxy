package encryption

import (
	"context"
)

// KeyEncryptor handles Key Encryption Key (KEK) operations for encrypting/decrypting Data Encryption Keys (DEK)
type KeyEncryptor interface {
	// EncryptDEK encrypts a Data Encryption Key with the Key Encryption Key
	EncryptDEK(ctx context.Context, dek []byte) (encryptedDEK []byte, err error)

	// DecryptDEK decrypts a Data Encryption Key using the Key Encryption Key.
	// The caller has already selected this KeyEncryptor by fingerprint.
	DecryptDEK(ctx context.Context, encryptedDEK []byte) (dek []byte, err error)

	// Name returns a short unique name for this KeyEncryptor type
	// Used to identify the encryption provider (e.g., "aes", "none")
	Name() string

	// Fingerprint returns a unique identifier for this KeyEncryptor
	// Used to match encrypted DEKs with the correct KeyEncryptor
	Fingerprint() string
}
