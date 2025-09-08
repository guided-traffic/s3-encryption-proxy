package envelope

import (
	"context"
	"fmt"

	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption"
)

// EnvelopeEncryptor implements encryption.EnvelopeEncryptor using the composition pattern
// It combines a KeyEncryptor (for KEK operations) with a DataEncryptor (for data operations)
type EnvelopeEncryptor struct {
	keyEncryptor  encryption.KeyEncryptor
	dataEncryptor encryption.DataEncryptor
	version       string
}

// NewEnvelopeEncryptor creates a new envelope encryptor with the specified key and data encryptors
func NewEnvelopeEncryptor(keyEncryptor encryption.KeyEncryptor, dataEncryptor encryption.DataEncryptor) encryption.EnvelopeEncryptor {
	return &EnvelopeEncryptor{
		keyEncryptor:  keyEncryptor,
		dataEncryptor: dataEncryptor,
		version:       "1.0",
	}
}

// EncryptData performs envelope encryption:
// 1. Generates a new DEK
// 2. Encrypts data with the DEK
// 3. Encrypts the DEK with KEK
// Returns encrypted data, encrypted DEK, and metadata
func (e *EnvelopeEncryptor) EncryptData(ctx context.Context, data []byte, associatedData []byte) ([]byte, []byte, map[string]string, error) {
	// Step 1: Generate a new DEK
	dek, err := e.dataEncryptor.GenerateDEK(ctx)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate DEK: %w", err)
	}
	defer func() {
		// Clear DEK from memory
		for i := range dek {
			dek[i] = 0
		}
	}()

	// Step 2: Encrypt data with the DEK
	encryptedData, err := e.dataEncryptor.Encrypt(ctx, data, dek, associatedData)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to encrypt data with DEK: %w", err)
	}

	// Step 3: Encrypt the DEK with KEK
	encryptedDEK, keyID, err := e.keyEncryptor.EncryptDEK(ctx, dek)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to encrypt DEK with KEK: %w", err)
	}

	// Create metadata
	metadata := map[string]string{
		"algorithm":       fmt.Sprintf("envelope-%s", e.dataEncryptor.Algorithm()),
		"version":         e.version,
		"key_id":          keyID,
		"data_algorithm":  e.dataEncryptor.Algorithm(),
		"kek_fingerprint": e.keyEncryptor.Fingerprint(),
	}

	return encryptedData, encryptedDEK, metadata, nil
}

// DecryptData performs envelope decryption:
// 1. Decrypts the DEK with KEK
// 2. Decrypts data with the DEK
func (e *EnvelopeEncryptor) DecryptData(ctx context.Context, encryptedData []byte, encryptedDEK []byte, associatedData []byte) ([]byte, error) {
	// Step 1: Decrypt the DEK using the KEK
	dek, err := e.keyEncryptor.DecryptDEK(ctx, encryptedDEK, e.keyEncryptor.Fingerprint())
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt DEK: %w", err)
	}
	defer func() {
		// Clear DEK from memory
		for i := range dek {
			dek[i] = 0
		}
	}()

	// Step 2: Decrypt the data using the DEK
	data, err := e.dataEncryptor.Decrypt(ctx, encryptedData, dek, associatedData)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data with DEK: %w", err)
	}

	return data, nil
}

// Fingerprint returns a combined fingerprint of both the key and data encryptors
func (e *EnvelopeEncryptor) Fingerprint() string {
	return e.keyEncryptor.Fingerprint()
}

// RotateKEK rotates the Key Encryption Key
func (e *EnvelopeEncryptor) RotateKEK(ctx context.Context) error {
	return e.keyEncryptor.RotateKEK(ctx)
}

// GetKeyEncryptor returns the underlying key encryptor (for advanced use cases)
func (e *EnvelopeEncryptor) GetKeyEncryptor() encryption.KeyEncryptor {
	return e.keyEncryptor
}

// GetDataEncryptor returns the underlying data encryptor (for advanced use cases)
func (e *EnvelopeEncryptor) GetDataEncryptor() encryption.DataEncryptor {
	return e.dataEncryptor
}
