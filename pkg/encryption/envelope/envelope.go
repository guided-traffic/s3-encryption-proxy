package envelope

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/guided-traffic/s3-encryption-proxy/internal/crypto"
	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption"
)

// EnvelopeEncryptor implements encryption.EnvelopeEncryptor using the composition pattern
// It combines a KeyEncryptor (for KEK operations) with a DataEncryptor (for data operations)
// EnvelopeEncryptor implements envelope encryption with separate KEK and DEK
//
//nolint:revive // Exported type name matches domain context
type EnvelopeEncryptor struct {
	keyEncryptor   encryption.KeyEncryptor
	dataEncryptor  encryption.DataEncryptor
	metadataPrefix string
	version        string
}

// NewEnvelopeEncryptor creates a new envelope encryptor with the specified key and data encryptors
// Uses no prefix - suitable for Factory-level operations
func NewEnvelopeEncryptor(keyEncryptor encryption.KeyEncryptor, dataEncryptor encryption.DataEncryptor) encryption.EnvelopeEncryptor {
	return &EnvelopeEncryptor{
		keyEncryptor:   keyEncryptor,
		dataEncryptor:  dataEncryptor,
		metadataPrefix: "", // no prefix for raw factory operations
		version:        "1.0",
	}
}

// NewEnvelopeEncryptorWithPrefix creates a new envelope encryptor with custom metadata prefix
func NewEnvelopeEncryptorWithPrefix(keyEncryptor encryption.KeyEncryptor, dataEncryptor encryption.DataEncryptor, metadataPrefix string) encryption.EnvelopeEncryptor {
	return &EnvelopeEncryptor{
		keyEncryptor:   keyEncryptor,
		dataEncryptor:  dataEncryptor,
		metadataPrefix: metadataPrefix,
		version:        "1.0",
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
	encryptedDEK, _, err := e.keyEncryptor.EncryptDEK(ctx, dek)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to encrypt DEK with KEK: %w", err)
	}

	// Create final metadata with prefix - all 5 allowed fields
	metadata := map[string]string{
		e.metadataPrefix + "dek-algorithm":   e.dataEncryptor.Algorithm(),
		e.metadataPrefix + "encrypted-dek":   base64.StdEncoding.EncodeToString(encryptedDEK),
		e.metadataPrefix + "kek-algorithm":   e.keyEncryptor.Name(),
		e.metadataPrefix + "kek-fingerprint": e.keyEncryptor.Fingerprint(),
	}

	// Check if the data encryptor provides an IV (for AES-CTR modes)
	if ivProvider, ok := e.dataEncryptor.(interface{ GetLastIV() []byte }); ok {
		if iv := ivProvider.GetLastIV(); iv != nil {
			metadata[e.metadataPrefix+"aes-iv"] = base64.StdEncoding.EncodeToString(iv)
		}
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

// EncryptDataWithHMAC performs envelope encryption with HMAC integrity verification
// 1. Generates a new DEK
// 2. Derives HMAC key from DEK using HKDF
// 3. Encrypts data with the DEK and calculates HMAC if provider supports it
// 4. Encrypts the DEK with KEK
// Returns encrypted data, encrypted DEK, and metadata including HMAC
func (e *EnvelopeEncryptor) EncryptDataWithHMAC(ctx context.Context, data []byte, associatedData []byte) ([]byte, []byte, map[string]string, error) {
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

	var encryptedData []byte
	var calculatedHMAC []byte

	// Step 2: Check if data encryptor supports HMAC
	if hmacProvider, ok := e.dataEncryptor.(encryption.HMACProvider); ok {
		// Derive HMAC key from DEK using HKDF
		hmacKey, err := crypto.DeriveIntegrityKey(dek)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("failed to derive HMAC key: %w", err)
		}
		defer func() {
			// Clear HMAC key from memory
			for i := range hmacKey {
				hmacKey[i] = 0
			}
		}()

		// Encrypt data with HMAC calculation
		encryptedData, calculatedHMAC, err = hmacProvider.EncryptWithHMAC(ctx, data, dek, hmacKey, associatedData)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("failed to encrypt data with HMAC: %w", err)
		}
	} else {
		// Fallback to standard encryption without HMAC
		encryptedData, err = e.dataEncryptor.Encrypt(ctx, data, dek, associatedData)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("failed to encrypt data with DEK: %w", err)
		}
	}

	// Step 3: Encrypt the DEK with KEK
	encryptedDEK, _, err := e.keyEncryptor.EncryptDEK(ctx, dek)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to encrypt DEK with KEK: %w", err)
	}

	// Create final metadata with prefix - all allowed fields
	metadata := map[string]string{
		e.metadataPrefix + "dek-algorithm":   e.dataEncryptor.Algorithm(),
		e.metadataPrefix + "encrypted-dek":   base64.StdEncoding.EncodeToString(encryptedDEK),
		e.metadataPrefix + "kek-algorithm":   e.keyEncryptor.Name(),
		e.metadataPrefix + "kek-fingerprint": e.keyEncryptor.Fingerprint(),
	}

	// Add HMAC to metadata if calculated
	if calculatedHMAC != nil {
		metadata[e.metadataPrefix+"hmac"] = base64.StdEncoding.EncodeToString(calculatedHMAC)
	}

	// Check if the data encryptor provides an IV (for AES-CTR modes)
	if ivProvider, ok := e.dataEncryptor.(encryption.IVProvider); ok {
		if iv := ivProvider.GetLastIV(); iv != nil {
			metadata[e.metadataPrefix+"aes-iv"] = base64.StdEncoding.EncodeToString(iv)
		}
	}

	return encryptedData, encryptedDEK, metadata, nil
}

// DecryptDataWithHMAC performs envelope decryption with HMAC integrity verification
// 1. Decrypts the DEK with KEK
// 2. Derives HMAC key from DEK using HKDF
// 3. Decrypts data with the DEK and verifies HMAC if provider supports it
func (e *EnvelopeEncryptor) DecryptDataWithHMAC(ctx context.Context, encryptedData []byte, encryptedDEK []byte, expectedHMAC []byte, associatedData []byte) ([]byte, error) {
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

	// Step 2: Check if data encryptor supports HMAC and we have expectedHMAC
	if hmacProvider, ok := e.dataEncryptor.(encryption.HMACProvider); ok && expectedHMAC != nil {
		// Derive HMAC key from DEK using HKDF
		hmacKey, err := crypto.DeriveIntegrityKey(dek)
		if err != nil {
			return nil, fmt.Errorf("failed to derive HMAC key: %w", err)
		}
		defer func() {
			// Clear HMAC key from memory
			for i := range hmacKey {
				hmacKey[i] = 0
			}
		}()

		// Decrypt data with HMAC verification
		data, err := hmacProvider.DecryptWithHMAC(ctx, encryptedData, dek, hmacKey, expectedHMAC, associatedData)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt data with HMAC verification: %w", err)
		}
		return data, nil
	} else {
		// Fallback to standard decryption without HMAC verification
		data, err := e.dataEncryptor.Decrypt(ctx, encryptedData, dek, associatedData)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt data with DEK: %w", err)
		}
		return data, nil
	}
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
