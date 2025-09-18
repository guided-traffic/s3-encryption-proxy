package envelope

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"

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

// EncryptDataStream performs envelope encryption on streaming data:
// 1. Generates a new DEK
// 2. Encrypts data stream with the DEK
// 3. Encrypts the DEK with KEK
// Returns encrypted data reader, encrypted DEK, and metadata
func (e *EnvelopeEncryptor) EncryptDataStream(ctx context.Context, dataReader *bufio.Reader, associatedData []byte) (*bufio.Reader, []byte, map[string]string, error) {
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

	// Step 2: Encrypt data stream with the DEK
	encryptedDataReader, err := e.dataEncryptor.EncryptStream(ctx, dataReader, dek, associatedData)
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

	// Check if the data encryptor provides an IV (for AES-CTR modes or nonce for GCM)
	if ivProvider, ok := e.dataEncryptor.(encryption.IVProvider); ok {
		if iv := ivProvider.GetLastIV(); iv != nil {
			metadata[e.metadataPrefix+"aes-iv"] = base64.StdEncoding.EncodeToString(iv)
		}
	}

	return encryptedDataReader, encryptedDEK, metadata, nil
}

// DecryptDataStream performs envelope decryption on streaming data:
// 1. Decrypts the DEK with KEK
// 2. Decrypts data stream with the DEK
func (e *EnvelopeEncryptor) DecryptDataStream(ctx context.Context, encryptedDataReader *bufio.Reader, encryptedDEK []byte, iv []byte, associatedData []byte) (*bufio.Reader, error) {
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

	// Step 2: Decrypt the data stream using the DEK
	dataReader, err := e.dataEncryptor.DecryptStream(ctx, encryptedDataReader, dek, iv, associatedData)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data with DEK: %w", err)
	}

	return dataReader, nil
}

// EncryptDataStreamWithHMAC performs envelope encryption with HMAC integrity verification on streaming data
// Same as EncryptDataStream but also calculates HMAC for integrity verification if provider supports it
// Returns encrypted data reader, encrypted DEK, metadata, and HMAC finalizer function
func (e *EnvelopeEncryptor) EncryptDataStreamWithHMAC(ctx context.Context, dataReader *bufio.Reader, associatedData []byte) (*bufio.Reader, []byte, map[string]string, func() []byte, error) {
	// Step 1: Generate a new DEK
	dek, err := e.dataEncryptor.GenerateDEK(ctx)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to generate DEK: %w", err)
	}
	defer func() {
		// Clear DEK from memory
		for i := range dek {
			dek[i] = 0
		}
	}()

	var encryptedDataReader *bufio.Reader
	var hmacFinalizer func() []byte

	// Step 2: Check if data encryptor supports HMAC
	if hmacProvider, ok := e.dataEncryptor.(encryption.HMACProvider); ok {
		// Derive HMAC key from DEK using HKDF
		hmacKey, err := crypto.DeriveIntegrityKey(dek)
		if err != nil {
			return nil, nil, nil, nil, fmt.Errorf("failed to derive HMAC key: %w", err)
		}
		defer func() {
			// Clear HMAC key from memory
			for i := range hmacKey {
				hmacKey[i] = 0
			}
		}()

		// Encrypt data stream with HMAC calculation
		encryptedDataReader, hmacFinalizer, err = hmacProvider.EncryptStreamWithHMAC(ctx, dataReader, dek, hmacKey, associatedData)
		if err != nil {
			return nil, nil, nil, nil, fmt.Errorf("failed to encrypt data with HMAC: %w", err)
		}
	} else {
		// Fallback to standard encryption without HMAC
		encryptedDataReader, err = e.dataEncryptor.EncryptStream(ctx, dataReader, dek, associatedData)
		if err != nil {
			return nil, nil, nil, nil, fmt.Errorf("failed to encrypt data with DEK: %w", err)
		}
		// Provide empty HMAC finalizer
		hmacFinalizer = func() []byte { return nil }
	}

	// Step 3: Encrypt the DEK with KEK
	encryptedDEK, _, err := e.keyEncryptor.EncryptDEK(ctx, dek)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to encrypt DEK with KEK: %w", err)
	}

	// Create final metadata with prefix - all allowed fields
	metadata := map[string]string{
		e.metadataPrefix + "dek-algorithm":   e.dataEncryptor.Algorithm(),
		e.metadataPrefix + "encrypted-dek":   base64.StdEncoding.EncodeToString(encryptedDEK),
		e.metadataPrefix + "kek-algorithm":   e.keyEncryptor.Name(),
		e.metadataPrefix + "kek-fingerprint": e.keyEncryptor.Fingerprint(),
	}

	// Check if the data encryptor provides an IV (for AES-CTR modes or nonce for GCM)
	if ivProvider, ok := e.dataEncryptor.(encryption.IVProvider); ok {
		if iv := ivProvider.GetLastIV(); iv != nil {
			metadata[e.metadataPrefix+"aes-iv"] = base64.StdEncoding.EncodeToString(iv)
		}
	}

	return encryptedDataReader, encryptedDEK, metadata, hmacFinalizer, nil
}

// DecryptDataStreamWithHMAC performs envelope decryption with HMAC integrity verification on streaming data
// Same as DecryptDataStream but also verifies HMAC for integrity verification if provider supports it
func (e *EnvelopeEncryptor) DecryptDataStreamWithHMAC(ctx context.Context, encryptedDataReader *bufio.Reader, encryptedDEK []byte, iv []byte, expectedHMAC []byte, associatedData []byte) (*bufio.Reader, error) {
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

		// Decrypt data stream with HMAC verification
		dataReader, err := hmacProvider.DecryptStreamWithHMAC(ctx, encryptedDataReader, dek, hmacKey, expectedHMAC, associatedData)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt data with HMAC verification: %w", err)
		}
		return dataReader, nil
	} else {
		// Fallback to standard decryption without HMAC verification
		dataReader, err := e.dataEncryptor.DecryptStream(ctx, encryptedDataReader, dek, iv, associatedData)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt data with DEK: %w", err)
		}
		return dataReader, nil
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

// Utility methods for backward compatibility with []byte data
// These methods wrap the streaming variants for convenient []byte operations

// EncryptData is a convenience method for encrypting []byte data
// It wraps the streaming EncryptDataStream method
func (e *EnvelopeEncryptor) EncryptData(ctx context.Context, data []byte, associatedData []byte) ([]byte, []byte, map[string]string, error) {
	dataReader := bufio.NewReader(bytes.NewReader(data))
	encryptedReader, encryptedDEK, metadata, err := e.EncryptDataStream(ctx, dataReader, associatedData)
	if err != nil {
		return nil, nil, nil, err
	}

	// Read all encrypted data
	encryptedData, err := io.ReadAll(encryptedReader)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to read encrypted data: %w", err)
	}

	return encryptedData, encryptedDEK, metadata, nil
}

// DecryptData is a convenience method for decrypting []byte data
// It wraps the streaming DecryptDataStream method
func (e *EnvelopeEncryptor) DecryptData(ctx context.Context, encryptedData []byte, encryptedDEK []byte, associatedData []byte) ([]byte, error) {
	encryptedReader := bufio.NewReader(bytes.NewReader(encryptedData))
	dataReader, err := e.DecryptDataStream(ctx, encryptedReader, encryptedDEK, nil, associatedData)
	if err != nil {
		return nil, err
	}

	// Read all decrypted data
	data, err := io.ReadAll(dataReader)
	if err != nil {
		return nil, fmt.Errorf("failed to read decrypted data: %w", err)
	}

	return data, nil
}

// EncryptDataWithHMAC is a convenience method for encrypting []byte data with HMAC
// It wraps the streaming EncryptDataStreamWithHMAC method
func (e *EnvelopeEncryptor) EncryptDataWithHMAC(ctx context.Context, data []byte, associatedData []byte) ([]byte, []byte, map[string]string, error) {
	dataReader := bufio.NewReader(bytes.NewReader(data))
	encryptedReader, encryptedDEK, metadata, hmacFinalizer, err := e.EncryptDataStreamWithHMAC(ctx, dataReader, associatedData)
	if err != nil {
		return nil, nil, nil, err
	}

	// Read all encrypted data
	encryptedData, err := io.ReadAll(encryptedReader)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to read encrypted data: %w", err)
	}

	// Get HMAC if available
	if hmac := hmacFinalizer(); hmac != nil {
		metadata[e.metadataPrefix+"hmac"] = base64.StdEncoding.EncodeToString(hmac)
	}

	return encryptedData, encryptedDEK, metadata, nil
}

// DecryptDataWithHMAC is a convenience method for decrypting []byte data with HMAC verification
// It wraps the streaming DecryptDataStreamWithHMAC method
func (e *EnvelopeEncryptor) DecryptDataWithHMAC(ctx context.Context, encryptedData []byte, encryptedDEK []byte, expectedHMAC []byte, associatedData []byte) ([]byte, error) {
	encryptedReader := bufio.NewReader(bytes.NewReader(encryptedData))
	dataReader, err := e.DecryptDataStreamWithHMAC(ctx, encryptedReader, encryptedDEK, nil, expectedHMAC, associatedData)
	if err != nil {
		return nil, err
	}

	// Read all decrypted data
	data, err := io.ReadAll(dataReader)
	if err != nil {
		return nil, fmt.Errorf("failed to read decrypted data: %w", err)
	}

	return data, nil
}
