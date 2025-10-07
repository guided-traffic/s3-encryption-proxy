package envelope

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"

	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption"
)

// EnvelopeEncryptor implements envelope encryption with separate KEK and DEK.
// It combines a KeyEncryptor (for KEK operations) with a DataEncryptor (for data operations).
//
//nolint:revive // Exported type name matches domain context
type EnvelopeEncryptor struct {
	keyEncryptor   encryption.KeyEncryptor
	dataEncryptor  encryption.DataEncryptor
	metadataPrefix string
}

// New creates an envelope encryptor with the specified key and data encryptors
func New(keyEncryptor encryption.KeyEncryptor, dataEncryptor encryption.DataEncryptor, metadataPrefix string) encryption.EnvelopeEncryptor {
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
