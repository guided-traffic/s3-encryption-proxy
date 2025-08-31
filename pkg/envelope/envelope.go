package envelope

import (
	"context"
	"fmt"
	"io"

	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/tink"

	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption"
)

// TinkEncryptor implements envelope encryption using Google's Tink library
type TinkEncryptor struct {
	kekAEAD tink.AEAD
}

// NewTinkEncryptor creates a new TinkEncryptor instance
func NewTinkEncryptor(kekHandle *keyset.Handle, template *keyset.Handle) (*TinkEncryptor, error) {
	if kekHandle == nil {
		return nil, fmt.Errorf("KEK handle cannot be nil")
	}

	// Get AEAD primitive from KEK handle
	kekAEAD, err := aead.New(kekHandle)
	if err != nil {
		return nil, fmt.Errorf("failed to create KEK AEAD: %w", err)
	}

	return &TinkEncryptor{
		kekAEAD: kekAEAD,
	}, nil
}

// Encrypt implements envelope encryption
func (e *TinkEncryptor) Encrypt(ctx context.Context, data []byte, associatedData []byte) (*encryption.EncryptionResult, error) {
	// Generate a new DEK using AES256-GCM template
	dekHandle, err := keyset.NewHandle(aead.AES256GCMKeyTemplate())
	if err != nil {
		return nil, fmt.Errorf("failed to generate DEK: %w", err)
	}

	// Get AEAD primitive from DEK
	dekAEAD, err := aead.New(dekHandle)
	if err != nil {
		return nil, fmt.Errorf("failed to create DEK AEAD: %w", err)
	}

	// Encrypt data with DEK
	encryptedData, err := dekAEAD.Encrypt(data, associatedData)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt data: %w", err)
	}

	// Serialize DEK and encrypt it with KEK
	buf := &memoryWriter{}
	writer := keyset.NewBinaryWriter(buf)
	err = dekHandle.Write(writer, e.kekAEAD)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt DEK: %w", err)
	}
	encryptedDEK := buf.Bytes()

	return &encryption.EncryptionResult{
		EncryptedData: encryptedData,
		EncryptedDEK:  encryptedDEK,
		Metadata: map[string]string{
			"algorithm": "envelope-aes-gcm",
			"version":   "1.0",
		},
	}, nil
}

// Decrypt implements envelope decryption
func (e *TinkEncryptor) Decrypt(ctx context.Context, encryptedData []byte, encryptedDEK []byte, associatedData []byte) ([]byte, error) {
	// Deserialize and decrypt DEK
	reader := keyset.NewBinaryReader(&memoryReader{data: encryptedDEK})
	dekHandle, err := keyset.Read(reader, e.kekAEAD)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt DEK: %w", err)
	}

	// Get AEAD primitive from DEK
	dekAEAD, err := aead.New(dekHandle)
	if err != nil {
		return nil, fmt.Errorf("failed to create DEK AEAD: %w", err)
	}

	// Decrypt data with DEK
	plaintext, err := dekAEAD.Decrypt(encryptedData, associatedData)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data: %w", err)
	}

	return plaintext, nil
}

// RotateKEK rotates the Key Encryption Key
func (e *TinkEncryptor) RotateKEK(ctx context.Context) error {
	// KEK rotation would typically involve:
	// 1. Creating a new KEK version
	// 2. Re-encrypting DEKs with the new KEK (background process)
	// 3. Updating the active KEK reference

	// This is a placeholder implementation
	// In a real implementation, this would involve coordination with the key management system
	return fmt.Errorf("KEK rotation not implemented yet")
}

// memoryWriter implements io.Writer for in-memory operations
type memoryWriter struct {
	data []byte
}

func (w *memoryWriter) Write(p []byte) (int, error) {
	w.data = append(w.data, p...)
	return len(p), nil
}

func (w *memoryWriter) Bytes() []byte {
	return w.data
}

// memoryReader implements io.Reader for in-memory operations
type memoryReader struct {
	data []byte
	pos  int
}

func (r *memoryReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	n := copy(p, r.data[r.pos:])
	r.pos += n
	return n, nil
}
