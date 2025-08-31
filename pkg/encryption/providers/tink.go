package providers

import (
	"context"
	"fmt"
	"io"

	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/tink"

	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption"
)

// TinkProvider implements envelope encryption using Google's Tink library
type TinkProvider struct {
	kekAEAD tink.AEAD
}

// NewTinkProvider creates a new Tink encryption provider
func NewTinkProvider(kekHandle *keyset.Handle) (*TinkProvider, error) {
	if kekHandle == nil {
		return nil, fmt.Errorf("KEK handle cannot be nil")
	}

	// Get AEAD primitive from KEK handle
	kekAEAD, err := aead.New(kekHandle)
	if err != nil {
		return nil, fmt.Errorf("failed to create KEK AEAD: %w", err)
	}

	return &TinkProvider{
		kekAEAD: kekAEAD,
	}, nil
}

// Encrypt implements envelope encryption using Tink
func (p *TinkProvider) Encrypt(ctx context.Context, data []byte, associatedData []byte) (*encryption.EncryptionResult, error) {
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
	err = dekHandle.Write(writer, p.kekAEAD)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt DEK: %w", err)
	}
	encryptedDEK := buf.Bytes()

	return &encryption.EncryptionResult{
		EncryptedData: encryptedData,
		EncryptedDEK:  encryptedDEK,
		Metadata: map[string]string{
			"algorithm": "envelope-aes256-gcm",
			"version":   "1.0",
		},
	}, nil
}

// Decrypt implements envelope decryption using Tink
func (p *TinkProvider) Decrypt(ctx context.Context, encryptedData []byte, encryptedDEK []byte, associatedData []byte) ([]byte, error) {
	if encryptedDEK == nil {
		return nil, fmt.Errorf("encrypted DEK is required for envelope decryption")
	}

	// Deserialize and decrypt DEK
	reader := keyset.NewBinaryReader(&memoryReader{data: encryptedDEK})
	dekHandle, err := keyset.Read(reader, p.kekAEAD)
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
func (p *TinkProvider) RotateKEK(ctx context.Context) error {
	// In a real implementation, this would:
	// 1. Generate a new KEK in the KMS
	// 2. Re-encrypt all DEKs with the new KEK
	// 3. Update the KEK reference
	return fmt.Errorf("KEK rotation not implemented in this version")
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
