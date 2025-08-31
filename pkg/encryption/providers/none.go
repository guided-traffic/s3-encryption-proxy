package providers

import (
	"context"

	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption"
)

// NoneProvider is a pass-through provider that doesn't encrypt data
// This is useful for testing or when encryption is handled elsewhere
type NoneProvider struct{}

// NoneConfig represents the configuration for the none provider
type NoneConfig struct {
	// No configuration needed for pass-through
}

// NewNoneProvider creates a new none encryption provider
func NewNoneProvider(config *NoneConfig) (*NoneProvider, error) {
	return &NoneProvider{}, nil
}

// Encrypt passes through the data without encryption
// Returns the original data as both encrypted data and "DEK"
func (p *NoneProvider) Encrypt(ctx context.Context, plaintext, associatedData []byte) (*encryption.EncryptionResult, error) {
	return &encryption.EncryptionResult{
		EncryptedData: plaintext, // Pass through unchanged
		EncryptedDEK:  []byte{},  // Empty DEK since no encryption
		Metadata: map[string]string{
			"algorithm":     "none",
			"provider_type": "none",
		},
	}, nil
}

// Decrypt passes through the data without decryption
// Since no encryption was applied, just return the "encrypted" data
func (p *NoneProvider) Decrypt(ctx context.Context, encryptedData, encryptedDEK, associatedData []byte) ([]byte, error) {
	// No decryption needed, return the data as-is
	return encryptedData, nil
}

// RotateKEK is a no-op for the none provider
func (p *NoneProvider) RotateKEK(ctx context.Context) error {
	// No keys to rotate
	return nil
}
