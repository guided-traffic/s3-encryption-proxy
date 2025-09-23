package keyencryption

import (
	"context"

	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption"
)

// NoneProvider implements encryption.KeyEncryptor for pass-through scenarios
// This provider returns data unchanged and is intended for testing or transition scenarios
type NoneProvider struct{}

// NewNoneProvider creates a new None key encryptor that provides no encryption
func NewNoneProvider(_ map[string]interface{}) (encryption.KeyEncryptor, error) {
	return &NoneProvider{}, nil
}

// EncryptDEK returns the DEK unchanged (no encryption)
func (n *NoneProvider) EncryptDEK(_ context.Context, dek []byte) ([]byte, string, error) {
	// Return DEK as-is, with no key ID needed for decryption
	return dek, "", nil
}

// DecryptDEK returns the "encrypted" DEK unchanged (no decryption)
func (n *NoneProvider) DecryptDEK(_ context.Context, encryptedDEK []byte, _ string) ([]byte, error) {
	// Return "encrypted" DEK as-is
	return encryptedDEK, nil
}

// Name returns the provider name
func (n *NoneProvider) Name() string {
	return "none"
}

// Fingerprint returns a consistent fingerprint for the none provider
func (n *NoneProvider) Fingerprint() string {
	// Use a consistent fingerprint for all none providers
	return "none-provider-fingerprint"
}

// RotateKEK is a no-op for none provider as there are no keys to rotate
func (n *NoneProvider) RotateKEK(_ context.Context) error {
	// No-op: none provider has no keys to rotate
	return nil
}
