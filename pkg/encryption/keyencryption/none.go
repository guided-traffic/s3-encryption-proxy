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
func (n *NoneProvider) EncryptDEK(_ context.Context, dek []byte) ([]byte, error) {
	return dek, nil
}

// DecryptDEK returns the "encrypted" DEK unchanged (no decryption)
func (n *NoneProvider) DecryptDEK(_ context.Context, encryptedDEK []byte) ([]byte, error) {
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
