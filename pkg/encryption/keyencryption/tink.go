package keyencryption

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/tink"
)

// TinkConfig holds configuration specific to Tink encryption
type TinkConfig struct {
	KEKUri          string `json:"kek_uri" mapstructure:"kek_uri"`                   // Key Encryption Key URI for KMS
	CredentialsPath string `json:"credentials_path" mapstructure:"credentials_path"` // Path to KMS credentials file
	KeyTemplate     string `json:"key_template" mapstructure:"key_template"`         // Optional: Tink key template (defaults to AES256_GCM)
}

// Validate validates the Tink configuration
func (c *TinkConfig) Validate() error {
	if c.KEKUri == "" {
		return fmt.Errorf("kek_uri is required for Tink provider")
	}

	// Validate key template if specified
	if c.KeyTemplate != "" {
		switch c.KeyTemplate {
		case "AES128_GCM", "AES256_GCM", "AES128_CTR_HMAC_SHA256", "AES256_CTR_HMAC_SHA256":
			// Valid templates
		default:
			return fmt.Errorf("unsupported key_template: %s", c.KeyTemplate)
		}
	}

	return nil
}

// NewTinkProviderFromConfig creates a new Tink provider from config
func NewTinkProviderFromConfig(config *TinkConfig) (*TinkProvider, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}

	// Load KEK handle (this would typically come from a KMS)
	kekHandle, err := loadKEKHandle(config.KEKUri, config.CredentialsPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load KEK handle: %w", err)
	}

	return NewTinkProvider(kekHandle, config.KEKUri)
}

// loadKEKHandle loads the Key Encryption Key handle from the specified URI
func loadKEKHandle(_ string, _ string) (*keyset.Handle, error) {
	// This is a simplified implementation
	// In a real scenario, this would:
	// 1. Parse the KEK URI to determine the KMS provider (AWS KMS, GCP KMS, etc.)
	// 2. Initialize the appropriate KMS client using credentialsPath
	// 3. Load the KEK from the KMS

	// For now, we'll create a local handle for testing
	// In production, this should use a proper KMS
	handle, err := keyset.NewHandle(aead.AES256GCMKeyTemplate())
	if err != nil {
		return nil, fmt.Errorf("failed to create local KEK handle: %w", err)
	}

	return handle, nil
}

// TinkProvider implements envelope encryption using Google's Tink library
type TinkProvider struct {
	kekHandle *keyset.Handle
	kekAEAD   tink.AEAD
	kekURI    string // Store the KEK URI for fingerprinting
}

// NewTinkProvider creates a new Tink encryption provider
func NewTinkProvider(kekHandle *keyset.Handle, kekURI string) (*TinkProvider, error) {
	if kekHandle == nil {
		return nil, fmt.Errorf("KEK handle cannot be nil")
	}

	// Get AEAD primitive from KEK handle
	kekAEAD, err := aead.New(kekHandle)
	if err != nil {
		return nil, fmt.Errorf("failed to create KEK AEAD: %w", err)
	}

	return &TinkProvider{
		kekHandle: kekHandle,
		kekAEAD:   kekAEAD,
		kekURI:    kekURI,
	}, nil
}

// EncryptDEK encrypts a Data Encryption Key with the Key Encryption Key using Tink
func (p *TinkProvider) EncryptDEK(_ context.Context, dek []byte) ([]byte, string, error) {
	// Create a DEK handle from the raw DEK bytes
	// For simplicity, we'll use the raw bytes directly with our KEK
	encryptedDEK, err := p.kekAEAD.Encrypt(dek, nil)
	if err != nil {
		return nil, "", fmt.Errorf("failed to encrypt DEK with Tink KEK: %w", err)
	}

	return encryptedDEK, p.Fingerprint(), nil
}

// DecryptDEK decrypts a Data Encryption Key using the Key Encryption Key with Tink
func (p *TinkProvider) DecryptDEK(_ context.Context, encryptedDEK []byte, keyID string) ([]byte, error) {
	// Verify the key ID matches our fingerprint
	if keyID != p.Fingerprint() {
		return nil, fmt.Errorf("key ID mismatch: expected %s, got %s", p.Fingerprint(), keyID)
	}

	// Decrypt the DEK using our KEK
	dek, err := p.kekAEAD.Decrypt(encryptedDEK, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt DEK with Tink KEK: %w", err)
	}

	return dek, nil
}

// Name returns the provider name
func (p *TinkProvider) Name() string {
	return "tink"
}

// Fingerprint returns a SHA-256 fingerprint of the Tink KEK
// This allows identification of the correct KEK provider during decryption
func (p *TinkProvider) Fingerprint() string {
	// Use the KEK URI as the basis for the fingerprint
	// This is safe as it doesn't expose the actual key material
	hash := sha256.Sum256([]byte(p.kekURI))
	return hex.EncodeToString(hash[:])
}

// RotateKEK is not implemented
func (p *TinkProvider) RotateKEK(_ context.Context) error {
	return fmt.Errorf("KEK rotation not implemented")
}
