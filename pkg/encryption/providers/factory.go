package providers

import (
	"fmt"

	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/keyset"
	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption"
)

// ProviderType represents the type of encryption provider
type ProviderType string

const (
	// ProviderTypeAESGCM uses direct AES-256-GCM encryption
	ProviderTypeAESGCM ProviderType = "aes256-gcm"

	// ProviderTypeTink uses Google Tink with envelope encryption
	ProviderTypeTink ProviderType = "tink"
)

// ProviderConfig holds configuration for creating encryption providers
type ProviderConfig struct {
	Type            ProviderType
	AESKey          string // Base64-encoded key for AES-GCM
	KEKUri          string // URI for KEK in Tink
	CredentialsPath string // Path to credentials for KMS access
}

// Factory creates encryption providers based on configuration
type Factory struct{}

// NewFactory creates a new provider factory
func NewFactory() *Factory {
	return &Factory{}
}

// CreateProvider creates an encryption provider based on the configuration
func (f *Factory) CreateProvider(config *ProviderConfig) (encryption.Encryptor, error) {
	switch config.Type {
	case ProviderTypeAESGCM:
		return f.createAESGCMProvider(config)
	case ProviderTypeTink:
		return f.createTinkProvider(config)
	default:
		return nil, fmt.Errorf("unsupported provider type: %s", config.Type)
	}
}

// createAESGCMProvider creates an AES-GCM encryption provider
func (f *Factory) createAESGCMProvider(config *ProviderConfig) (encryption.Encryptor, error) {
	if config.AESKey == "" {
		return nil, fmt.Errorf("AES key is required for AES-GCM provider")
	}

	provider, err := NewAESGCMProviderFromBase64(config.AESKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES-GCM provider: %w", err)
	}

	return provider, nil
}

// createTinkProvider creates a Tink encryption provider
func (f *Factory) createTinkProvider(config *ProviderConfig) (encryption.Encryptor, error) {
	if config.KEKUri == "" {
		return nil, fmt.Errorf("KEK URI is required for Tink provider")
	}

	// Load KEK handle (this would typically come from a KMS)
	kekHandle, err := f.loadKEKHandle(config.KEKUri, config.CredentialsPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load KEK handle: %w", err)
	}

	provider, err := NewTinkProvider(kekHandle)
	if err != nil {
		return nil, fmt.Errorf("failed to create Tink provider: %w", err)
	}

	return provider, nil
}

// loadKEKHandle loads the Key Encryption Key handle from the specified URI
func (f *Factory) loadKEKHandle(kekUri, credentialsPath string) (*keyset.Handle, error) {
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

// GetSupportedProviders returns a list of supported provider types
func (f *Factory) GetSupportedProviders() []ProviderType {
	return []ProviderType{
		ProviderTypeAESGCM,
		ProviderTypeTink,
	}
}

// ValidateProviderConfig validates a provider configuration
func (f *Factory) ValidateProviderConfig(config *ProviderConfig) error {
	if config == nil {
		return fmt.Errorf("provider config cannot be nil")
	}

	switch config.Type {
	case ProviderTypeAESGCM:
		if config.AESKey == "" {
			return fmt.Errorf("AES key is required for AES-GCM provider")
		}
	case ProviderTypeTink:
		if config.KEKUri == "" {
			return fmt.Errorf("KEK URI is required for Tink provider")
		}
	default:
		return fmt.Errorf("unsupported provider type: %s", config.Type)
	}

	return nil
}
