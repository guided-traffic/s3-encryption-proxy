package encryption

import (
	"context"
	"fmt"

	"github.com/guided-traffic/s3-encryption-proxy/internal/config"
	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption"
	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption/providers"
)

// Manager handles encryption operations and key management with multiple providers
type Manager struct {
	activeEncryptor encryption.Encryptor            // Used for encrypting new data
	decryptors      map[string]encryption.Encryptor // Used for decrypting (keyed by provider alias)
	config          *config.Config
}

// NewManager creates a new encryption manager with multiple provider support
func NewManager(cfg *config.Config) (*Manager, error) {
	// Create provider factory
	factory := providers.NewFactory()

	// Get active provider for encryption
	activeProvider, err := cfg.GetActiveProvider()
	if err != nil {
		return nil, fmt.Errorf("failed to get active provider: %w", err)
	}

	// Create active encryptor
	activeEncryptor, err := factory.CreateProviderFromConfig(
		providers.ProviderType(activeProvider.Type),
		activeProvider.GetProviderConfig(),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create active encryption provider '%s': %w", activeProvider.Alias, err)
	}

	// Create all decryptors
	decryptors := make(map[string]encryption.Encryptor)
	allProviders := cfg.GetAllProviders()

	for _, provider := range allProviders {
		decryptor, err := factory.CreateProviderFromConfig(
			providers.ProviderType(provider.Type),
			provider.GetProviderConfig(),
		)
		if err != nil {
			return nil, fmt.Errorf("failed to create decryption provider '%s': %w", provider.Alias, err)
		}

		decryptors[provider.Alias] = decryptor
	}

	return &Manager{
		activeEncryptor: activeEncryptor,
		decryptors:      decryptors,
		config:          cfg,
	}, nil
}

// EncryptData encrypts data using the active encryption method
func (m *Manager) EncryptData(ctx context.Context, data []byte, objectKey string) (*encryption.EncryptionResult, error) {
	// Use object key as associated data for additional security
	associatedData := []byte(objectKey)

	result, err := m.activeEncryptor.Encrypt(ctx, data, associatedData)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt data: %w", err)
	}

	// Add provider alias to metadata for later decryption
	if result.Metadata == nil {
		result.Metadata = make(map[string]string)
	}
	activeProvider, err := m.config.GetActiveProvider()
	if err == nil {
		result.Metadata["provider_alias"] = activeProvider.Alias
	}

	return result, nil
}

// DecryptData decrypts data using any available provider
func (m *Manager) DecryptData(ctx context.Context, encryptedData, encryptedDEK []byte, objectKey string, providerAlias string) ([]byte, error) {
	// Use object key as associated data
	associatedData := []byte(objectKey)

	// Try the specified provider first (if provided)
	if providerAlias != "" {
		if decryptor, exists := m.decryptors[providerAlias]; exists {
			plaintext, err := decryptor.Decrypt(ctx, encryptedData, encryptedDEK, associatedData)
			if err == nil {
				return plaintext, nil
			}
			// Log the error but continue with other providers
		}
	}

	// Try all providers if specific provider failed or wasn't specified
	var lastErr error
	for _, decryptor := range m.decryptors {
		plaintext, err := decryptor.Decrypt(ctx, encryptedData, encryptedDEK, associatedData)
		if err == nil {
			return plaintext, nil
		}
		lastErr = err
	}

	return nil, fmt.Errorf("failed to decrypt data with any provider (last error: %w)", lastErr)
}

// DecryptDataLegacy decrypts data using the active provider (for backward compatibility)
func (m *Manager) DecryptDataLegacy(ctx context.Context, encryptedData, encryptedDEK []byte, objectKey string) ([]byte, error) {
	return m.DecryptData(ctx, encryptedData, encryptedDEK, objectKey, "")
}

// RotateKEK initiates key rotation for the active provider
func (m *Manager) RotateKEK(ctx context.Context) error {
	return m.activeEncryptor.RotateKEK(ctx)
}

// GetProviderAliases returns all available provider aliases
func (m *Manager) GetProviderAliases() []string {
	aliases := make([]string, 0, len(m.decryptors))
	for alias := range m.decryptors {
		aliases = append(aliases, alias)
	}
	return aliases
}

// GetActiveProviderAlias returns the alias of the active provider
func (m *Manager) GetActiveProviderAlias() string {
	activeProvider, err := m.config.GetActiveProvider()
	if err != nil {
		return "unknown"
	}
	return activeProvider.Alias
}
