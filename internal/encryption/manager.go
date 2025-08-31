package encryption

import (
	"context"
	"fmt"

	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption"
	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption/providers"
)

// Manager handles encryption operations and key management
type Manager struct {
	encryptor encryption.Encryptor
	config    *Config
}

// Config holds encryption configuration
type Config struct {
	EncryptionType  string
	KEKUri          string
	CredentialsPath string
	AESKey          string
	Algorithm       string
	KeyRotationDays int
}

// NewManager creates a new encryption manager
func NewManager(cfg *Config) (*Manager, error) {
	// Create provider factory
	factory := providers.NewFactory()

	// Create provider configuration
	providerConfig := &providers.ProviderConfig{
		Type:            providers.ProviderType(cfg.EncryptionType),
		AESKey:          cfg.AESKey,
		KEKUri:          cfg.KEKUri,
		CredentialsPath: cfg.CredentialsPath,
	}

	// Validate configuration
	if err := factory.ValidateProviderConfig(providerConfig); err != nil {
		return nil, fmt.Errorf("invalid provider configuration: %w", err)
	}

	// Create encryption provider
	encryptor, err := factory.CreateProvider(providerConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create encryption provider: %w", err)
	}

	return &Manager{
		encryptor: encryptor,
		config:    cfg,
	}, nil
}

// EncryptData encrypts data using the configured encryption method
func (m *Manager) EncryptData(ctx context.Context, data []byte, objectKey string) (*encryption.EncryptionResult, error) {
	// Use object key as associated data for additional security
	associatedData := []byte(objectKey)

	result, err := m.encryptor.Encrypt(ctx, data, associatedData)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt data: %w", err)
	}

	return result, nil
}

// DecryptData decrypts data using envelope encryption
func (m *Manager) DecryptData(ctx context.Context, encryptedData, encryptedDEK []byte, objectKey string) ([]byte, error) {
	// Use object key as associated data
	associatedData := []byte(objectKey)

	plaintext, err := m.encryptor.Decrypt(ctx, encryptedData, encryptedDEK, associatedData)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data: %w", err)
	}

	return plaintext, nil
}

// RotateKEK initiates key rotation
func (m *Manager) RotateKEK(ctx context.Context) error {
	return m.encryptor.RotateKEK(ctx)
}
