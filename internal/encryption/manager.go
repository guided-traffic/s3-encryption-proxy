package encryption

import (
	"context"
	"fmt"

	"github.com/guided-traffic/s3-encryption-proxy/internal/config"
	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption"
	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption/factory"
)

// Manager handles encryption operations using the new Factory-based approach
type Manager struct {
	factory           *factory.Factory
	activeFingerprint string // Fingerprint of the active key encryptor
	config            *config.Config
}

// NewManager creates a new encryption manager with the new Factory approach
func NewManager(cfg *config.Config) (*Manager, error) {
	// Create factory instance
	factoryInstance := factory.NewFactory()

	// Get active provider for encryption
	activeProvider, err := cfg.GetActiveProvider()
	if err != nil {
		return nil, fmt.Errorf("failed to get active provider: %w", err)
	}

	// Create key encryptors for all providers and register them with the factory
	allProviders := cfg.GetAllProviders()
	var activeFingerprint string

	for _, provider := range allProviders {
		// Map old provider types to new key encryption types
		var keyType factory.KeyEncryptionType
		switch provider.Type {
		case "aes-gcm", "aes-ctr":
			keyType = factory.KeyEncryptionTypeAES
		case "rsa":
			keyType = factory.KeyEncryptionTypeRSA
		case "none":
			// Skip "none" provider for now - it doesn't use key encryption
			continue
		default:
			return nil, fmt.Errorf("unsupported provider type: %s", provider.Type)
		}

		// Create key encryptor
		keyEncryptor, err := factoryInstance.CreateKeyEncryptorFromConfig(keyType, provider.Config)
		if err != nil {
			return nil, fmt.Errorf("failed to create key encryptor for provider '%s': %w", provider.Alias, err)
		}

		// Register with factory
		factoryInstance.RegisterKeyEncryptor(keyEncryptor)

		// Track the active provider's fingerprint
		if provider.Alias == activeProvider.Alias {
			activeFingerprint = keyEncryptor.Fingerprint()
		}
	}

	if activeFingerprint == "" {
		return nil, fmt.Errorf("active provider '%s' not found or not supported", activeProvider.Alias)
	}

	return &Manager{
		factory:           factoryInstance,
		activeFingerprint: activeFingerprint,
		config:            cfg,
	}, nil
}

// EncryptData encrypts data using the active encryption method with content-type based algorithm selection
func (m *Manager) EncryptData(ctx context.Context, data []byte, objectKey string) (*encryption.EncryptionResult, error) {
	// Use object key as associated data for additional security
	associatedData := []byte(objectKey)

	// Determine content type based on data size (simple heuristic for now)
	contentType := factory.ContentTypeWhole // Default to whole file encryption
	if len(data) > 5*1024*1024 { // For large files > 5MB, could be multipart
		contentType = factory.ContentTypeMultipart
	}

	// Create envelope encryptor with the active key fingerprint
	envelopeEncryptor, err := m.factory.CreateEnvelopeEncryptor(contentType, m.activeFingerprint)
	if err != nil {
		return nil, fmt.Errorf("failed to create envelope encryptor: %w", err)
	}

	// Encrypt data
	encryptedData, encryptedDEK, metadata, err := envelopeEncryptor.EncryptData(ctx, data, associatedData)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt data: %w", err)
	}

	// Create encryption result
	encResult := &encryption.EncryptionResult{
		EncryptedData: encryptedData,
		EncryptedDEK:  encryptedDEK,
		Metadata:      metadata,
	}

	// Add additional metadata
	if encResult.Metadata == nil {
		encResult.Metadata = make(map[string]string)
	}

	// Add provider information for backward compatibility
	activeProvider, err := m.config.GetActiveProvider()
	if err == nil {
		encResult.Metadata["provider_alias"] = activeProvider.Alias
	}

	return encResult, nil
}

// DecryptData decrypts data using metadata to find the correct encryptors
func (m *Manager) DecryptData(ctx context.Context, encryptedData, encryptedDEK []byte, objectKey string, providerAlias string) ([]byte, error) {
	// Use object key as associated data
	associatedData := []byte(objectKey)

	// Try both algorithms since we don't have the metadata from encryption
	algorithms := []string{"aes-256-gcm", "aes-256-ctr"}

	for _, algorithm := range algorithms {
		metadata := map[string]string{
			"kek_fingerprint": m.activeFingerprint,
			"data_algorithm":  algorithm,
		}

		// Try to decrypt using the factory's DecryptData method
		plaintext, err := m.factory.DecryptData(ctx, encryptedData, encryptedDEK, metadata, associatedData)
		if err == nil {
			return plaintext, nil
		}
	}

	return nil, fmt.Errorf("failed to decrypt data with any algorithm")
}

// RotateKEK is not supported in the new Factory-based approach
// Key rotation should be handled externally by updating the configuration
func (m *Manager) RotateKEK(ctx context.Context) error {
	return fmt.Errorf("key rotation not supported in Factory-based approach - update configuration externally")
}

// GetProviderAliases returns all available provider aliases from configuration
func (m *Manager) GetProviderAliases() []string {
	allProviders := m.config.GetAllProviders()
	aliases := make([]string, 0, len(allProviders))
	for _, provider := range allProviders {
		aliases = append(aliases, provider.Alias)
	}
	return aliases
}

// GetProvider returns error since we don't expose individual providers in the new approach
func (m *Manager) GetProvider(alias string) (encryption.EncryptionProvider, bool) {
	// In the new approach, we don't expose individual providers
	// All encryption goes through the Factory
	return nil, false
}

// GetActiveProviderAlias returns the alias of the active provider from configuration
func (m *Manager) GetActiveProviderAlias() string {
	activeProvider, err := m.config.GetActiveProvider()
	if err != nil {
		return ""
	}
	return activeProvider.Alias
}

// Simplified multipart upload methods (not fully implemented)

// InitiateMultipartUpload creates a new multipart upload state
func (m *Manager) InitiateMultipartUpload(ctx context.Context, uploadID, objectKey, bucketName string) error {
	// TODO: Implement multipart upload with new Factory approach
	return fmt.Errorf("multipart upload not implemented in new Factory approach")
}

// UploadPart encrypts and uploads a part of a multipart upload
func (m *Manager) UploadPart(ctx context.Context, uploadID string, partNumber int, data []byte) (*encryption.EncryptionResult, error) {
	// TODO: Implement multipart part upload
	return nil, fmt.Errorf("multipart upload not implemented in new Factory approach")
}

// CompleteMultipartUpload completes a multipart upload
func (m *Manager) CompleteMultipartUpload(ctx context.Context, uploadID string, parts map[int]string) (map[string]string, error) {
	// TODO: Implement multipart completion
	return nil, fmt.Errorf("multipart upload not implemented in new Factory approach")
}

// AbortMultipartUpload aborts a multipart upload
func (m *Manager) AbortMultipartUpload(ctx context.Context, uploadID string) error {
	// TODO: Implement multipart abort
	return fmt.Errorf("multipart upload not implemented in new Factory approach")
}
