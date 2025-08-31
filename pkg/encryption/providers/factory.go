package providers

import (
	"encoding/json"
	"fmt"

	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption"
)

// ProviderType represents the type of encryption provider
type ProviderType string

const (
	// ProviderTypeNone is a pass-through provider with no encryption
	ProviderTypeNone ProviderType = "none"

	// ProviderTypeAESGCM uses direct AES-256-GCM encryption
	ProviderTypeAESGCM ProviderType = "aes256-gcm"

	// ProviderTypeTink uses Google Tink with envelope encryption
	ProviderTypeTink ProviderType = "tink"
)

// Factory creates encryption providers based on configuration
type Factory struct{}

// NewFactory creates a new provider factory
func NewFactory() *Factory {
	return &Factory{}
}

// CreateProviderFromConfig creates an encryption provider from a raw config map
func (f *Factory) CreateProviderFromConfig(providerType ProviderType, configData map[string]interface{}) (encryption.Encryptor, error) {
	switch providerType {
	case ProviderTypeNone:
		return f.createNoneProviderFromMap(configData)
	case ProviderTypeAESGCM:
		return f.createAESGCMProviderFromMap(configData)
	case ProviderTypeTink:
		return f.createTinkProviderFromMap(configData)
	default:
		return nil, fmt.Errorf("unsupported provider type: %s", providerType)
	}
}

// createNoneProviderFromMap creates a none provider from a config map
func (f *Factory) createNoneProviderFromMap(configData map[string]interface{}) (encryption.Encryptor, error) {
	// None provider doesn't need any configuration
	config := &NoneConfig{}
	return NewNoneProvider(config)
}

// createAESGCMProviderFromMap creates an AES-GCM provider from a config map
func (f *Factory) createAESGCMProviderFromMap(configData map[string]interface{}) (encryption.Encryptor, error) {
	// Convert map to JSON and back to struct for type safety
	jsonData, err := json.Marshal(configData)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal config data: %w", err)
	}

	var config AESGCMConfig
	if err := json.Unmarshal(jsonData, &config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal AES-GCM config: %w", err)
	}

	return NewAESGCMProviderFromConfig(&config)
}

// createTinkProviderFromMap creates a Tink provider from a config map
func (f *Factory) createTinkProviderFromMap(configData map[string]interface{}) (encryption.Encryptor, error) {
	// Convert map to JSON and back to struct for type safety
	jsonData, err := json.Marshal(configData)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal config data: %w", err)
	}

	var config TinkConfig
	if err := json.Unmarshal(jsonData, &config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal Tink config: %w", err)
	}

	return NewTinkProviderFromConfig(&config)
}

// GetSupportedProviders returns a list of supported provider types
func (f *Factory) GetSupportedProviders() []ProviderType {
	return []ProviderType{
		ProviderTypeNone,
		ProviderTypeAESGCM,
		ProviderTypeTink,
	}
}

// ValidateProviderConfig validates a provider configuration
func (f *Factory) ValidateProviderConfig(providerType ProviderType, configData map[string]interface{}) error {
	switch providerType {
	case ProviderTypeNone:
		return f.validateNoneConfig(configData)
	case ProviderTypeAESGCM:
		return f.validateAESGCMConfig(configData)
	case ProviderTypeTink:
		return f.validateTinkConfig(configData)
	default:
		return fmt.Errorf("unsupported provider type: %s", providerType)
	}
}

// validateNoneConfig validates none provider configuration
func (f *Factory) validateNoneConfig(configData map[string]interface{}) error {
	// None provider doesn't require any configuration, so always valid
	return nil
}

// validateAESGCMConfig validates AES-GCM configuration
func (f *Factory) validateAESGCMConfig(configData map[string]interface{}) error {
	// Convert map to JSON and back to struct for validation
	jsonData, err := json.Marshal(configData)
	if err != nil {
		return fmt.Errorf("failed to marshal config data: %w", err)
	}

	var config AESGCMConfig
	if err := json.Unmarshal(jsonData, &config); err != nil {
		return fmt.Errorf("failed to unmarshal AES-GCM config: %w", err)
	}

	return config.Validate()
}

// validateTinkConfig validates Tink configuration
func (f *Factory) validateTinkConfig(configData map[string]interface{}) error {
	// Convert map to JSON and back to struct for validation
	jsonData, err := json.Marshal(configData)
	if err != nil {
		return fmt.Errorf("failed to marshal config data: %w", err)
	}

	var config TinkConfig
	if err := json.Unmarshal(jsonData, &config); err != nil {
		return fmt.Errorf("failed to unmarshal Tink config: %w", err)
	}

	return config.Validate()
}
