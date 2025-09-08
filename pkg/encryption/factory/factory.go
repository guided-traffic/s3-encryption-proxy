package factory

import (
	"encoding/json"
	"fmt"

	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption"
	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption/dataencryption"
	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption/keyencryption"
	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption/meta"
)

// ProviderType represents the type of encryption provider
type ProviderType string

const (
	// Meta Provider
	ProviderTypeNone ProviderType = "none"

	// Data Encryption Providers
	ProviderTypeAESGCM ProviderType = "aes-gcm"
	ProviderTypeAESCTR ProviderType = "aes-ctr"

	// Key Encryption Providers
	ProviderTypeAES         ProviderType = "aes-envelope"
	ProviderTypeTink        ProviderType = "tink"
	ProviderTypeRSAEnvelope ProviderType = "rsa-envelope"
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
	// Meta Provider
	case ProviderTypeNone:
		return f.createNoneProviderFromMap(configData)

	// Data Encryption Providers
	case ProviderTypeAESGCM:
		return f.createAESGCMProviderFromMap(configData)
	case ProviderTypeAESCTR:
		return f.createAESCTRProviderFromMap(configData)

	// Key Encryption Providers
	case ProviderTypeAES:
		return f.createAESEnvelopeProviderFromMap(configData)
	case ProviderTypeTink:
		return f.createTinkProviderFromMap(configData)
	case ProviderTypeRSAEnvelope:
		return f.createRSAProviderFromMap(configData)

	default:
		return nil, fmt.Errorf("unsupported provider type: %s", providerType)
	}
}

// Meta Provider Methods

func (f *Factory) createNoneProviderFromMap(configData map[string]interface{}) (encryption.Encryptor, error) {
	// None provider doesn't need configuration validation
	if err := f.validateNoneConfig(configData); err != nil {
		return nil, err
	}

	config := &meta.NoneConfig{}
	return meta.NewNoneProvider(config)
}

func (f *Factory) validateNoneConfig(configData map[string]interface{}) error {
	// None provider accepts any configuration (or no configuration)
	return nil
}

// Data Encryption Provider Methods

func (f *Factory) createAESGCMProviderFromMap(configData map[string]interface{}) (encryption.Encryptor, error) {
	if err := f.validateAESGCMConfig(configData); err != nil {
		return nil, err
	}

	config := &dataencryption.AESGCMConfig{}
	if err := f.mapToStruct(configData, config); err != nil {
		return nil, fmt.Errorf("failed to parse AES-GCM config: %w", err)
	}

	return dataencryption.NewAESGCMProviderFromConfig(config)
}

func (f *Factory) validateAESGCMConfig(configData map[string]interface{}) error {
	if _, exists := configData["aes_key"]; !exists {
		return fmt.Errorf("aes_key is required for AES-GCM provider")
	}
	return nil
}

func (f *Factory) createAESCTRProviderFromMap(configData map[string]interface{}) (encryption.Encryptor, error) {
	if err := f.validateAESCTRConfig(configData); err != nil {
		return nil, err
	}

	config := &dataencryption.AESCTRConfig{}
	if err := f.mapToStruct(configData, config); err != nil {
		return nil, fmt.Errorf("failed to parse AES-CTR config: %w", err)
	}

	return dataencryption.NewAESCTRProviderFromConfig(config)
}

func (f *Factory) validateAESCTRConfig(configData map[string]interface{}) error {
	if _, exists := configData["aes_key"]; !exists {
		return fmt.Errorf("aes_key is required for AES-CTR provider")
	}
	return nil
}

// Key Encryption Provider Methods

func (f *Factory) createTinkProviderFromMap(configData map[string]interface{}) (encryption.Encryptor, error) {
	if err := f.validateTinkConfig(configData); err != nil {
		return nil, err
	}

	config := &keyencryption.TinkConfig{}
	if err := f.mapToStruct(configData, config); err != nil {
		return nil, fmt.Errorf("failed to parse Tink config: %w", err)
	}

	return keyencryption.NewTinkProviderFromConfig(config)
}

func (f *Factory) validateTinkConfig(configData map[string]interface{}) error {
	if _, exists := configData["kek_uri"]; !exists {
		return fmt.Errorf("kek_uri is required for Tink provider")
	}
	return nil
}

func (f *Factory) createRSAProviderFromMap(configData map[string]interface{}) (encryption.Encryptor, error) {
	if err := f.validateRSAConfig(configData); err != nil {
		return nil, err
	}

	config := &keyencryption.RSAConfig{}
	if err := f.mapToStruct(configData, config); err != nil {
		return nil, fmt.Errorf("failed to parse RSA config: %w", err)
	}

	return keyencryption.NewRSAProviderFromConfig(config)
}

func (f *Factory) validateRSAConfig(configData map[string]interface{}) error {
	if _, exists := configData["public_key_pem"]; !exists {
		return fmt.Errorf("public_key_pem is required for RSA envelope provider")
	}
	if _, exists := configData["private_key_pem"]; !exists {
		return fmt.Errorf("private_key_pem is required for RSA envelope provider")
	}
	return nil
}

func (f *Factory) createAESEnvelopeProviderFromMap(configData map[string]interface{}) (encryption.Encryptor, error) {
	if err := f.validateAESEnvelopeConfig(configData); err != nil {
		return nil, err
	}

	// Convert aes_key to key for the AESProvider constructor
	if aesKey, exists := configData["aes_key"]; exists {
		providerConfig := map[string]interface{}{
			"key": aesKey,
		}
		return keyencryption.NewAESProvider(providerConfig)
	}

	return nil, fmt.Errorf("aes_key not found in configuration")
}

func (f *Factory) validateAESEnvelopeConfig(configData map[string]interface{}) error {
	if _, exists := configData["aes_key"]; !exists {
		return fmt.Errorf("aes_key is required for AES envelope provider")
	}
	return nil
}

// Helper Methods

// mapToStruct converts a map to a struct using JSON marshaling/unmarshaling
func (f *Factory) mapToStruct(data map[string]interface{}, target interface{}) error {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marshal config data: %w", err)
	}

	err = json.Unmarshal(jsonData, target)
	if err != nil {
		return fmt.Errorf("failed to unmarshal config data: %w", err)
	}

	return nil
}

// GetSupportedProviderTypes returns a list of all supported provider types
func (f *Factory) GetSupportedProviderTypes() []ProviderType {
	return []ProviderType{
		ProviderTypeNone,
		ProviderTypeAESGCM,
		ProviderTypeAESCTR,
		ProviderTypeAES,
		ProviderTypeTink,
		ProviderTypeRSAEnvelope,
	}
}

// IsProviderTypeSupported checks if a provider type is supported
func (f *Factory) IsProviderTypeSupported(providerType ProviderType) bool {
	supportedTypes := f.GetSupportedProviderTypes()
	for _, supported := range supportedTypes {
		if supported == providerType {
			return true
		}
	}
	return false
}
