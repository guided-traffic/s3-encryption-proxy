package providers

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewFactory(t *testing.T) {
	factory := NewFactory()
	assert.NotNil(t, factory)
}

func TestFactory_GetSupportedProviders(t *testing.T) {
	factory := NewFactory()
	providers := factory.GetSupportedProviders()
	assert.Contains(t, providers, ProviderTypeNone)
	assert.Contains(t, providers, ProviderTypeAESGCM)
	assert.Contains(t, providers, ProviderTypeTink)
	assert.Contains(t, providers, ProviderTypeRSAEnvelope)
	assert.Len(t, providers, 4)
}

func TestFactory_CreateProviderFromConfig_None(t *testing.T) {
	factory := NewFactory()
	config := map[string]interface{}{}

	provider, err := factory.CreateProviderFromConfig(ProviderTypeNone, config)
	require.NoError(t, err)
	assert.NotNil(t, provider)

	// Test encryption/decryption
	ctx := context.Background()
	data := []byte("test data")
	associatedData := []byte("test key")

	result, err := provider.Encrypt(ctx, data, associatedData)
	require.NoError(t, err)
	assert.Equal(t, data, result.EncryptedData) // None provider returns data as-is

	decrypted, err := provider.Decrypt(ctx, result.EncryptedData, result.EncryptedDEK, associatedData)
	require.NoError(t, err)
	assert.Equal(t, data, decrypted)
}

func TestFactory_CreateProviderFromConfig_AESGCM(t *testing.T) {
	factory := NewFactory()
	config := map[string]interface{}{
		"aes_key": "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=", // base64 encoded 32-byte key
	}

	provider, err := factory.CreateProviderFromConfig(ProviderTypeAESGCM, config)
	require.NoError(t, err)
	assert.NotNil(t, provider)

	// Test encryption/decryption
	ctx := context.Background()
	data := []byte("test data for AES-GCM")
	associatedData := []byte("test key")

	result, err := provider.Encrypt(ctx, data, associatedData)
	require.NoError(t, err)
	assert.NotEqual(t, data, result.EncryptedData) // Should be encrypted

	decrypted, err := provider.Decrypt(ctx, result.EncryptedData, result.EncryptedDEK, associatedData)
	require.NoError(t, err)
	assert.Equal(t, data, decrypted)
}

func TestFactory_CreateProviderFromConfig_Tink(t *testing.T) {
	factory := NewFactory()
	config := map[string]interface{}{
		"kek_uri": "fake-kms://CM2b3_MDElQKSAowdHlwZS5nb29nbGVhcGlzLmNvbS9nb29nbGUuY3J5cHRvLnRpbmsuQWVzR2NtS2V5EhIa",
	}

	provider, err := factory.CreateProviderFromConfig(ProviderTypeTink, config)
	require.NoError(t, err)
	assert.NotNil(t, provider)

	// Test basic functionality (don't test RotateKEK as it's not implemented for fake KMS)
	ctx := context.Background()
	data := []byte("test data")
	associatedData := []byte("test key")

	result, err := provider.Encrypt(ctx, data, associatedData)
	require.NoError(t, err)
	assert.NotNil(t, result)
}

func TestFactory_CreateProviderFromConfig_UnsupportedType(t *testing.T) {
	factory := NewFactory()
	config := map[string]interface{}{}

	_, err := factory.CreateProviderFromConfig("unsupported", config)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported provider type")
}

func TestFactory_CreateProviderFromConfig_InvalidAESGCMConfig(t *testing.T) {
	factory := NewFactory()
	config := map[string]interface{}{
		"aes_key": "invalid-key", // Invalid base64
	}

	_, err := factory.CreateProviderFromConfig(ProviderTypeAESGCM, config)
	assert.Error(t, err)
}

func TestFactory_CreateProviderFromConfig_MissingAESKey(t *testing.T) {
	factory := NewFactory()
	config := map[string]interface{}{} // Missing aes_key

	_, err := factory.CreateProviderFromConfig(ProviderTypeAESGCM, config)
	assert.Error(t, err)
}

func TestFactory_CreateProviderFromConfig_InvalidTinkConfig(t *testing.T) {
	factory := NewFactory()
	config := map[string]interface{}{} // Missing kek_uri

	_, err := factory.CreateProviderFromConfig(ProviderTypeTink, config)
	assert.Error(t, err)
}

func TestFactory_ValidateProviderConfig_None(t *testing.T) {
	factory := NewFactory()
	config := map[string]interface{}{}

	err := factory.ValidateProviderConfig(ProviderTypeNone, config)
	assert.NoError(t, err) // None provider always valid
}

func TestFactory_ValidateProviderConfig_AESGCM_Valid(t *testing.T) {
	factory := NewFactory()
	config := map[string]interface{}{
		"aes_key": "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=", // base64 32-byte key
	}

	err := factory.ValidateProviderConfig(ProviderTypeAESGCM, config)
	assert.NoError(t, err)
}

func TestFactory_ValidateProviderConfig_AESGCM_Invalid(t *testing.T) {
	factory := NewFactory()
	config := map[string]interface{}{
		"aes_key": "invalid-key",
	}

	err := factory.ValidateProviderConfig(ProviderTypeAESGCM, config)
	assert.Error(t, err)
}

func TestFactory_ValidateProviderConfig_AESGCM_Missing(t *testing.T) {
	factory := NewFactory()
	config := map[string]interface{}{}

	err := factory.ValidateProviderConfig(ProviderTypeAESGCM, config)
	assert.Error(t, err)
}

func TestFactory_ValidateProviderConfig_Tink_Valid(t *testing.T) {
	factory := NewFactory()
	config := map[string]interface{}{
		"kek_uri": "fake-kms://CM2b3_MDElQKSAowdHlwZS5nb29nbGVhcGlzLmNvbS9nb29nbGUuY3J5cHRvLnRpbmsuQWVzR2NtS2V5EhIa",
	}

	err := factory.ValidateProviderConfig(ProviderTypeTink, config)
	assert.NoError(t, err)
}

func TestFactory_ValidateProviderConfig_Tink_Missing(t *testing.T) {
	factory := NewFactory()
	config := map[string]interface{}{}

	err := factory.ValidateProviderConfig(ProviderTypeTink, config)
	assert.Error(t, err)
}

func TestFactory_ValidateProviderConfig_UnsupportedType(t *testing.T) {
	factory := NewFactory()
	config := map[string]interface{}{}

	err := factory.ValidateProviderConfig("unsupported", config)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported provider type")
}

func TestFactory_createNoneProviderFromMap(t *testing.T) {
	factory := NewFactory()
	config := map[string]interface{}{}

	provider, err := factory.createNoneProviderFromMap(config)
	require.NoError(t, err)
	assert.NotNil(t, provider)
}

func TestFactory_createAESGCMProviderFromMap_InvalidJSON(t *testing.T) {
	factory := NewFactory()
	// Create a config that can't be marshaled to JSON
	config := map[string]interface{}{
		"invalid": make(chan int), // channels can't be marshaled
	}

	_, err := factory.createAESGCMProviderFromMap(config)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to marshal config data")
}

func TestFactory_createTinkProviderFromMap_InvalidJSON(t *testing.T) {
	factory := NewFactory()
	// Create a config that can't be marshaled to JSON
	config := map[string]interface{}{
		"invalid": make(chan int), // channels can't be marshaled
	}

	_, err := factory.createTinkProviderFromMap(config)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to marshal config data")
}

func TestFactory_CreateProviderFromConfig_RSAEnvelope(t *testing.T) {
	// Generate test RSA key pair
	privateKey, err := GenerateRSAKeyPair(2048)
	require.NoError(t, err)

	privateKeyPEM, publicKeyPEM, err := RSAKeyPairToPEM(privateKey)
	require.NoError(t, err)

	factory := NewFactory()
	config := map[string]interface{}{
		"public_key_pem":  publicKeyPEM,
		"private_key_pem": privateKeyPEM,
		"key_size":        2048,
	}

	provider, err := factory.CreateProviderFromConfig(ProviderTypeRSAEnvelope, config)
	require.NoError(t, err)
	assert.NotNil(t, provider)

	// Test encryption/decryption
	ctx := context.Background()
	data := []byte("test data")
	associatedData := []byte("test key")

	result, err := provider.Encrypt(ctx, data, associatedData)
	require.NoError(t, err)
	assert.NotEqual(t, data, result.EncryptedData) // Should be encrypted
	assert.NotNil(t, result.EncryptedDEK)          // Should have encrypted DEK

	decrypted, err := provider.Decrypt(ctx, result.EncryptedData, result.EncryptedDEK, associatedData)
	require.NoError(t, err)
	assert.Equal(t, data, decrypted)
}

func TestFactory_CreateProviderFromConfig_RSAEnvelope_InvalidConfig(t *testing.T) {
	factory := NewFactory()
	config := map[string]interface{}{
		"public_key_pem": "invalid-key-data",
		// Missing private_key_pem
	}

	_, err := factory.CreateProviderFromConfig(ProviderTypeRSAEnvelope, config)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "private_key_pem is required")
}

func TestFactory_ValidateProviderConfig_RSAEnvelope_Valid(t *testing.T) {
	// Generate test RSA key pair
	privateKey, err := GenerateRSAKeyPair(2048)
	require.NoError(t, err)

	privateKeyPEM, publicKeyPEM, err := RSAKeyPairToPEM(privateKey)
	require.NoError(t, err)

	factory := NewFactory()
	config := map[string]interface{}{
		"public_key_pem":  publicKeyPEM,
		"private_key_pem": privateKeyPEM,
		"key_size":        2048,
	}

	err = factory.ValidateProviderConfig(ProviderTypeRSAEnvelope, config)
	assert.NoError(t, err)
}

func TestFactory_ValidateProviderConfig_RSAEnvelope_Invalid(t *testing.T) {
	factory := NewFactory()
	config := map[string]interface{}{
		"public_key_pem": "invalid-key-data",
		// Missing private_key_pem
	}

	err := factory.ValidateProviderConfig(ProviderTypeRSAEnvelope, config)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "private_key_pem is required")
}

func TestFactory_ValidateProviderConfig_RSAEnvelope_Missing(t *testing.T) {
	factory := NewFactory()
	config := map[string]interface{}{
		// Missing required fields
	}

	err := factory.ValidateProviderConfig(ProviderTypeRSAEnvelope, config)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "public_key_pem is required")
}

func TestFactory_createRSAEnvelopeProviderFromMap_InvalidJSON(t *testing.T) {
	factory := NewFactory()
	// Create a config that can't be marshaled to JSON
	config := map[string]interface{}{
		"invalid": make(chan int), // channels can't be marshaled
	}

	_, err := factory.createRSAEnvelopeProviderFromMap(config)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to marshal config data")
}
