package config

import (
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoad_ValidTinkConfig(t *testing.T) {
	t.Skip("Tink encryption is not yet implemented with the new architecture")
}

func TestLoad_ValidNoneConfig(t *testing.T) {
	// Setup test environment
	viper.Reset()
	setDefaults()

	// Set required configuration values for None provider
	viper.Set("target_endpoint", "http://localhost:9000")
	viper.Set("encryption.encryption_method_alias", "none")
	viper.Set("encryption.providers", []map[string]interface{}{
		{
			"alias": "none",
			"type":  "none",
			"config": map[string]interface{}{},
		},
	})

	cfg, err := Load()
	require.NoError(t, err)
	require.NotNil(t, cfg)

	// Test provider configuration
	assert.Equal(t, "none", cfg.Encryption.EncryptionMethodAlias)
	assert.Len(t, cfg.Encryption.Providers, 1)

	provider := cfg.Encryption.Providers[0]
	assert.Equal(t, "none", provider.Alias)
	assert.Equal(t, "none", provider.Type)

	// Test provider config (none provider has empty config)
	assert.Empty(t, provider.Config)
}

func TestLoad_MissingTargetEndpoint(t *testing.T) {
	viper.Reset()
	setDefaults()

	// Set providers but not target endpoint
	viper.Set("encryption.providers", []map[string]interface{}{
		{
			"alias": "default",
			"type":  "tink",
			"config": map[string]interface{}{
				"kek_uri": "gcp-kms://projects/test-project/locations/global/keyRings/test-ring/cryptoKeys/test-key",
			},
		},
	})

	cfg, err := Load()
	assert.Error(t, err)
	assert.Nil(t, cfg)
	assert.Contains(t, err.Error(), "target_endpoint is required")
}

func TestGetActiveProvider(t *testing.T) {
	cfg := &Config{
		Encryption: EncryptionConfig{
			EncryptionMethodAlias: "default",
			Providers: []EncryptionProvider{
				{
					Alias: "default",
					Type:  "aes",
					Config: map[string]interface{}{
						"aes_key": "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=",
					},
				},
			},
		},
	}

	provider, err := cfg.GetActiveProvider()
	require.NoError(t, err)
	assert.Equal(t, "default", provider.Alias)
	assert.Equal(t, "aes", provider.Type)
}

func TestGetActiveProvider_NoAlias(t *testing.T) {
	cfg := &Config{
		Encryption: EncryptionConfig{
			Providers: []EncryptionProvider{
				{
					Alias: "first",
					Type:  "tink",
					Config: map[string]interface{}{
						"kek_uri": "test-kek-uri",
					},
				},
			},
		},
	}

	// Should fail when no encryption_method_alias is set but providers are configured
	_, err := cfg.GetActiveProvider()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "encryption_method_alias is required")
}

func TestGetActiveProvider_NotFound(t *testing.T) {
	cfg := &Config{
		Encryption: EncryptionConfig{
			EncryptionMethodAlias: "missing",
			Providers: []EncryptionProvider{
				{
					Alias: "default",
					Type:  "tink",
					Config: map[string]interface{}{
						"kek_uri": "test-kek-uri",
					},
				},
			},
		},
	}

	provider, err := cfg.GetActiveProvider()
	assert.Error(t, err)
	assert.Nil(t, provider)
	assert.Contains(t, err.Error(), "active encryption provider 'missing' not found")
}

func TestGetAllProviders(t *testing.T) {
	cfg := &Config{
		Encryption: EncryptionConfig{
			Providers: []EncryptionProvider{
				{
					Alias: "tink",
					Type:  "tink",
					Config: map[string]interface{}{
						"kek_uri": "test-kek-uri",
					},
				},
				{
					Alias: "aes",
					Type:  "aes",
					Config: map[string]interface{}{
						"aes_key": "test-aes-key",
					},
				},
			},
		},
	}

	providers := cfg.GetAllProviders()
	assert.Len(t, providers, 2)
	assert.Equal(t, "tink", providers[0].Alias)
	assert.Equal(t, "aes", providers[1].Alias)
}

func TestGetProviderByAlias(t *testing.T) {
	cfg := &Config{
		Encryption: EncryptionConfig{
			Providers: []EncryptionProvider{
				{
					Alias: "tink",
					Type:  "tink",
					Config: map[string]interface{}{
						"kek_uri": "test-kek-uri",
					},
				},
				{
					Alias: "aes",
					Type:  "aes",
					Config: map[string]interface{}{
						"aes_key": "test-aes-key",
					},
				},
			},
		},
	}

	provider, err := cfg.GetProviderByAlias("aes")
	require.NoError(t, err)
	assert.Equal(t, "aes", provider.Alias)
	assert.Equal(t, "aes", provider.Type)

	_, err = cfg.GetProviderByAlias("missing")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "encryption provider with alias 'missing' not found")
}

func TestProviderGetConfig(t *testing.T) {
	provider := &EncryptionProvider{
		Alias: "test",
		Type:  "tink",
		Config: map[string]interface{}{
			"kek_uri":   "test-uri",
			"algorithm": "AES256_GCM",
		},
	}

	config := provider.GetProviderConfig()
	assert.Equal(t, "test-uri", config["kek_uri"])
	assert.Equal(t, "AES256_GCM", config["algorithm"])
}

func TestProviderGetConfig_NilConfig(t *testing.T) {
	provider := &EncryptionProvider{
		Alias:  "test",
		Type:   "tink",
		Config: nil,
	}

	config := provider.GetProviderConfig()
	assert.NotNil(t, config)
	assert.NotNil(t, provider.Config) // Should initialize
}

func TestValidateEncryption_ValidTink(t *testing.T) {
	t.Skip("Tink encryption is not yet implemented with the new architecture")
}

func TestValidateEncryption_ValidAES(t *testing.T) {
	cfg := &Config{
		TargetEndpoint: "http://localhost:9000",
		Encryption: EncryptionConfig{
			EncryptionMethodAlias: "aes",
			Providers: []EncryptionProvider{
				{
					Alias: "aes",
					Type:  "aes",
					Config: map[string]interface{}{
						"aes_key": "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=", // base64 encoded 32 bytes
					},
				},
			},
		},
	}

	err := validateEncryption(cfg)
	assert.NoError(t, err)
}

func TestValidateEncryption_MissingActiveProvider(t *testing.T) {
	cfg := &Config{
		TargetEndpoint: "http://localhost:9000",
		Encryption: EncryptionConfig{
			EncryptionMethodAlias: "missing",
			Providers: []EncryptionProvider{
				{
					Alias: "default",
					Type:  "aes",
					Config: map[string]interface{}{
						"aes_key": "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=",
					},
				},
			},
		},
	}

	err := validateEncryption(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "encryption_method_alias 'missing' does not match any provider alias")
}

func TestValidateEncryption_MissingTinkKEK(t *testing.T) {
	t.Skip("Tink encryption is not yet implemented with the new architecture")
}

func TestValidateEncryption_MissingAESKey(t *testing.T) {
	cfg := &Config{
		TargetEndpoint: "http://localhost:9000",
		Encryption: EncryptionConfig{
			EncryptionMethodAlias: "aes",
			Providers: []EncryptionProvider{
				{
					Alias:  "aes",
					Type:   "aes",
					Config: map[string]interface{}{},
				},
			},
		},
	}

	err := validateEncryption(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "aes_key is required when using aes encryption")
}

func TestValidateEncryption_UnsupportedType(t *testing.T) {
	cfg := &Config{
		TargetEndpoint: "http://localhost:9000",
		Encryption: EncryptionConfig{
			EncryptionMethodAlias: "default",
			Providers: []EncryptionProvider{
				{
					Alias:  "default",
					Type:   "unsupported",
					Config: map[string]interface{}{},
				},
			},
		},
	}

	err := validateEncryption(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported encryption type: unsupported")
}
