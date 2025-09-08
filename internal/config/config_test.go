package config

import (
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoad_ValidTinkConfig(t *testing.T) {
	// Setup test environment
	viper.Reset()
	setDefaults()

	// Set required configuration values for Tink
	viper.Set("target_endpoint", "http://localhost:9000")
	viper.Set("encryption.encryption_method_alias", "default")
	viper.Set("encryption.providers", []map[string]interface{}{
		{
			"alias": "default",
			"type":  "tink",
			"config": map[string]interface{}{
				"kek_uri":             "gcp-kms://projects/test-project/locations/global/keyRings/test-ring/cryptoKeys/test-key",
				"algorithm":           "CHACHA20_POLY1305",
				"key_rotation_days":   30,
				"metadata_key_prefix": "custom-prefix-",
				"credentials_path":    "/path/to/credentials",
			},
		},
	})

	cfg, err := Load()
	require.NoError(t, err)
	require.NotNil(t, cfg)

	// Test default values
	assert.Equal(t, "0.0.0.0:8080", cfg.BindAddress)
	assert.Equal(t, "info", cfg.LogLevel)
	assert.Equal(t, "us-east-1", cfg.Region)

	// Test provider configuration
	assert.Equal(t, "default", cfg.Encryption.EncryptionMethodAlias)
	assert.Len(t, cfg.Encryption.Providers, 1)

	provider := cfg.Encryption.Providers[0]
	assert.Equal(t, "default", provider.Alias)
	assert.Equal(t, "tink", provider.Type)

	// Test provider config values
	assert.Equal(t, "gcp-kms://projects/test-project/locations/global/keyRings/test-ring/cryptoKeys/test-key", provider.Config["kek_uri"])
	assert.Equal(t, "CHACHA20_POLY1305", provider.Config["algorithm"])
	assert.Equal(t, 30, provider.Config["key_rotation_days"])
	assert.Equal(t, "custom-prefix-", provider.Config["metadata_key_prefix"])
	assert.Equal(t, "/path/to/credentials", provider.Config["credentials_path"])

	// Test required values
	assert.Equal(t, "http://localhost:9000", cfg.TargetEndpoint)
}

func TestLoad_ValidAESConfig(t *testing.T) {
	// Setup test environment
	viper.Reset()
	setDefaults()

	// Set required configuration values for AES
	viper.Set("target_endpoint", "http://localhost:9000")
	viper.Set("encryption.encryption_method_alias", "aes")
	viper.Set("encryption.providers", []map[string]interface{}{
		{
			"alias": "aes",
			"type":  "aes-gcm",
			"config": map[string]interface{}{
				"aes_key":             "dGVzdC1rZXktMzItYnl0ZXMtZm9yLWFlcy0yNTY=", // base64 encoded 32 bytes
				"algorithm":           "AES256_GCM",
				"metadata_key_prefix": "s3ep-aes-",
			},
		},
	})

	cfg, err := Load()
	require.NoError(t, err)
	require.NotNil(t, cfg)

	// Test provider configuration
	assert.Equal(t, "aes", cfg.Encryption.EncryptionMethodAlias)
	assert.Len(t, cfg.Encryption.Providers, 1)

	provider := cfg.Encryption.Providers[0]
	assert.Equal(t, "aes", provider.Alias)
	assert.Equal(t, "aes-gcm", provider.Type)

	// Test provider config values
	assert.Equal(t, "dGVzdC1rZXktMzItYnl0ZXMtZm9yLWFlcy0yNTY=", provider.Config["aes_key"])
	assert.Equal(t, "AES256_GCM", provider.Config["algorithm"])
	assert.Equal(t, "s3ep-aes-", provider.Config["metadata_key_prefix"])
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
					Type:  "tink",
					Config: map[string]interface{}{
						"kek_uri": "test-kek-uri",
					},
				},
			},
		},
	}

	provider, err := cfg.GetActiveProvider()
	require.NoError(t, err)
	assert.Equal(t, "default", provider.Alias)
	assert.Equal(t, "tink", provider.Type)
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
					Type:  "aes-gcm",
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
					Type:  "aes-gcm",
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
	assert.Equal(t, "aes-gcm", provider.Type)

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
	cfg := &Config{
		TargetEndpoint: "http://localhost:9000",
		Encryption: EncryptionConfig{
			EncryptionMethodAlias: "default",
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

	err := validateEncryption(cfg)
	assert.NoError(t, err)
}

func TestValidateEncryption_ValidAES(t *testing.T) {
	cfg := &Config{
		TargetEndpoint: "http://localhost:9000",
		Encryption: EncryptionConfig{
			EncryptionMethodAlias: "aes",
			Providers: []EncryptionProvider{
				{
					Alias: "aes",
					Type:  "aes-gcm",
					Config: map[string]interface{}{
						"aes_key": "dGVzdC1rZXktMzItYnl0ZXMtZm9yLWFlcy0yNTY=", // base64 encoded 32 bytes
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
					Type:  "tink",
					Config: map[string]interface{}{
						"kek_uri": "test-kek-uri",
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
	cfg := &Config{
		TargetEndpoint: "http://localhost:9000",
		Encryption: EncryptionConfig{
			EncryptionMethodAlias: "default",
			Providers: []EncryptionProvider{
				{
					Alias:  "default",
					Type:   "tink",
					Config: map[string]interface{}{},
				},
			},
		},
	}

	err := validateEncryption(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "kek_uri is required when using tink encryption")
}

func TestValidateEncryption_MissingAESKey(t *testing.T) {
	cfg := &Config{
		TargetEndpoint: "http://localhost:9000",
		Encryption: EncryptionConfig{
			EncryptionMethodAlias: "aes",
			Providers: []EncryptionProvider{
				{
					Alias:  "aes",
					Type:   "aes-gcm",
					Config: map[string]interface{}{},
				},
			},
		},
	}

	err := validateEncryption(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "aes_key is required when using aes-gcm encryption")
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
