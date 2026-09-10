package config

import (
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoad_ValidExitConfig(t *testing.T) {
	// Setup test environment
	viper.Reset()
	setDefaults()

	// Set required configuration values for the exit provider
	viper.Set("s3_backend.target_endpoint", "http://localhost:9000")
	viper.Set("encryption.encryption_method_alias", "way-out")
	viper.Set("encryption.providers", []map[string]interface{}{
		{
			"alias":  "way-out",
			"type":   "exit",
			"config": map[string]interface{}{},
		},
	})

	// Add required S3 client configuration for authentication
	viper.Set("s3_clients", []map[string]interface{}{
		{
			"type":          "static",
			"access_key_id": "testuser123456",
			"secret_key":    "testsecret123456",
			"description":   "Test S3 client for unit tests",
		},
	})

	cfg, err := Load()
	require.NoError(t, err)
	require.NotNil(t, cfg)

	// Test provider configuration
	assert.Equal(t, "way-out", cfg.Encryption.EncryptionMethodAlias)
	assert.Len(t, cfg.Encryption.Providers, 1)

	provider := cfg.Encryption.Providers[0]
	assert.Equal(t, "way-out", provider.Alias)
	assert.Equal(t, "exit", provider.Type)

	// Test provider config (the exit provider takes no configuration)
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
						"aes_key": "ZEsubBlmU+Pr61y+JOwO09c0LOrHs5LITaO0D4JzSZE=",
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

func TestValidateEncryption_ValidAES(t *testing.T) {
	cfg := &Config{
		S3Backend: S3BackendConfig{TargetEndpoint: "http://localhost:9000"},
		Encryption: EncryptionConfig{
			EncryptionMethodAlias: "aes",
			Providers: []EncryptionProvider{
				{
					Alias: "aes",
					Type:  "aes",
					Config: map[string]interface{}{
						"aes_key": "ZEsubBlmU+Pr61y+JOwO09c0LOrHs5LITaO0D4JzSZE=", // base64 encoded 32 bytes
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
		S3Backend: S3BackendConfig{TargetEndpoint: "http://localhost:9000"},
		Encryption: EncryptionConfig{
			EncryptionMethodAlias: "missing",
			Providers: []EncryptionProvider{
				{
					Alias: "default",
					Type:  "aes",
					Config: map[string]interface{}{
						"aes_key": "ZEsubBlmU+Pr61y+JOwO09c0LOrHs5LITaO0D4JzSZE=",
					},
				},
			},
		},
	}

	err := validateEncryption(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "encryption_method_alias 'missing' does not match any provider alias")
}

func TestValidateEncryption_MissingAESKey(t *testing.T) {
	cfg := &Config{
		S3Backend: S3BackendConfig{TargetEndpoint: "http://localhost:9000"},
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
		S3Backend: S3BackendConfig{TargetEndpoint: "http://localhost:9000"},
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
