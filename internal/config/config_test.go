package config

import (
	"strings"
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

// The listener budgets of ADR 0015. The two body budgets accept 0, which is the
// shipped default and what makes a transfer bounded by the client rather than by
// a server wall clock; the two that bound what is *not* a transfer refuse it.
func TestValidateListenerBudgets(t *testing.T) {
	valid := func() *Config {
		return &Config{
			ReadTimeout:       0,
			WriteTimeout:      0,
			ReadHeaderTimeout: 30,
			IdleTimeout:       60,
		}
	}

	tests := []struct {
		name     string
		mutate   func(*Config)
		errorMsg string
	}{
		{name: "the shipped defaults", mutate: func(*Config) {}},
		{name: "a bounded body budget is allowed", mutate: func(c *Config) { c.ReadTimeout = 600 }},
		{name: "a raised shutdown budget is allowed", mutate: func(c *Config) { c.ShutdownTimeout = 120 }},
		{
			name:     "a negative read budget",
			mutate:   func(c *Config) { c.ReadTimeout = -1 },
			errorMsg: "read_timeout: must not be negative",
		},
		{
			name:     "a negative write budget",
			mutate:   func(c *Config) { c.WriteTimeout = -1 },
			errorMsg: "write_timeout: must not be negative",
		},
		{
			name:     "no header budget leaves the slow-header bound to nothing",
			mutate:   func(c *Config) { c.ReadHeaderTimeout = 0 },
			errorMsg: "read_header_timeout: must be at least 1 second",
		},
		{
			name:     "no idle budget holds a keep-alive connection forever",
			mutate:   func(c *Config) { c.IdleTimeout = 0 },
			errorMsg: "idle_timeout: must be at least 1 second",
		},
		{
			name:     "a negative shutdown budget",
			mutate:   func(c *Config) { c.ShutdownTimeout = -1 },
			errorMsg: "shutdown_timeout: must not be negative",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := valid()
			tt.mutate(cfg)

			err := validateListenerBudgets(cfg)
			if tt.errorMsg == "" {
				if err != nil {
					t.Fatalf("expected the configuration to be accepted, got: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected a refusal naming %q, got none", tt.errorMsg)
			}
			if !strings.Contains(err.Error(), tt.errorMsg) {
				t.Fatalf("the refusal must name the key: want %q in %q", tt.errorMsg, err.Error())
			}
		})
	}
}

// setDefaults is what decides that an operator who configures nothing gets no
// wall clock on a transfer. A default that drifts back to a finite value would
// re-introduce the defect ADR 0015 exists to remove, silently.
func TestListenerBudgetDefaults(t *testing.T) {
	viper.Reset()
	defer viper.Reset()
	setDefaults()

	for key, want := range map[string]int{
		"read_timeout":        0,
		"write_timeout":       0,
		"read_header_timeout": 30,
		"idle_timeout":        60,
	} {
		if got := viper.GetInt(key); got != want {
			t.Errorf("%s: want %d, got %d", key, want, got)
		}
	}
}
