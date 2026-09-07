package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCfgExpandConfigEnvVarsErrorPerField(t *testing.T) {
	t.Setenv("CFG_PRESENT", "value")

	tests := []struct {
		name        string
		build       func() *Config
		expectError string
	}{
		{
			name: "s3_backend access key id",
			build: func() *Config {
				return &Config{S3Backend: S3BackendConfig{AccessKeyID: "${CFG_MISSING_BACKEND_AK}"}}
			},
			expectError: "s3_backend.access_key_id: environment variable ${CFG_MISSING_BACKEND_AK} is not set or empty",
		},
		{
			name: "s3_backend secret key",
			build: func() *Config {
				return &Config{S3Backend: S3BackendConfig{
					AccessKeyID: "${CFG_PRESENT}",
					SecretKey:   "${CFG_MISSING_BACKEND_SK}",
				}}
			},
			expectError: "s3_backend.secret_key: environment variable ${CFG_MISSING_BACKEND_SK} is not set or empty",
		},
		{
			name: "s3_clients access key id reports its index",
			build: func() *Config {
				return &Config{S3Clients: []S3ClientCredentials{
					{AccessKeyID: "static-key", SecretKey: "${CFG_PRESENT}"},
					{AccessKeyID: "${CFG_MISSING_CLIENT_AK}", SecretKey: "${CFG_PRESENT}"},
				}}
			},
			expectError: "s3_clients[1].access_key_id: environment variable ${CFG_MISSING_CLIENT_AK} is not set or empty",
		},
		{
			name: "s3_clients secret key reports its index",
			build: func() *Config {
				return &Config{S3Clients: []S3ClientCredentials{
					{AccessKeyID: "${CFG_PRESENT}", SecretKey: "${CFG_MISSING_CLIENT_SK}"},
				}}
			},
			expectError: "s3_clients[0].secret_key: environment variable ${CFG_MISSING_CLIENT_SK} is not set or empty",
		},
		{
			name: "provider config reports provider index and key",
			build: func() *Config {
				return &Config{Encryption: EncryptionConfig{Providers: []EncryptionProvider{
					{Alias: "a", Type: "none"},
					{Alias: "b", Type: "aes", Config: map[string]interface{}{"aes_key": "${CFG_MISSING_AES_KEY}"}},
				}}}
			},
			expectError: "encryption.providers[1].config.aes_key: environment variable ${CFG_MISSING_AES_KEY} is not set or empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := tt.build()
			err := expandConfigEnvVars(cfg)
			require.Error(t, err)
			assert.Equal(t, tt.expectError, err.Error())
		})
	}
}

func TestCfgExpandConfigEnvVarsExpandsEveryField(t *testing.T) {
	t.Setenv("CFG_AK", "ak-value")
	t.Setenv("CFG_SK", "sk-value")
	t.Setenv("CFG_CLIENT_AK", "client-ak")
	t.Setenv("CFG_CLIENT_SK", "client-sk")
	t.Setenv("CFG_PEM", "-----BEGIN KEY-----")

	cfg := &Config{
		S3Backend: S3BackendConfig{
			AccessKeyID: "prefix-${CFG_AK}-suffix",
			SecretKey:   "${CFG_SK}",
		},
		S3Clients: []S3ClientCredentials{
			{AccessKeyID: "${CFG_CLIENT_AK}", SecretKey: "${CFG_CLIENT_SK}"},
			{AccessKeyID: "plain", SecretKey: "plain-secret"},
		},
		Encryption: EncryptionConfig{Providers: []EncryptionProvider{
			{Alias: "rsa", Type: "rsa", Config: map[string]interface{}{
				"private_key_pem": "${CFG_PEM}",
				"rotation_days":   90,
				"enabled":         true,
			}},
		}},
	}

	require.NoError(t, expandConfigEnvVars(cfg))

	assert.Equal(t, "prefix-ak-value-suffix", cfg.S3Backend.AccessKeyID)
	assert.Equal(t, "sk-value", cfg.S3Backend.SecretKey)
	assert.Equal(t, "client-ak", cfg.S3Clients[0].AccessKeyID)
	assert.Equal(t, "client-sk", cfg.S3Clients[0].SecretKey)
	assert.Equal(t, "plain", cfg.S3Clients[1].AccessKeyID)
	assert.Equal(t, "plain-secret", cfg.S3Clients[1].SecretKey)
	assert.Equal(t, "-----BEGIN KEY-----", cfg.Encryption.Providers[0].Config["private_key_pem"])
	// Non-string values are passed through untouched.
	assert.Equal(t, 90, cfg.Encryption.Providers[0].Config["rotation_days"])
	assert.Equal(t, true, cfg.Encryption.Providers[0].Config["enabled"])
}
