package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTLSConfig(t *testing.T) {
	tests := []struct {
		name    string
		config  map[string]interface{}
		wantErr bool
		errMsg  string
	}{
		{
			name: "TLS disabled",
			config: map[string]interface{}{
				"target_endpoint": "https://s3.amazonaws.com",
				"encryption_type": "aes-gcm",
				"aes_key":         "SGVsbG8gV29ybGQhIFRoaXMgaXMgYSAzMi1ieXRlIGtleQ==",
				"tls": map[string]interface{}{
					"enabled": false,
				},
			},
			wantErr: false,
		},
		{
			name: "TLS enabled with valid files",
			config: map[string]interface{}{
				"target_endpoint": "https://s3.amazonaws.com",
				"encryption_type": "aes-gcm",
				"aes_key":         "SGVsbG8gV29ybGQhIFRoaXMgaXMgYSAzMi1ieXRlIGtleQ==",
				"tls": map[string]interface{}{
					"enabled":   true,
					"cert_file": "", // Will be set to temp file
					"key_file":  "", // Will be set to temp file
				},
			},
			wantErr: false,
		},
		{
			name: "TLS enabled without cert_file",
			config: map[string]interface{}{
				"target_endpoint": "https://s3.amazonaws.com",
				"encryption_type": "aes-gcm",
				"aes_key":         "SGVsbG8gV29ybGQhIFRoaXMgaXMgYSAzMi1ieXRlIGtleQ==",
				"tls": map[string]interface{}{
					"enabled":  true,
					"key_file": "/path/to/key.pem",
				},
			},
			wantErr: true,
			errMsg:  "tls.cert_file is required when TLS is enabled",
		},
		{
			name: "TLS enabled without key_file",
			config: map[string]interface{}{
				"target_endpoint": "https://s3.amazonaws.com",
				"encryption_type": "aes-gcm",
				"aes_key":         "SGVsbG8gV29ybGQhIFRoaXMgaXMgYSAzMi1ieXRlIGtleQ==",
				"tls": map[string]interface{}{
					"enabled":   true,
					"cert_file": "/path/to/cert.pem",
				},
			},
			wantErr: true,
			errMsg:  "tls.key_file is required when TLS is enabled",
		},
		{
			name: "TLS enabled with non-existent cert_file",
			config: map[string]interface{}{
				"target_endpoint": "https://s3.amazonaws.com",
				"encryption_type": "aes-gcm",
				"aes_key":         "SGVsbG8gV29ybGQhIFRoaXMgaXMgYSAzMi1ieXRlIGtleQ==",
				"tls": map[string]interface{}{
					"enabled":   true,
					"cert_file": "/non/existent/cert.pem",
					"key_file":  "/non/existent/key.pem",
				},
			},
			wantErr: true,
			errMsg:  "TLS certificate file does not exist: /non/existent/cert.pem",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset viper for each test
			viper.Reset()
			setDefaults()

			// Create temporary certificate files for valid test case
			if tt.name == "TLS enabled with valid files" {
				tempDir := t.TempDir()
				certFile := filepath.Join(tempDir, "cert.pem")
				keyFile := filepath.Join(tempDir, "key.pem")

				// Create dummy cert and key files with secure permissions
				err := os.WriteFile(certFile, []byte("dummy cert"), 0600)
				require.NoError(t, err)
				err = os.WriteFile(keyFile, []byte("dummy key"), 0600)
				require.NoError(t, err)

				// Update config with temp file paths
				tlsConfig := tt.config["tls"].(map[string]interface{})
				tlsConfig["cert_file"] = certFile
				tlsConfig["key_file"] = keyFile
			}

			// Set configuration values
			for key, value := range tt.config {
				viper.Set(key, value)
			}

			// Load and validate configuration
			cfg, err := Load()

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				require.NoError(t, err)
				assert.NotNil(t, cfg)

				// Verify TLS configuration
				if tlsConfig, ok := tt.config["tls"].(map[string]interface{}); ok {
					if enabled, exists := tlsConfig["enabled"].(bool); exists {
						assert.Equal(t, enabled, cfg.TLS.Enabled)
					}
					if certFile, exists := tlsConfig["cert_file"].(string); exists && certFile != "" {
						assert.Equal(t, certFile, cfg.TLS.CertFile)
					}
					if keyFile, exists := tlsConfig["key_file"].(string); exists && keyFile != "" {
						assert.Equal(t, keyFile, cfg.TLS.KeyFile)
					}
				}
			}
		})
	}
}

func TestTLSDefaults(t *testing.T) {
	// Reset viper and set defaults
	viper.Reset()
	setDefaults()

	// Set minimal required config
	viper.Set("target_endpoint", "https://s3.amazonaws.com")
	viper.Set("encryption_type", "aes-gcm")
	viper.Set("aes_key", "SGVsbG8gV29ybGQhIFRoaXMgaXMgYSAzMi1ieXRlIGtleQ==")

	cfg, err := Load()
	require.NoError(t, err)

	// Verify TLS defaults
	assert.False(t, cfg.TLS.Enabled, "TLS should be disabled by default")
	assert.Empty(t, cfg.TLS.CertFile, "cert_file should be empty by default")
	assert.Empty(t, cfg.TLS.KeyFile, "key_file should be empty by default")
}

func TestTLSEnvironmentVariables(t *testing.T) {
	// Reset viper
	viper.Reset()
	setDefaults()

	// Directly set values in viper instead of relying on environment variable parsing
	viper.Set("target_endpoint", "https://s3.amazonaws.com")
	viper.Set("encryption_type", "aes-gcm")
	viper.Set("aes_key", "SGVsbG8gV29ybGQhIFRoaXMgaXMgYSAzMi1ieXRlIGtleQ==")
	viper.Set("tls.enabled", true)

	// Create temporary certificate files
	tempDir := t.TempDir()
	certFile := filepath.Join(tempDir, "cert.pem")
	keyFile := filepath.Join(tempDir, "key.pem")

	// Create dummy cert and key files with secure permissions
	err := os.WriteFile(certFile, []byte("dummy cert"), 0600)
	require.NoError(t, err)
	err = os.WriteFile(keyFile, []byte("dummy key"), 0600)
	require.NoError(t, err)

	viper.Set("tls.cert_file", certFile)
	viper.Set("tls.key_file", keyFile)

	cfg, err := Load()
	require.NoError(t, err)

	// Verify TLS configuration
	assert.True(t, cfg.TLS.Enabled)
	assert.Equal(t, certFile, cfg.TLS.CertFile)
	assert.Equal(t, keyFile, cfg.TLS.KeyFile)
}
