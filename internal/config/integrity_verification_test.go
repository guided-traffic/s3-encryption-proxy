package config

import (
	"os"
	"testing"

	"github.com/spf13/viper"
)

func TestIntegrityVerificationConfigDefaults(t *testing.T) {
	// Reset viper to ensure clean state
	viper.Reset()

	// Set defaults
	setDefaults()

	// Check that defaults are set correctly
	if !viper.IsSet("encryption.integrity_verification") {
		t.Error("Default for encryption.integrity_verification should be set")
	}

	if viper.GetString("encryption.integrity_verification") != "off" {
		t.Error("Default for encryption.integrity_verification should be 'off'")
	}
}

func TestIntegrityVerificationConfigLoading(t *testing.T) {
	tests := []struct {
		name           string
		configData     map[string]interface{}
		expectedValue  string
		expectError    bool
	}{
		{
			name: "valid integrity verification strict mode",
			configData: map[string]interface{}{
				"encryption": map[string]interface{}{
					"integrity_verification": "strict",
				},
				// Minimal required config
				"s3_backend": map[string]interface{}{
					"target_endpoint": "http://localhost:9000",
				},
				"s3_clients": []map[string]interface{}{
					{
						"type":           "static",
						"access_key_id":  "test_access_key_id",
						"secret_key":     "test_secret_key_value",
					},
				},
			},
			expectedValue: "strict",
			expectError:   false,
		},
		{
			name: "valid integrity verification lax mode",
			configData: map[string]interface{}{
				"encryption": map[string]interface{}{
					"integrity_verification": "lax",
				},
				// Minimal required config
				"s3_backend": map[string]interface{}{
					"target_endpoint": "http://localhost:9000",
				},
				"s3_clients": []map[string]interface{}{
					{
						"type":           "static",
						"access_key_id":  "test_access_key_id",
						"secret_key":     "test_secret_key_value",
					},
				},
			},
			expectedValue: "lax",
			expectError:   false,
		},
		{
			name: "valid integrity verification off mode",
			configData: map[string]interface{}{
				"encryption": map[string]interface{}{
					"integrity_verification": "off",
				},
				// Minimal required config
				"s3_backend": map[string]interface{}{
					"target_endpoint": "http://localhost:9000",
				},
				"s3_clients": []map[string]interface{}{
					{
						"type":           "static",
						"access_key_id":  "test_access_key_id",
						"secret_key":     "test_secret_key_value",
					},
				},
			},
			expectedValue: "off",
			expectError:   false,
		},
		{
			name: "valid integrity verification hybrid mode",
			configData: map[string]interface{}{
				"encryption": map[string]interface{}{
					"integrity_verification": "hybrid",
				},
				// Minimal required config
				"s3_backend": map[string]interface{}{
					"target_endpoint": "http://localhost:9000",
				},
				"s3_clients": []map[string]interface{}{
					{
						"type":           "static",
						"access_key_id":  "test_access_key_id",
						"secret_key":     "test_secret_key_value",
					},
				},
			},
			expectedValue: "hybrid",
			expectError:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a temporary config file
			tmpDir, err := os.MkdirTemp("", "config_test")
			if err != nil {
				t.Fatalf("Failed to create temp dir: %v", err)
			}
			defer os.RemoveAll(tmpDir)

			// Reset viper
			viper.Reset()

			// Load config data into viper
			for key, value := range tt.configData {
				viper.Set(key, value)
			}

			// Set defaults
			setDefaults()

			// Load configuration
			cfg, err := Load()

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
					return
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error but got: %v", err)
					return
				}

				// Verify the loaded configuration
				if cfg == nil {
					t.Error("Config should not be nil")
					return
				}

				// Verify integrity verification config was loaded correctly
				if cfg.Encryption.IntegrityVerification != tt.expectedValue {
					t.Errorf("Expected integrity verification=%v, got %v", tt.expectedValue, cfg.Encryption.IntegrityVerification)
				}
			}
		})
	}
}

func TestIntegrityVerificationWithDefaults(t *testing.T) {
	// Reset viper
	viper.Reset()

	// Set minimal config that will pass validation
	viper.Set("s3_backend.target_endpoint", "http://localhost:9000")
	viper.Set("s3_clients", []map[string]interface{}{
		{
			"type":           "static",
			"access_key_id":  "test_access_key_id",
			"secret_key":     "test_secret_key_value",
		},
	})

	// Set defaults
	setDefaults()

	// Load configuration
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	// Verify defaults are applied - default should be "off"
	if cfg.Encryption.IntegrityVerification != "off" {
		t.Errorf("Expected default integrity_verification='off', got %v", cfg.Encryption.IntegrityVerification)
	}
}

func TestIntegrityVerificationEnabledExplicitly(t *testing.T) {
	// Reset viper
	viper.Reset()

	// Set config with enabled integrity verification
	viper.Set("encryption.integrity_verification", "strict")

	// Set minimal required config
	viper.Set("s3_backend.target_endpoint", "http://localhost:9000")
	viper.Set("s3_clients", []map[string]interface{}{
		{
			"type":           "static",
			"access_key_id":  "test_access_key_id",
			"secret_key":     "test_secret_key_value",
		},
	})

	// Set defaults
	setDefaults()

	// Load configuration - should succeed
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Expected no error when integrity verification is enabled, got: %v", err)
	}

	if cfg.Encryption.IntegrityVerification != "strict" {
		t.Errorf("Integrity verification should be 'strict', got %v", cfg.Encryption.IntegrityVerification)
	}
}