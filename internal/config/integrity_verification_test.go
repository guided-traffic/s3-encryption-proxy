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

	if viper.GetBool("encryption.integrity_verification") != false {
		t.Error("Default for encryption.integrity_verification should be false")
	}
}

func TestIntegrityVerificationConfigLoading(t *testing.T) {
	tests := []struct {
		name        string
		configData  map[string]interface{}
		expectError bool
	}{
		{
			name: "valid integrity verification enabled",
			configData: map[string]interface{}{
				"encryption": map[string]interface{}{
					"integrity_verification": true,
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
			expectError: false,
		},
		{
			name: "valid integrity verification disabled",
			configData: map[string]interface{}{
				"encryption": map[string]interface{}{
					"integrity_verification": false,
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
			expectError: false,
		},
		{
			name: "integrity verification as string (should work with yaml conversion)",
			configData: map[string]interface{}{
				"encryption": map[string]interface{}{
					"integrity_verification": "true",
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
			expectError: false,
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
				expectedValue := tt.configData["encryption"].(map[string]interface{})["integrity_verification"]

				var expectedBool bool
				switch v := expectedValue.(type) {
				case bool:
					expectedBool = v
				case string:
					expectedBool = v == "true"
				default:
					t.Errorf("Unexpected integrity_verification type: %T", v)
					return
				}

				if cfg.Encryption.IntegrityVerification != expectedBool {
					t.Errorf("Expected integrity verification=%v, got %v", expectedBool, cfg.Encryption.IntegrityVerification)
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

	// Verify defaults are applied
	if cfg.Encryption.IntegrityVerification != false {
		t.Errorf("Expected default integrity_verification=false, got %v", cfg.Encryption.IntegrityVerification)
	}
}

func TestIntegrityVerificationEnabledExplicitly(t *testing.T) {
	// Reset viper
	viper.Reset()

	// Set config with enabled integrity verification
	viper.Set("encryption.integrity_verification", true)

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

	if !cfg.Encryption.IntegrityVerification {
		t.Error("Integrity verification should be enabled")
	}
}