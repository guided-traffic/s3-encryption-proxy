package config

import (
	"testing"

	"github.com/spf13/viper"
)

func TestDebugViperConfig(t *testing.T) {
	viper.Reset()
	setDefaults()

	// Set test configuration like in the real test
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

	// Let's debug Viper data before migration
	t.Logf("Viper providers before migration: %+v", viper.Get("encryption.providers"))
	if providers, ok := viper.Get("encryption.providers").([]interface{}); ok && len(providers) > 0 {
		if provider, ok := providers[0].(map[string]interface{}); ok {
			t.Logf("Provider 0 before migration: %+v", provider)
			if config, ok := provider["config"]; ok {
				t.Logf("Config before migration: %+v", config)
			}
		}
	}

	// Try Viper migration
	if err := migrateProviderConfigs(); err != nil {
		t.Logf("Viper migration error: %v", err)
		return
	}

	// Check Viper data after migration
	t.Logf("Viper providers after migration: %+v", viper.Get("encryption.providers"))
	if providers, ok := viper.Get("encryption.providers").([]interface{}); ok && len(providers) > 0 {
		if provider, ok := providers[0].(map[string]interface{}); ok {
			t.Logf("Provider 0 after migration: %+v", provider)
			if config, ok := provider["config"]; ok {
				t.Logf("Config after migration: %+v", config)
			}
		}
	}

	// Now try the Load function
	cfg, err := Load()
	if err != nil {
		t.Logf("Load error: %v", err)

		// Let's debug manually what Load() does
		var manualCfg Config
		if err := viper.Unmarshal(&manualCfg); err != nil {
			t.Logf("Manual unmarshal error: %v", err)
		} else {
			t.Logf("Manual config after unmarshal: %+v", manualCfg.Encryption.Providers)

			if err := loadProviderConfigs(&manualCfg); err != nil {
				t.Logf("Manual loadProviderConfigs error: %v", err)
			} else {
				t.Logf("Viper data during loadProviderConfigs: %+v", viper.Get("encryption.providers"))
				t.Logf("Manual config after loadProviderConfigs: %+v", manualCfg.Encryption.Providers)
				if len(manualCfg.Encryption.Providers) > 0 {
					t.Logf("Manual provider[0] config: %+v", manualCfg.Encryption.Providers[0].Config)
					t.Logf("Manual KEK URI: %v", manualCfg.Encryption.Providers[0].Config["kek_uri"])
				} else {
					t.Logf("No providers loaded!")
				}
			}
		}
	} else {
		t.Logf("Config loaded successfully")
		t.Logf("Providers: %+v", cfg.Encryption.Providers)
		if len(cfg.Encryption.Providers) > 0 {
			t.Logf("First provider config: %+v", cfg.Encryption.Providers[0].Config)
		}
	}
}
