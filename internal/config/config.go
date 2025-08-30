package config

import (
	"fmt"
	"os"

	"github.com/spf13/viper"
)

// Config holds the application configuration
type Config struct {
	// Server configuration
	BindAddress string `mapstructure:"bind_address"`
	LogLevel    string `mapstructure:"log_level"`

	// S3 configuration
	TargetEndpoint string `mapstructure:"target_endpoint"`
	Region         string `mapstructure:"region"`
	AccessKeyID    string `mapstructure:"access_key_id"`
	SecretKey      string `mapstructure:"secret_key"`

	// Encryption configuration
	EncryptionType  string `mapstructure:"encryption_type"`  // "tink" or "aes256-gcm"
	KEKUri          string `mapstructure:"kek_uri"`          // For Tink encryption
	CredentialsPath string `mapstructure:"credentials_path"` // For Tink encryption
	AESKey          string `mapstructure:"aes_key"`          // Base64 encoded AES-256 key for direct encryption

	// Additional encryption settings
	Algorithm         string `mapstructure:"algorithm"`
	KeyRotationDays   int    `mapstructure:"key_rotation_days"`
	MetadataKeyPrefix string `mapstructure:"metadata_key_prefix"`
}

// InitConfig initializes the configuration system
func InitConfig(cfgFile string) {
	if cfgFile != "" {
		// Use config file from the flag
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory
		home, err := os.UserHomeDir()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error finding home directory: %v\n", err)
			os.Exit(1)
		}

		// Search config in home directory with name ".s3-encryption-proxy" (without extension)
		viper.AddConfigPath(home)
		viper.AddConfigPath(".")
		viper.AddConfigPath("./config")
		viper.SetConfigType("yaml")
		viper.SetConfigName(".s3-encryption-proxy")
	}

	// Environment variable configuration
	viper.SetEnvPrefix("S3EP") // S3 Encryption Proxy
	viper.AutomaticEnv()

	// Set defaults
	setDefaults()

	// If a config file is found, read it in
	if err := viper.ReadInConfig(); err == nil {
		fmt.Fprintf(os.Stderr, "Using config file: %s\n", viper.ConfigFileUsed())
	}
}

// Load loads the configuration from viper
func Load() (*Config, error) {
	var cfg Config

	if err := viper.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	// Validate required fields
	if err := validate(&cfg); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	return &cfg, nil
}

// setDefaults sets default configuration values
func setDefaults() {
	viper.SetDefault("bind_address", "0.0.0.0:8080")
	viper.SetDefault("log_level", "info")
	viper.SetDefault("region", "us-east-1")
	viper.SetDefault("encryption_type", "tink")
	viper.SetDefault("algorithm", "AES256_GCM")
	viper.SetDefault("key_rotation_days", 90)
	viper.SetDefault("metadata_key_prefix", "x-s3ep-")
}

// validate validates the configuration
func validate(cfg *Config) error {
	if cfg.TargetEndpoint == "" {
		return fmt.Errorf("target_endpoint is required")
	}

	// Validate encryption configuration based on type
	switch cfg.EncryptionType {
	case "tink":
		if cfg.KEKUri == "" {
			return fmt.Errorf("kek_uri is required when using tink encryption")
		}
	case "aes256-gcm":
		if cfg.AESKey == "" {
			return fmt.Errorf("aes_key is required when using aes256-gcm encryption")
		}
	default:
		return fmt.Errorf("unsupported encryption_type: %s (supported: tink, aes256-gcm)", cfg.EncryptionType)
	}

	return nil
}
