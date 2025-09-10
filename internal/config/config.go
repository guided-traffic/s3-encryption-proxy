package config

import (
	"fmt"
	"os"

	"github.com/spf13/viper"
)

// TLSConfig holds TLS configuration
type TLSConfig struct {
	Enabled  bool   `mapstructure:"enabled"`
	CertFile string `mapstructure:"cert_file"`
	KeyFile  string `mapstructure:"key_file"`
}

// EncryptionProvider holds configuration for a single encryption provider
type EncryptionProvider struct {
	Alias       string                 `mapstructure:"alias"`       // Unique identifier for this provider
	Type        string                 `mapstructure:"type"`        // "tink" or "aes-gcm"
	Description string                 `mapstructure:"description"` // Optional description for this provider
	Config      map[string]interface{} `mapstructure:",remain"`     // Provider-specific configuration parameters
} // EncryptionConfig holds encryption configuration with multiple providers
type EncryptionConfig struct {
	// Active encryption method alias (used for writing/encrypting new files)
	EncryptionMethodAlias string `mapstructure:"encryption_method_alias"`

	// Metadata key prefix for encryption metadata fields
	// - nil (not set): use default "s3ep-"
	// - empty string "": use no prefix
	// - any value: use that value as prefix
	MetadataKeyPrefix *string `mapstructure:"metadata_key_prefix"`

	// List of available encryption providers (used for reading/decrypting files)
	Providers []EncryptionProvider `mapstructure:"providers"`
}

// StreamingConfig holds streaming upload configuration
type StreamingConfig struct {
	// Maximum segment size in bytes before sending as S3 upload part (default: 5MB)
	SegmentSize int64 `mapstructure:"segment_size"`
}

// Config holds the application configuration
type Config struct {
	// Server configuration
	BindAddress       string    `mapstructure:"bind_address"`
	LogLevel          string    `mapstructure:"log_level"`
	LogHealthRequests bool      `mapstructure:"log_health_requests"`
	ShutdownTimeout   int       `mapstructure:"shutdown_timeout"` // Graceful shutdown timeout in seconds
	TLS               TLSConfig `mapstructure:"tls"`

	// S3 configuration
	TargetEndpoint string `mapstructure:"target_endpoint"`
	Region         string `mapstructure:"region"`
	AccessKeyID    string `mapstructure:"access_key_id"`
	SecretKey      string `mapstructure:"secret_key"`

	// Encryption configuration
	Encryption EncryptionConfig `mapstructure:"encryption"`

	// Streaming configuration
	Streaming StreamingConfig `mapstructure:"streaming"`
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

	// Handle provider configs manually due to viper's unmarshaling issues
	if err := loadProviderConfigs(&cfg); err != nil {
		return nil, fmt.Errorf("provider config loading failed: %w", err)
	}

	// Handle backward compatibility - migrate legacy config to new format
	if err := migrateConfig(&cfg); err != nil {
		return nil, fmt.Errorf("config migration failed: %w", err)
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
	viper.SetDefault("log_health_requests", false)
	viper.SetDefault("region", "us-east-1")
	viper.SetDefault("tls.enabled", false)

	// Streaming defaults
	viper.SetDefault("streaming.segment_size", 5*1024*1024) // 5MB default

	// New encryption defaults
	viper.SetDefault("encryption.algorithm", "AES256_GCM")
	viper.SetDefault("encryption.key_rotation_days", 90)
	viper.SetDefault("encryption.metadata_key_prefix", "s3ep-")

}

// validate validates the configuration
func validate(cfg *Config) error {
	if cfg.TargetEndpoint == "" {
		return fmt.Errorf("target_endpoint is required")
	}

	// Validate TLS configuration
	if cfg.TLS.Enabled {
		if cfg.TLS.CertFile == "" {
			return fmt.Errorf("tls.cert_file is required when TLS is enabled")
		}
		if cfg.TLS.KeyFile == "" {
			return fmt.Errorf("tls.key_file is required when TLS is enabled")
		}

		// Check if certificate files exist
		if _, err := os.Stat(cfg.TLS.CertFile); os.IsNotExist(err) {
			return fmt.Errorf("TLS certificate file does not exist: %s", cfg.TLS.CertFile)
		}
		if _, err := os.Stat(cfg.TLS.KeyFile); os.IsNotExist(err) {
			return fmt.Errorf("TLS key file does not exist: %s", cfg.TLS.KeyFile)
		}
	}

	// Validate encryption configuration
	if err := validateEncryption(cfg); err != nil {
		return err
	}

	return nil
}

// loadProviderConfigs loads provider configurations directly from viper to avoid unmarshaling issues
func loadProviderConfigs(cfg *Config) error {
	providersData := viper.Get("encryption.providers")
	if providersData == nil {
		// No providers configured, that's okay - just leave empty
		return nil
	}

	// Always reset providers to avoid viper.Unmarshal issues
	cfg.Encryption.Providers = nil

	// Handle different types that viper might return
	if providersSlice, ok := providersData.([]interface{}); ok {
		return loadProvidersFromInterfaceSlice(cfg, providersSlice)
	}

	if providersMapSlice, ok := providersData.([]map[string]interface{}); ok {
		return loadProvidersFromMapSlice(cfg, providersMapSlice)
	}

	return fmt.Errorf("providers data is not a recognized format: %T", providersData)
}

// loadProvidersFromInterfaceSlice handles []interface{} format
func loadProvidersFromInterfaceSlice(cfg *Config, providersSlice []interface{}) error {
	providers := make([]EncryptionProvider, 0, len(providersSlice))

	for i, providerData := range providersSlice {
		if providerMap, ok := providerData.(map[string]interface{}); ok {
			provider, err := createProviderFromProviderMap(providerMap)
			if err != nil {
				return err
			}
			providers = append(providers, provider)
		} else {
			return fmt.Errorf("provider %d is not a map", i)
		}
	}

	cfg.Encryption.Providers = providers
	return nil
}

// loadProvidersFromMapSlice handles []map[string]interface{} format
func loadProvidersFromMapSlice(cfg *Config, providersMapSlice []map[string]interface{}) error {
	providers := make([]EncryptionProvider, 0, len(providersMapSlice))

	for _, providerMap := range providersMapSlice {
		provider, err := createProviderFromProviderMap(providerMap)
		if err != nil {
			return err
		}
		providers = append(providers, provider)
	}

	cfg.Encryption.Providers = providers
	return nil
}

// createProviderFromProviderMap creates a provider from a provider map
func createProviderFromProviderMap(providerMap map[string]interface{}) (EncryptionProvider, error) {
	provider := EncryptionProvider{
		Config: make(map[string]interface{}),
	}

	// Map basic fields
	if alias, ok := providerMap["alias"].(string); ok {
		provider.Alias = alias
	}
	if typ, ok := providerMap["type"].(string); ok {
		provider.Type = typ
	}
	if desc, ok := providerMap["description"].(string); ok {
		provider.Description = desc
	}

	// Extract config map directly
	if configData, exists := providerMap["config"]; exists {
		if configMap, ok := configData.(map[string]interface{}); ok {
			provider.Config = configMap
		}
	}

	return provider, nil
}

// migrateConfig handles configuration setup and provider config processing
func migrateConfig(cfg *Config) error {
	// Get providers data from viper to handle the map vs slice issue
	providersData := viper.Get("encryption.providers")

	if providersData == nil {
		return nil
	}

	// Handle different provider data formats
	if err := processProvidersData(cfg, providersData); err != nil {
		return err
	}

	// Ensure all providers have initialized Config maps
	ensureProviderConfigMaps(cfg)

	return nil
}

// processProvidersData processes providers data in different formats
func processProvidersData(cfg *Config, providersData interface{}) error {
	if providersSlice, ok := providersData.([]interface{}); ok {
		return processProvidersSlice(cfg, providersSlice)
	}

	if providersMap, ok := providersData.(map[string]interface{}); ok {
		return processProvidersMap(cfg, providersMap)
	}

	if providersMapSlice, ok := providersData.([]map[string]interface{}); ok {
		return processProvidersMapSlice(cfg, providersMapSlice)
	}

	// If providers data is in some other format, try to handle it generically
	return fmt.Errorf("unsupported providers data format: %T", providersData)
}

// processProvidersMapSlice handles []map[string]interface{} format from configs
func processProvidersMapSlice(cfg *Config, providersMapSlice []map[string]interface{}) error {
	providers := make([]EncryptionProvider, 0, len(providersMapSlice))

	for _, providerMap := range providersMapSlice {
		provider, err := createProviderFromMap(providerMap)
		if err != nil {
			return err
		}
		providers = append(providers, provider)
	}

	cfg.Encryption.Providers = providers
	return nil
}

// processProvidersSlice handles array format providers (from tests)
func processProvidersSlice(cfg *Config, providersSlice []interface{}) error {
	providers := make([]EncryptionProvider, 0, len(providersSlice))

	for _, providerData := range providersSlice {
		if providerMap, ok := providerData.(map[string]interface{}); ok {
			provider, err := createProviderFromMap(providerMap)
			if err != nil {
				return err
			}
			providers = append(providers, provider)
		}
	}

	cfg.Encryption.Providers = providers
	return nil
}

// processProvidersMap handles map format providers (from file config)
func processProvidersMap(cfg *Config, providersMap map[string]interface{}) error {
	providers := make([]EncryptionProvider, 0)

	for i := 0; i < len(providersMap); i++ {
		key := fmt.Sprintf("%d", i)
		if providerData, exists := providersMap[key]; exists {
			if providerMap, ok := providerData.(map[string]interface{}); ok {
				provider, err := createProviderFromMap(providerMap)
				if err != nil {
					return err
				}
				providers = append(providers, provider)
			}
		}
	}

	cfg.Encryption.Providers = providers
	return nil
}

// createProviderFromMap creates an EncryptionProvider from a map
func createProviderFromMap(providerMap map[string]interface{}) (EncryptionProvider, error) {
	provider := EncryptionProvider{}

	// Map basic fields
	setProviderBasicFields(&provider, providerMap)

	// Extract and process config map
	setProviderConfig(&provider, providerMap)

	return provider, nil
}

// setProviderBasicFields sets basic provider fields from map
func setProviderBasicFields(provider *EncryptionProvider, providerMap map[string]interface{}) {
	if alias, ok := providerMap["alias"].(string); ok {
		provider.Alias = alias
	}
	if typ, ok := providerMap["type"].(string); ok {
		provider.Type = typ
	}
	if desc, ok := providerMap["description"].(string); ok {
		provider.Description = desc
	}
}

// setProviderConfig sets provider config from map
func setProviderConfig(provider *EncryptionProvider, providerMap map[string]interface{}) {
	provider.Config = make(map[string]interface{})

	if configData, exists := providerMap["config"]; exists {
		if configMap, ok := configData.(map[string]interface{}); ok {
			provider.Config = configMap
		}
	}

	// Handle nested config issue from Viper
	if nestedConfig, exists := provider.Config["config"]; exists {
		if nestedConfigMap, ok := nestedConfig.(map[string]interface{}); ok {
			provider.Config = nestedConfigMap
		}
	}
}

// ensureProviderConfigMaps ensures all providers have initialized Config maps
func ensureProviderConfigMaps(cfg *Config) {
	for i := range cfg.Encryption.Providers {
		provider := &cfg.Encryption.Providers[i]
		if provider.Config == nil {
			provider.Config = make(map[string]interface{})
		}
	}
} // validateEncryption validates the encryption configuration
func validateEncryption(cfg *Config) error {
	// If using new encryption config format
	if cfg.Encryption.EncryptionMethodAlias != "" || len(cfg.Encryption.Providers) > 0 {
		// Validate that encryption_method_alias is specified
		if cfg.Encryption.EncryptionMethodAlias == "" {
			return fmt.Errorf("encryption.encryption_method_alias is required when using encryption.providers")
		}

		// Validate that providers list is not empty
		if len(cfg.Encryption.Providers) == 0 {
			return fmt.Errorf("encryption.providers cannot be empty")
		}

		// Find the active provider
		var activeProvider *EncryptionProvider
		aliasMap := make(map[string]bool)

		for i := range cfg.Encryption.Providers {
			provider := &cfg.Encryption.Providers[i]

			// Validate provider fields
			if provider.Alias == "" {
				return fmt.Errorf("encryption.providers[%d].alias is required", i)
			}

			// Check for duplicate aliases
			if aliasMap[provider.Alias] {
				return fmt.Errorf("duplicate encryption provider alias: %s", provider.Alias)
			}
			aliasMap[provider.Alias] = true

			// Validate provider type and required fields
			if err := validateProvider(provider, i); err != nil {
				return err
			}

			// Check if this is the active provider
			if provider.Alias == cfg.Encryption.EncryptionMethodAlias {
				activeProvider = provider
			}
		}

		// Validate that the active provider exists
		if activeProvider == nil {
			return fmt.Errorf("encryption_method_alias '%s' does not match any provider alias", cfg.Encryption.EncryptionMethodAlias)
		}

		return nil
	}

	// If no explicit alias but providers exist, validate at least
	// Note: Having no providers is valid for non-encryption use cases (e.g., TLS only)

	return nil
}

// validateProvider validates a single encryption provider
func validateProvider(provider *EncryptionProvider, index int) error {
	switch provider.Type {
	case "tink":
		return fmt.Errorf("encryption.providers[%d]: tink encryption is not yet implemented with the new architecture", index)
	case "aes":
		if aesKey, ok := provider.Config["aes_key"].(string); !ok || aesKey == "" {
			return fmt.Errorf("encryption.providers[%d]: aes_key is required when using aes encryption", index)
		}
	case "rsa":
		if publicKeyPEM, ok := provider.Config["public_key_pem"].(string); !ok || publicKeyPEM == "" {
			return fmt.Errorf("encryption.providers[%d]: public_key_pem is required when using rsa encryption", index)
		}
		if privateKeyPEM, ok := provider.Config["private_key_pem"].(string); !ok || privateKeyPEM == "" {
			return fmt.Errorf("encryption.providers[%d]: private_key_pem is required when using rsa encryption", index)
		}
	case "none":
		// No validation needed for "none" provider - no encryption parameters required
	default:
		return fmt.Errorf("encryption.providers[%d].type: unsupported encryption type: %s (supported: aes, rsa, none)", index, provider.Type)
	}

	return nil
} // GetActiveProvider returns the active encryption provider (used for encrypting)
func (cfg *Config) GetActiveProvider() (*EncryptionProvider, error) {
	// Validate that encryption_method_alias is specified for new format
	if cfg.Encryption.EncryptionMethodAlias == "" {
		if len(cfg.Encryption.Providers) > 0 {
			return nil, fmt.Errorf("encryption_method_alias is required when providers are configured")
		}
		return nil, fmt.Errorf("no encryption providers configured")
	}

	// Find the specified provider
	for i := range cfg.Encryption.Providers {
		provider := &cfg.Encryption.Providers[i]
		if provider.Alias == cfg.Encryption.EncryptionMethodAlias {
			// Validate provider type
			if provider.Type == "" {
				return nil, fmt.Errorf("provider '%s' has empty type", provider.Alias)
			}
			// Add known provider type validation
			if !isValidProviderType(provider.Type) {
				return nil, fmt.Errorf("provider '%s' has invalid type '%s'", provider.Alias, provider.Type)
			}
			return provider, nil
		}
	}
	return nil, fmt.Errorf("active encryption provider '%s' not found", cfg.Encryption.EncryptionMethodAlias)
}

// isValidProviderType checks if the provider type is valid
func isValidProviderType(providerType string) bool {
	validTypes := []string{"aes", "rsa", "none"}
	for _, validType := range validTypes {
		if providerType == validType {
			return true
		}
	}
	return false
}

// GetAllProviders returns all encryption providers (used for decrypting)
func (cfg *Config) GetAllProviders() []EncryptionProvider {
	return cfg.Encryption.Providers
}

// GetProviderByAlias returns a specific provider by its alias
func (cfg *Config) GetProviderByAlias(alias string) (*EncryptionProvider, error) {
	for i := range cfg.Encryption.Providers {
		if cfg.Encryption.Providers[i].Alias == alias {
			return &cfg.Encryption.Providers[i], nil
		}
	}
	return nil, fmt.Errorf("encryption provider with alias '%s' not found", alias)
}

// GetProviderConfig returns the configuration parameters for a provider
func (provider *EncryptionProvider) GetProviderConfig() map[string]interface{} {
	if provider.Config == nil {
		provider.Config = make(map[string]interface{})
	}
	return provider.Config
}
