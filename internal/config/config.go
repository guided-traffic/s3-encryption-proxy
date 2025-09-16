package config

import (
	"fmt"
	"os"

	"github.com/guided-traffic/s3-encryption-proxy/internal/license"
	"github.com/spf13/viper"
)

// TLSConfig holds TLS configuration
type TLSConfig struct {
	Enabled  bool   `mapstructure:"enabled"`
	CertFile string `mapstructure:"cert_file"`
	KeyFile  string `mapstructure:"key_file"`
}

// S3BackendConfig holds S3 backend configuration
type S3BackendConfig struct {
	TargetEndpoint     string `mapstructure:"target_endpoint"`
	Region             string `mapstructure:"region"`
	AccessKeyID        string `mapstructure:"access_key_id"`
	SecretKey          string `mapstructure:"secret_key"`
	UseTLS             bool   `mapstructure:"use_tls"`
	InsecureSkipVerify bool   `mapstructure:"insecure_skip_verify"` // Only for development/testing
}

// EncryptionProvider holds configuration for a single encryption provider
type EncryptionProvider struct {
	Alias       string                 `mapstructure:"alias"`       // Unique identifier for this provider
	Type        string                 `mapstructure:"type"`        // "tink" or "aes-gcm"
	Description string                 `mapstructure:"description"` // Optional description for this provider
	Config      map[string]interface{} `mapstructure:",remain"`     // Provider-specific configuration parameters
}

// EncryptionConfig holds encryption configuration with multiple providers
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

	// Enable integrity verification for encrypted data using HMAC
	IntegrityVerification bool `mapstructure:"integrity_verification"`
}

// S3ClientCredentials holds credentials for a single S3 client
type S3ClientCredentials struct {
	Type          string `mapstructure:"type"`            // "static" (more types may be added later)
	AccessKeyID   string `mapstructure:"access_key_id"`   // S3 Access Key ID
	SecretKey     string `mapstructure:"secret_key"`      // S3 Secret Access Key
	Description   string `mapstructure:"description"`     // Optional description for this client
}

// S3SecurityConfig holds S3 client authentication security configuration
type S3SecurityConfig struct {
	// Enable strict signature validation (AWS Signature V4 only)
	StrictSignatureValidation bool `mapstructure:"strict_signature_validation"`

	// Maximum clock skew allowed in seconds (default: 900 = 15 minutes)
	MaxClockSkewSeconds int `mapstructure:"max_clock_skew_seconds"`

	// Enable rate limiting per client IP
	EnableRateLimiting bool `mapstructure:"enable_rate_limiting"`

	// Maximum requests per minute per IP (default: 100)
	MaxRequestsPerMinute int `mapstructure:"max_requests_per_minute"`

	// Enable request logging for security monitoring
	EnableSecurityLogging bool `mapstructure:"enable_security_logging"`

	// Block IPs after this many failed authentication attempts (default: 10)
	MaxFailedAttempts int `mapstructure:"max_failed_attempts"`

	// Automatically unblock IPs after this many seconds (default: 60)
	// 0 = never unblock automatically (manual intervention required)
	UnblockIPSeconds int `mapstructure:"unblock_ip_seconds"`
}

// S3ClientConfig holds S3 client authentication configuration
type S3ClientConfig struct {
	Clients  []S3ClientCredentials `mapstructure:"s3_clients"`  // List of allowed S3 client credentials
	Security S3SecurityConfig      `mapstructure:"s3_security"` // Security configuration
}

// OptimizationsConfig holds performance optimization settings
type OptimizationsConfig struct {
	// Streaming Buffer Configuration
	StreamingBufferSize     int  `mapstructure:"streaming_buffer_size" validate:"min=4096,max=2097152"` // 4KB - 2MB, default: 64KB
	EnableAdaptiveBuffering bool `mapstructure:"enable_adaptive_buffering"`                             // Dynamic buffer sizing based on load

	// Streaming Segment Configuration
	StreamingSegmentSize int64 `mapstructure:"streaming_segment_size" validate:"min=5242880,max=5368709120"` // 5MB - 5GB, default: 12MB

	// Upload Processing Threshold
	StreamingThreshold int64 `mapstructure:"streaming_threshold" validate:"min=1048576"` // Use streaming for files larger than this size (default: 1MB)
} // MonitoringConfig holds monitoring configuration
type MonitoringConfig struct {
	Enabled     bool   `mapstructure:"enabled"`      // Enable/disable monitoring
	BindAddress string `mapstructure:"bind_address"` // Address to bind monitoring server (default: :9090)
	MetricsPath string `mapstructure:"metrics_path"` // Path for metrics endpoint (default: /metrics)
}

// Config holds the application configuration
type Config struct {
	// Server configuration
	BindAddress       string    `mapstructure:"bind_address"`
	LogLevel          string    `mapstructure:"log_level"`
	LogFormat         string    `mapstructure:"log_format"`       // "text" (default) or "json"
	LogHealthRequests bool      `mapstructure:"log_health_requests"`
	ShutdownTimeout   int       `mapstructure:"shutdown_timeout"` // Graceful shutdown timeout in seconds
	TLS               TLSConfig `mapstructure:"tls"`

	// Monitoring configuration
	Monitoring MonitoringConfig `mapstructure:"monitoring"`

	// S3 configuration
	S3Backend      S3BackendConfig `mapstructure:"s3_backend"`
	TargetEndpoint string          `mapstructure:"target_endpoint"`
	Region         string          `mapstructure:"region"`
	AccessKeyID    string          `mapstructure:"access_key_id"`
	SecretKey      string          `mapstructure:"secret_key"`

	// S3 Client Authentication configuration
	S3Clients  []S3ClientCredentials `mapstructure:"s3_clients"`
	S3Security S3SecurityConfig      `mapstructure:"s3_security"`

	// Legacy S3 TLS configuration (for backward compatibility)
	UseTLS              bool `mapstructure:"use_tls"`
	SkipSSLVerification bool `mapstructure:"skip_ssl_verification"`

	// License configuration
	LicenseFile string `mapstructure:"license_file"` // Path to license file (default: config/license.jwt)

	// Encryption configuration
	Encryption EncryptionConfig `mapstructure:"encryption"`

	// Performance optimizations configuration
	Optimizations OptimizationsConfig `mapstructure:"optimizations"`
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

	// Handle legacy configuration migration
	migrateLegacyConfig(&cfg)

	// Handle provider configs manually due to viper's unmarshaling issues
	if err := loadProviderConfigs(&cfg); err != nil {
		return nil, fmt.Errorf("provider config loading failed: %w", err)
	}

	// Validate required fields
	if err := validate(&cfg); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	return &cfg, nil
}

// LoadAndStartLicense loads configuration and returns license validator for runtime monitoring
func LoadAndStartLicense() (*Config, *license.LicenseValidator, error) {
	cfg, err := Load()
	if err != nil {
		return nil, nil, err
	}

	// Create and configure license validator for runtime monitoring
	licenseToken := license.LoadLicense(cfg.LicenseFile)
	validator := license.NewValidator()
	result := validator.ValidateLicense(licenseToken)

	// Start runtime monitoring if license is valid
	if result.Valid {
		validator.StartRuntimeMonitoring()
	}

	return cfg, validator, nil
}

// migrateLegacyConfig handles migration from legacy configuration parameters
func migrateLegacyConfig(cfg *Config) {
	migratedFields := []string{}

	// Migrate legacy S3 configuration to new s3_backend structure - only if explicitly set
	if viper.IsSet("target_endpoint") && !viper.IsSet("s3_backend.target_endpoint") && cfg.TargetEndpoint != "" {
		cfg.S3Backend.TargetEndpoint = cfg.TargetEndpoint
		migratedFields = append(migratedFields, "target_endpoint")
	}

	if viper.IsSet("region") && !viper.IsSet("s3_backend.region") && cfg.Region != "" {
		cfg.S3Backend.Region = cfg.Region
		migratedFields = append(migratedFields, "region")
	}

	if viper.IsSet("access_key_id") && !viper.IsSet("s3_backend.access_key_id") && cfg.AccessKeyID != "" {
		cfg.S3Backend.AccessKeyID = cfg.AccessKeyID
		migratedFields = append(migratedFields, "access_key_id")
	}

	if viper.IsSet("secret_key") && !viper.IsSet("s3_backend.secret_key") && cfg.SecretKey != "" {
		cfg.S3Backend.SecretKey = cfg.SecretKey
		migratedFields = append(migratedFields, "secret_key")
	}

	// Only migrate if the legacy field was explicitly set in config (not just default)
	if cfg.UseTLS != viper.GetBool("s3_backend.use_tls") && viper.IsSet("use_tls") && !viper.IsSet("s3_backend.use_tls") {
		cfg.S3Backend.UseTLS = cfg.UseTLS
		migratedFields = append(migratedFields, "use_tls")
	}

	// Migrate legacy skip_ssl_verification to new s3_backend.insecure_skip_verify
	if cfg.SkipSSLVerification != viper.GetBool("s3_backend.insecure_skip_verify") && viper.IsSet("skip_ssl_verification") && !viper.IsSet("s3_backend.insecure_skip_verify") {
		cfg.S3Backend.InsecureSkipVerify = cfg.SkipSSLVerification
		migratedFields = append(migratedFields, "skip_ssl_verification")
	}

	// Issue warning if any fields were migrated
	if len(migratedFields) > 0 {
		fmt.Fprintf(os.Stderr, "Warning: The following top-level S3 configuration fields are deprecated:\n")
		for _, field := range migratedFields {
			fmt.Fprintf(os.Stderr, "  - '%s' should be moved to 's3_backend.%s'\n", field, field)
		}
		fmt.Fprintf(os.Stderr, "Please update your configuration to use the new 's3_backend' structure.\n")
	}
}

// setDefaults sets default configuration values
func setDefaults() {
	viper.SetDefault("bind_address", "0.0.0.0:8080")
	viper.SetDefault("log_level", "info")
	viper.SetDefault("log_format", "text")
	viper.SetDefault("log_health_requests", false)

	// New s3_backend configuration defaults
	viper.SetDefault("s3_backend.region", "us-east-1")
	viper.SetDefault("s3_backend.use_tls", true)
	viper.SetDefault("s3_backend.insecure_skip_verify", false)

	// Legacy S3 configuration defaults (for backward compatibility)
	viper.SetDefault("region", "us-east-1")
	viper.SetDefault("use_tls", true)
	viper.SetDefault("skip_ssl_verification", false)

	// TLS defaults
	viper.SetDefault("tls.enabled", false)

	// Monitoring defaults
	viper.SetDefault("monitoring.enabled", false)
	viper.SetDefault("monitoring.bind_address", ":9090")
	viper.SetDefault("monitoring.metrics_path", "/metrics")

	// License defaults
	viper.SetDefault("license_file", "config/license.jwt")

	// Optimizations defaults
	viper.SetDefault("optimizations.streaming_buffer_size", 64*1024)       // 64KB default
	viper.SetDefault("optimizations.enable_adaptive_buffering", false)     // Disabled by default
	viper.SetDefault("optimizations.streaming_segment_size", 12*1024*1024) // 12MB default
	viper.SetDefault("optimizations.streaming_threshold", 5*1024*1024)     // 5MB default

	// New encryption defaults
	viper.SetDefault("encryption.algorithm", "AES256_GCM")
	viper.SetDefault("encryption.key_rotation_days", 90)
	viper.SetDefault("encryption.metadata_key_prefix", "s3ep-")

	// Integrity verification defaults
	viper.SetDefault("encryption.integrity_verification", false)

	// S3 Security defaults
	viper.SetDefault("s3_security.max_clock_skew_seconds", 900)
	viper.SetDefault("s3_security.enable_rate_limiting", true)
	viper.SetDefault("s3_security.max_requests_per_minute", 100)
	viper.SetDefault("s3_security.enable_security_logging", true)
	viper.SetDefault("s3_security.max_failed_attempts", 10)
	viper.SetDefault("s3_security.unblock_ip_seconds", 60)

}

// validate validates the configuration
func validate(cfg *Config) error {
	// Use migrated S3 configuration for validation
	targetEndpoint := cfg.S3Backend.TargetEndpoint
	if targetEndpoint == "" {
		targetEndpoint = cfg.TargetEndpoint // fallback to legacy
	}

	if targetEndpoint == "" {
		return fmt.Errorf("target_endpoint is required (use 's3_backend.target_endpoint' or legacy 'target_endpoint')")
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

	// Validate license and encryption configuration
	if err := validateLicenseAndEncryption(cfg); err != nil {
		return err
	}

	// Validate optimizations configuration
	if err := validateOptimizations(cfg); err != nil {
		return err
	}

	// Validate S3 client authentication configuration
	if err := validateS3Clients(cfg); err != nil {
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

// validateLicenseAndEncryption validates both license and encryption configuration
func validateLicenseAndEncryption(cfg *Config) error {
	// Load and validate license
	licenseToken := license.LoadLicense(cfg.LicenseFile)
	validator := license.NewValidator()
	result := validator.ValidateLicense(licenseToken)

	// Log license information
	license.LogLicenseInfo(result)

	// Validate encryption configuration
	if err := validateEncryption(cfg); err != nil {
		return err
	}

	// Check if encryption provider requires license
	if cfg.Encryption.EncryptionMethodAlias != "" {
		// Find the active provider
		for _, provider := range cfg.Encryption.Providers {
			if provider.Alias == cfg.Encryption.EncryptionMethodAlias {
				// Log provider restriction info
				license.LogProviderRestriction(provider.Type, provider.Alias, result.Valid)

				// Validate provider type against license
				if err := validator.ValidateProviderType(provider.Type); err != nil {
					return err
				}
				break
			}
		}
	}

	return nil
}

// validateEncryption validates the encryption configuration
func validateEncryption(cfg *Config) error {
	// Integrity verification is just a boolean, no validation needed beyond type checking

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
}

// validateOptimizations validates the optimizations configuration
func validateOptimizations(cfg *Config) error {
	// Only validate if streaming buffer size is explicitly set
	if cfg.Optimizations.StreamingBufferSize > 0 {
		// Validate streaming buffer size (4KB to 2MB range)
		if cfg.Optimizations.StreamingBufferSize < 4*1024 {
			return fmt.Errorf("optimizations.streaming_buffer_size: minimum value is 4KB (4096 bytes), got %d", cfg.Optimizations.StreamingBufferSize)
		}
		if cfg.Optimizations.StreamingBufferSize > 2*1024*1024 {
			return fmt.Errorf("optimizations.streaming_buffer_size: maximum value is 2MB (2097152 bytes), got %d", cfg.Optimizations.StreamingBufferSize)
		}
	}

	// Validate streaming segment size (5MB to 5GB range)
	if cfg.Optimizations.StreamingSegmentSize > 0 {
		if cfg.Optimizations.StreamingSegmentSize < 5*1024*1024 {
			return fmt.Errorf("optimizations.streaming_segment_size: minimum value is 5MB (5242880 bytes), got %d", cfg.Optimizations.StreamingSegmentSize)
		}
		if cfg.Optimizations.StreamingSegmentSize > 5*1024*1024*1024 {
			return fmt.Errorf("optimizations.streaming_segment_size: maximum value is 5GB (5368709120 bytes), got %d", cfg.Optimizations.StreamingSegmentSize)
		}
	}

	// Validate threshold values when adaptive buffering is enabled
	if cfg.Optimizations.EnableAdaptiveBuffering {
		if cfg.Optimizations.StreamingThreshold > 0 && cfg.Optimizations.StreamingThreshold < 1*1024*1024 {
			return fmt.Errorf("optimizations.streaming_threshold: minimum value is 1MB (1048576 bytes), got %d", cfg.Optimizations.StreamingThreshold)
		}
	}

	return nil
}

// validateS3Clients validates the S3 client authentication configuration
func validateS3Clients(cfg *Config) error {
	// S3 client authentication is REQUIRED - application will not start without it
	if len(cfg.S3Clients) == 0 {
		return fmt.Errorf("s3_clients configuration is required - at least one S3 client must be configured for authentication")
	}

	// Validate each client credential
	for i, client := range cfg.S3Clients {
		if client.Type == "" {
			return fmt.Errorf("s3_clients[%d].type is required", i)
		}

		// Currently only "static" type is supported
		if client.Type != "static" {
			return fmt.Errorf("s3_clients[%d].type: unsupported type '%s' (supported: static)", i, client.Type)
		}

		if client.AccessKeyID == "" {
			return fmt.Errorf("s3_clients[%d].access_key_id is required", i)
		}

		if client.SecretKey == "" {
			return fmt.Errorf("s3_clients[%d].secret_key is required", i)
		}

		// Security validation: minimum key length
		if len(client.AccessKeyID) < 8 {
			return fmt.Errorf("s3_clients[%d].access_key_id must be at least 8 characters long", i)
		}

		if len(client.SecretKey) < 16 {
			return fmt.Errorf("s3_clients[%d].secret_key must be at least 16 characters long", i)
		}

		// Check for duplicate access_key_ids
		for j := i + 1; j < len(cfg.S3Clients); j++ {
			if cfg.S3Clients[j].AccessKeyID == client.AccessKeyID {
				return fmt.Errorf("s3_clients[%d] and s3_clients[%d] have duplicate access_key_id: %s", i, j, client.AccessKeyID)
			}
		}
	}

	// Validate security configuration
	if err := validateS3Security(cfg); err != nil {
		return err
	}

	return nil
}

// validateS3Security validates S3 security configuration
func validateS3Security(cfg *Config) error {
	sec := cfg.S3Security

	// Validate clock skew settings
	if sec.MaxClockSkewSeconds < 0 {
		return fmt.Errorf("s3_security.max_clock_skew_seconds cannot be negative")
	}
	if sec.MaxClockSkewSeconds > 3600 { // 1 hour max
		return fmt.Errorf("s3_security.max_clock_skew_seconds cannot exceed 3600 seconds (1 hour)")
	}

	// Validate rate limiting settings
	if sec.EnableRateLimiting {
		if sec.MaxRequestsPerMinute <= 0 {
			return fmt.Errorf("s3_security.max_requests_per_minute must be positive when rate limiting is enabled")
		}
		if sec.MaxRequestsPerMinute > 10000 {
			return fmt.Errorf("s3_security.max_requests_per_minute cannot exceed 10000")
		}
	}

	// Validate failed attempts threshold
	if sec.MaxFailedAttempts < 0 {
		return fmt.Errorf("s3_security.max_failed_attempts cannot be negative")
	}
	if sec.MaxFailedAttempts > 1000 {
		return fmt.Errorf("s3_security.max_failed_attempts cannot exceed 1000")
	}

	// Validate unblock IP seconds
	if sec.UnblockIPSeconds < 0 {
		return fmt.Errorf("s3_security.unblock_ip_seconds cannot be negative")
	}
	if sec.UnblockIPSeconds > 86400 { // 24 hours max
		return fmt.Errorf("s3_security.unblock_ip_seconds cannot exceed 86400 seconds (24 hours)")
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

// ValidateS3ClientCredentials validates S3 client credentials against configured allowed clients
// Returns true if credentials are valid
func (cfg *Config) ValidateS3ClientCredentials(accessKeyID, secretKey string) bool {
	// Check if the provided credentials match any configured client
	for _, client := range cfg.S3Clients {
		if client.AccessKeyID == accessKeyID && client.SecretKey == secretKey {
			return true
		}
	}

	return false
}

// IsS3ClientAuthEnabled returns true if S3 client authentication is enabled (always true now)
func (cfg *Config) IsS3ClientAuthEnabled() bool {
	return true  // Authentication is always required
}

// GetS3SecurityConfig returns the S3 security configuration with defaults
func (cfg *Config) GetS3SecurityConfig() S3SecurityConfig {
	security := cfg.S3Security

	// Apply defaults if not set
	if security.MaxClockSkewSeconds == 0 {
		security.MaxClockSkewSeconds = 900 // 15 minutes default
	}
	if security.MaxRequestsPerMinute == 0 {
		security.MaxRequestsPerMinute = 100 // 100 requests per minute default
	}
	if security.MaxFailedAttempts == 0 {
		security.MaxFailedAttempts = 10 // 10 failed attempts default
	}

	return security
}

// GetProviderConfig returns the configuration parameters for a provider
func (provider *EncryptionProvider) GetProviderConfig() map[string]interface{} {
	if provider.Config == nil {
		provider.Config = make(map[string]interface{})
	}
	return provider.Config
}

// GetStreamingSegmentSize returns the streaming segment size from optimizations config
func (cfg *Config) GetStreamingSegmentSize() int64 {
	// Use optimizations.streaming_segment_size
	if cfg.Optimizations.StreamingSegmentSize > 0 {
		return cfg.Optimizations.StreamingSegmentSize
	}

	// Default to 12MB if nothing is configured
	return 12 * 1024 * 1024
}
