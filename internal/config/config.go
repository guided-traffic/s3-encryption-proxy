package config

import (
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"regexp"

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
	InsecureSkipVerify bool   `mapstructure:"insecure_skip_verify"` // Only for development/testing
}

// EncryptionProvider holds configuration for a single encryption provider
type EncryptionProvider struct {
	Alias string `mapstructure:"alias"` // Unique identifier for this provider
	Type  string `mapstructure:"type"`  // "aes" or "none"; "tink" is refused
	// Description is never read. It is declared so that `description:` is
	// consumed here instead of falling into Config through `,remain`, where the
	// provider would reject it as an unknown key.
	Description string                 `mapstructure:"description"`
	Config      map[string]interface{} `mapstructure:",remain"` // Provider-specific configuration parameters
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
}

// S3ClientCredentials holds credentials for a single S3 client
type S3ClientCredentials struct {
	Type        string `mapstructure:"type"`          // "static" (more types may be added later)
	AccessKeyID string `mapstructure:"access_key_id"` // S3 Access Key ID
	SecretKey   string `mapstructure:"secret_key"`    // S3 Secret Access Key
	Description string `mapstructure:"description"`   // Optional description for this client
}

// S3SecurityConfig holds S3 client authentication security configuration
type S3SecurityConfig struct {
	// Maximum clock skew allowed in seconds (default: 900 = 15 minutes)
	MaxClockSkewSeconds int `mapstructure:"max_clock_skew_seconds"`
}

// OptimizationsConfig holds performance optimization settings
type OptimizationsConfig struct {
	// Streaming Segment Configuration
	StreamingSegmentSize int64 `mapstructure:"streaming_segment_size" validate:"min=5242880,max=5368709120"` // 5MB - 5GB, default: 12MB

	// Chunked Encoding Behavior
	CleanAWSSignatureV4Chunked bool `mapstructure:"clean_aws_signature_v4_chunked"` // Enable AWS Signature V4 chunked decoding (default: true)

	// Multipart Session Cleanup
	MultipartSessionCleanupInterval int  `mapstructure:"multipart_session_cleanup_interval" validate:"min=60"` // Cleanup interval in seconds (default: 300 = 5 minutes)
	MultipartSessionMaxAge          int  `mapstructure:"multipart_session_max_age" validate:"min=900"`         // Max age in seconds (default: 3600 = 1 hour)
	CleanHTTPTransferChunked        bool `mapstructure:"clean_http_transfer_chunked"`                          // Enable optimized standard HTTP chunked handling (default: true)

	// Multipart Upload Parallelism
	// Number of concurrent S3 UploadPart calls dispatched from putObjectAutoMultipart
	// after each part has been encrypted in order. Encryption stays sequential
	// (CTR streams require it); only the S3 network round-trip is parallelised.
	MultipartUploadConcurrency int `mapstructure:"multipart_upload_concurrency" validate:"min=1,max=32"` // 1-32, default: 4

	// MultipartShortPartBufferSize bounds what one client-driven upload may hold
	// for a part that does not cover whole segments. Such a part cannot be stored
	// on its own, so it waits for Complete; this is the memory an operator budgets
	// for that, per session (ADR 0011).
	MultipartShortPartBufferSize int64 `mapstructure:"multipart_short_part_buffer_size"` // default: 64MB
}

// MonitoringConfig holds monitoring configuration
type MonitoringConfig struct {
	Enabled     bool   `mapstructure:"enabled"`      // Enable/disable monitoring
	BindAddress string `mapstructure:"bind_address"` // Address to bind monitoring server (default: :9090)
	MetricsPath string `mapstructure:"metrics_path"` // Path for metrics endpoint (default: /metrics)
	// PprofEnabled serves /debug/pprof on its own listener, never on the
	// monitoring listener: a heap or goroutine profile of this process contains
	// DEKs and plaintext buffers (default: false).
	PprofEnabled bool `mapstructure:"pprof_enabled"`
	// PprofBindAddress is where that listener binds. It must be a loopback
	// address; anything else is refused at startup (default: 127.0.0.1:6060).
	PprofBindAddress string `mapstructure:"pprof_bind_address"`
}

// Config holds the application configuration
type Config struct {
	// Server configuration
	BindAddress       string    `mapstructure:"bind_address"`
	LogLevel          string    `mapstructure:"log_level"`
	LogFormat         string    `mapstructure:"log_format"` // "text" (default) or "json"
	LogHealthRequests bool      `mapstructure:"log_health_requests"`
	ShutdownTimeout   int       `mapstructure:"shutdown_timeout"` // Graceful shutdown timeout in seconds
	TLS               TLSConfig `mapstructure:"tls"`

	// Monitoring configuration
	Monitoring MonitoringConfig `mapstructure:"monitoring"`

	// S3 configuration
	S3Backend S3BackendConfig `mapstructure:"s3_backend"`

	// S3 Client Authentication configuration
	S3Clients  []S3ClientCredentials `mapstructure:"s3_clients"`
	S3Security S3SecurityConfig      `mapstructure:"s3_security"`

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

	// Handle provider configs manually due to viper's unmarshaling issues
	if err := loadProviderConfigs(&cfg); err != nil {
		return nil, fmt.Errorf("provider config loading failed: %w", err)
	}

	// Expand ${VAR} environment variable references in config values
	if err := expandConfigEnvVars(&cfg); err != nil {
		return nil, fmt.Errorf("environment variable expansion failed: %w", err)
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

// setDefaults sets default configuration values
func setDefaults() {
	viper.SetDefault("bind_address", "0.0.0.0:8080")
	viper.SetDefault("log_level", "info")
	viper.SetDefault("log_format", "text")
	viper.SetDefault("log_health_requests", false)

	// New s3_backend configuration defaults
	viper.SetDefault("s3_backend.region", "us-east-1")
	viper.SetDefault("s3_backend.insecure_skip_verify", false)

	// TLS defaults
	viper.SetDefault("tls.enabled", false)

	// Monitoring defaults
	viper.SetDefault("monitoring.enabled", false)
	viper.SetDefault("monitoring.bind_address", ":9090")
	viper.SetDefault("monitoring.metrics_path", "/metrics")
	viper.SetDefault("monitoring.pprof_enabled", false)
	viper.SetDefault("monitoring.pprof_bind_address", "127.0.0.1:6060")

	// License defaults
	viper.SetDefault("license_file", "config/license.jwt")

	// Optimizations defaults
	viper.SetDefault("optimizations.streaming_segment_size", 12*1024*1024)    // 12MB default
	viper.SetDefault("optimizations.clean_aws_signature_v4_chunked", true)    // Enable by default
	viper.SetDefault("optimizations.clean_http_transfer_chunked", true)       // Enable by default
	viper.SetDefault("optimizations.multipart_session_cleanup_interval", 300) // 5 minutes default
	viper.SetDefault("optimizations.multipart_session_max_age", 3600)         // 1 hour default
	viper.SetDefault("optimizations.multipart_upload_concurrency", 4)         // 4 parallel S3 UploadPart calls
	viper.SetDefault("optimizations.multipart_short_part_buffer_size", 67108864)

	// New encryption defaults
	viper.SetDefault("encryption.metadata_key_prefix", "s3ep-")

	// S3 Security defaults
	viper.SetDefault("s3_security.max_clock_skew_seconds", 900)

}

// validate validates the configuration
func validate(cfg *Config) error {
	if cfg.S3Backend.TargetEndpoint == "" {
		return fmt.Errorf("s3_backend.target_endpoint is required")
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

	// Validate the monitoring listeners
	if err := validateMonitoring(cfg); err != nil {
		return err
	}

	return nil
}

// validateMonitoring validates the monitoring listeners. Only pprof is
// sensitive: a heap or goroutine profile of this process contains DEKs and
// plaintext buffers, so its listener may only ever bind a loopback address. An
// operator reaches it through an SSH tunnel or kubectl port-forward.
func validateMonitoring(cfg *Config) error {
	if !cfg.Monitoring.PprofEnabled {
		return nil
	}

	if err := requireLoopbackAddress(cfg.Monitoring.PprofBindAddress); err != nil {
		return fmt.Errorf("monitoring.pprof_bind_address: %w", err)
	}

	return nil
}

// requireLoopbackAddress accepts a host:port address only if its host is a
// loopback IP literal or the name "localhost". A name is otherwise refused
// rather than resolved: resolving at startup would make the proxy fail to boot
// when a resolver is unavailable, and a name that points at loopback today can
// point elsewhere tomorrow while the process keeps running.
func requireLoopbackAddress(addr string) error {
	if addr == "" {
		return fmt.Errorf("is required when monitoring.pprof_enabled is true (for example 127.0.0.1:6060)")
	}

	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("%q is not a valid host:port address: %w", addr, err)
	}
	if port == "" {
		return fmt.Errorf("%q has no port", addr)
	}
	if host == "" {
		return fmt.Errorf("%q binds every interface; pprof must bind a loopback address such as 127.0.0.1:%s", addr, port)
	}

	if host == "localhost" {
		return nil
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("host %q of %q is a name; pprof takes a loopback IP literal or \"localhost\", so that the bound address cannot change under the running process", host, addr)
	}
	if !ip.IsLoopback() {
		return fmt.Errorf("%q is not a loopback address; a pprof profile contains key material and plaintext, so only 127.0.0.0/8 or [::1] are allowed", addr)
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

// metadataKeyPrefixPattern is what encryption.metadata_key_prefix must match.
//
// Lowercase, because S3 lower-cases metadata keys in transit while the proxy's
// own comparisons do not: a prefix with a capital in it never matches on the way
// back, which silently disables decryption and leaks the encryption metadata to
// the client. Non-empty, because an empty prefix makes the writer store
// "encrypted-dek" unprefixed while isNoneProviderData still looks for "s3ep-",
// so every GET decides the object is unencrypted and serves the ciphertext with
// a 200. Neither is repairable by normalisation - a configuration that would
// have turned the proxy into a shredder has to fail loudly.
var metadataKeyPrefixPattern = regexp.MustCompile(`^[a-z0-9-]+$`)

const (
	// aesKeyBytes is the only accepted master key length.
	aesKeyBytes = 32
	// aesKeyMinDistinct is the entropy floor a random 32-byte key clears with
	// overwhelming probability; a typed key does not.
	aesKeyMinDistinct = 16
)

// validateEncryption validates the encryption configuration
func validateEncryption(cfg *Config) error {
	// First, because the provider branch below returns early for every
	// configuration that actually has providers.
	if p := cfg.Encryption.MetadataKeyPrefix; p != nil && !metadataKeyPrefixPattern.MatchString(*p) {
		return fmt.Errorf(
			"encryption.metadata_key_prefix must be non-empty and match %s, got: %q",
			metadataKeyPrefixPattern, *p)
	}

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
		return validateAESKey(provider.Config, index)
	case "none":
		// No validation needed for "none" provider - no encryption parameters required
	default:
		return fmt.Errorf("encryption.providers[%d].type: unsupported encryption type: %s (supported: aes, none)", index, provider.Type)
	}

	return nil
}

// validateAESKey admits only what a master key may be: base64 of exactly 32
// random bytes.
//
// The two shape checks reject what a human types instead of generating. Random
// bytes are practically never all printable (2^-58 for 32 bytes) and practically
// always carry far more than 16 distinct values, so a passphrase and a
// base64-wrapped hex string both fail here rather than becoming an AES-256 key
// whose real entropy is a fraction of its length. Startup is the place for this:
// the alternative is discovering it at the first PUT.
func validateAESKey(providerConfig map[string]interface{}, index int) error {
	keyStr, ok := providerConfig["aes_key"].(string)
	if !ok || keyStr == "" {
		return fmt.Errorf("encryption.providers[%d]: aes_key is required when using aes encryption", index)
	}

	key, err := base64.StdEncoding.DecodeString(keyStr)
	if err != nil || len(key) != aesKeyBytes {
		return aesKeyError(index, fmt.Sprintf("must be base64 of exactly %d bytes", aesKeyBytes))
	}

	printable := true
	distinct := make(map[byte]struct{}, aesKeyBytes)
	for _, b := range key {
		if b < 0x20 || b > 0x7e {
			printable = false
		}
		distinct[b] = struct{}{}
	}

	if printable {
		return aesKeyError(index, "decodes to printable characters only, which is a passphrase and not a key")
	}
	if len(distinct) < aesKeyMinDistinct {
		return aesKeyError(index, fmt.Sprintf("decodes to only %d distinct byte values", len(distinct)))
	}

	return nil
}

func aesKeyError(index int, reason string) error {
	return fmt.Errorf(
		"encryption.providers[%d].config.aes_key: %s; generate one with s3ep-keygen or 'openssl rand -base64 32'"+
			" (base64 of a hex string is refused)",
		index, reason)
}

// validateOptimizations validates the optimizations configuration
func validateOptimizations(cfg *Config) error {
	// Validate streaming segment size (5MB to 5GB range)
	if cfg.Optimizations.StreamingSegmentSize > 0 {
		if cfg.Optimizations.StreamingSegmentSize < 5*1024*1024 {
			return fmt.Errorf("optimizations.streaming_segment_size: minimum value is 5MB (5242880 bytes), got %d", cfg.Optimizations.StreamingSegmentSize)
		}
		if cfg.Optimizations.StreamingSegmentSize > 5*1024*1024*1024 {
			return fmt.Errorf("optimizations.streaming_segment_size: maximum value is 5GB (5368709120 bytes), got %d", cfg.Optimizations.StreamingSegmentSize)
		}
	}

	// Validate multipart upload concurrency (1 to 32 range)
	if cfg.Optimizations.MultipartShortPartBufferSize != 0 &&
		cfg.Optimizations.MultipartShortPartBufferSize < 5*1024*1024 {
		return fmt.Errorf(
			"optimizations.multipart_short_part_buffer_size: minimum value is 5MB (5242880 bytes), got %d",
			cfg.Optimizations.MultipartShortPartBufferSize)
	}

	if cfg.Optimizations.MultipartUploadConcurrency != 0 {
		if cfg.Optimizations.MultipartUploadConcurrency < 1 {
			return fmt.Errorf("optimizations.multipart_upload_concurrency: minimum value is 1, got %d", cfg.Optimizations.MultipartUploadConcurrency)
		}
		if cfg.Optimizations.MultipartUploadConcurrency > 32 {
			return fmt.Errorf("optimizations.multipart_upload_concurrency: maximum value is 32, got %d", cfg.Optimizations.MultipartUploadConcurrency)
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

	return nil
}

// GetActiveProvider returns the active encryption provider (used for encrypting)
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
	validTypes := []string{"aes", "none"}
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

// GetStreamingSegmentSize returns the streaming segment size from optimizations config
func (cfg *Config) GetStreamingSegmentSize() int64 {
	// Use optimizations.streaming_segment_size
	if cfg.Optimizations.StreamingSegmentSize > 0 {
		return cfg.Optimizations.StreamingSegmentSize
	}

	// Default to 12MB if nothing is configured
	return 12 * 1024 * 1024
}
