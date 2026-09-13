package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"regexp"

	"github.com/go-viper/mapstructure/v2"
	"github.com/guided-traffic/s3-encryption-proxy/internal/license"
	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption/dataencryption"
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
	Type  string `mapstructure:"type"`  // "aes" or "exit"; "none" and "tink" are refused by name
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
	// Maximum clock skew allowed in seconds (default: 900 = 15 minutes).
	// It governs both authentication forms (ADR 0014 D4). 0 is refused rather
	// than read as "the default": at second granularity it can only ever mean a
	// misunderstanding, and a silent fixup is what ADR 0017 D8 forbids.
	MaxClockSkewSeconds int `mapstructure:"max_clock_skew_seconds"`

	// Longest lifetime a pre-signed URL may declare, in seconds (default 3600).
	// Deliberately below the S3 maximum of seven days: a leaked URL is a bearer
	// credential for exactly as long as it says (ADR 0014 D5).
	MaxPresignExpirySeconds int `mapstructure:"max_presign_expiry_seconds"`
}

// OptimizationsConfig holds performance optimization settings
type OptimizationsConfig struct {
	// Streaming Segment Configuration
	StreamingSegmentSize int64 `mapstructure:"streaming_segment_size" validate:"min=5242880,max=5368709120"` // 5MB - 5GB, default: 12MB

	// Multipart Session Cleanup
	MultipartSessionCleanupInterval int `mapstructure:"multipart_session_cleanup_interval"` // Cleanup interval in seconds (default: 300 = 5 minutes)
	MultipartSessionIdleTimeout     int `mapstructure:"multipart_session_idle_timeout"`     // Seconds a client-driven upload may go untouched before the proxy abandons it (default: 3600)

	// Multipart Upload Parallelism
	// Number of concurrent S3 UploadPart calls dispatched from putObjectAutoMultipart
	// after each part has been encrypted in order. Encryption stays sequential
	// (CTR streams require it); only the S3 network round-trip is parallelised.
	MultipartUploadConcurrency int `mapstructure:"multipart_upload_concurrency" validate:"min=1,max=32"` // 1-32, default: 4

	// MultipartShortPartBufferSize bounds what all open client-driven uploads
	// together may hold for a part that does not cover whole segments. Such a part
	// cannot be stored on its own, so it waits for Complete; this is the memory an
	// operator budgets for that, process-wide (ADR 0011 D5).
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

	// Listener budgets, in seconds (ADR 0015). A transfer is bounded by the
	// client and by shutdown, not by a server wall clock: ReadTimeout and
	// WriteTimeout default to 0, which is Go's "no deadline", so no healthy
	// transfer is ever cut for being long or slow. They exist as keys for an
	// operator who knows their workload and wants a ceiling anyway.
	//
	// The other two bound what is not a transfer, and neither may be 0:
	// ReadHeaderTimeout is the only limit on a connection that opens and never
	// completes its headers, and with both body budgets at 0 an IdleTimeout of 0
	// would leave a keep-alive connection open forever (net/http falls back to
	// ReadTimeout, which is itself 0).
	ReadTimeout       int `mapstructure:"read_timeout"`
	WriteTimeout      int `mapstructure:"write_timeout"`
	ReadHeaderTimeout int `mapstructure:"read_header_timeout"`
	IdleTimeout       int `mapstructure:"idle_timeout"`

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

// InitConfig initializes the configuration system. A configuration file that
// cannot be read refuses the start, and the error names it: the alternative was
// to carry on with the defaults, where the start still failed but told the
// operator that s3_backend.target_endpoint was missing - pointing at a key their
// file may well have set, instead of saying that the file was never read.
func InitConfig(cfgFile string) error {
	if cfgFile != "" {
		// Use config file from the flag
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("cannot determine the home directory to search for a configuration file: %w", err)
		}

		// Search config in home directory with name ".s3-encryption-proxy" (without extension)
		viper.AddConfigPath(home)
		viper.AddConfigPath(".")
		viper.AddConfigPath("./config")
		viper.SetConfigType("yaml")
		viper.SetConfigName(".s3-encryption-proxy")
	}

	// No AutomaticEnv. It bound every key to an S3EP_-prefixed variable and let
	// it win over the file, including s3_backend.insecure_skip_verify,
	// monitoring.pprof_enabled and encryption.metadata_key_prefix — so a control
	// an operator had written into the configuration could be switched off from
	// outside it, with nothing in the file or the log to say so, and a misspelt
	// variable was ignored in the same silence ADR 0013 D11 removed for the file.
	// The supported mechanism is a ${VAR} reference written into the value, which
	// is visible where it acts and fails the start when it is unset.

	// Set defaults
	setDefaults()

	if err := viper.ReadInConfig(); err != nil {
		// Finding no file in the search path is not a misread file: nothing was
		// named, so nothing was misread, and the start still fails on the keys
		// that have no default (ADR 0013 D12). Only viper's search reports this
		// error; a --config path that does not exist is an ordinary open failure
		// and refuses the start with the rest.
		var notFound viper.ConfigFileNotFoundError
		if errors.As(err, &notFound) {
			return nil
		}
		return fmt.Errorf("failed to read the configuration: %w", err)
	}
	fmt.Fprintf(os.Stderr, "Using config file: %s\n", viper.ConfigFileUsed())
	return nil
}

// Load loads the configuration from viper
func Load() (*Config, error) {
	var cfg Config
	// ErrorUnused: a key the proxy does not define refuses the start and the
	// error names it (ADR 0013 D11). It is the only mechanism that makes this
	// release's twenty-two deleted keys visible to an operator: without it a removed
	// key is dropped in silence and the setting the operator believes is in
	// force is not. A misspelling gets the same treatment, which is the point.
	//
	// A provider block keeps swallowing its own parameters: EncryptionProvider
	// carries a `,remain` field, and mapstructure clears the unused-key set
	// before it applies this check.
	// multipart_session_max_age measured a session from its creation;
	// multipart_session_idle_timeout measures it from the last part. The same
	// number means something else under the new key, so the old one is refused by
	// name rather than left to ErrorUnused's generic message: an operator has to
	// see the change in meaning once, not discover it from behaviour.
	if viper.IsSet("optimizations.multipart_session_max_age") {
		return nil, fmt.Errorf(
			"optimizations.multipart_session_max_age no longer exists; use " +
				"optimizations.multipart_session_idle_timeout, which counts from the last part " +
				"an upload received rather than from when it was created, so a transfer still " +
				"running is no longer abandoned for taking long")
	}

	// 0 does not mean "no timeout" here, it means "every session is already
	// idle": the sweeper would end a client-driven upload at the backend moments
	// after it opened. setDefaults fills 3600, so this is checked against what
	// the configuration actually wrote rather than against the decoded struct,
	// where an absent key and a written 0 look the same. ADR 0017 D8: a value
	// that switches a check off is refused by name, not quietly replaced.
	//
	// InConfig, not IsSet: viper consults its defaults unconditionally, so IsSet
	// is true for every key setDefaults fills - which is every key here. InConfig
	// searches the parsed file alone, which is the question being asked.
	if viper.InConfig("optimizations.multipart_session_idle_timeout") &&
		viper.GetInt("optimizations.multipart_session_idle_timeout") < 1 {
		return nil, fmt.Errorf(
			"optimizations.multipart_session_idle_timeout: minimum value is 1 second, got %d; "+
				"a value below 1 makes every client-driven upload look idle the moment the "+
				"sweeper runs, and it is ended at the backend",
			viper.GetInt("optimizations.multipart_session_idle_timeout"))
	}

	// Same question one key over: a written 0 switched the session sweeper off,
	// and the short-part budget an abandoned upload holds was then never given
	// back (ADR 0028 residual risks, ADR 0017 D8).
	if viper.InConfig("optimizations.multipart_session_cleanup_interval") &&
		viper.GetInt("optimizations.multipart_session_cleanup_interval") < 1 {
		return nil, fmt.Errorf(
			"optimizations.multipart_session_cleanup_interval: minimum value is 1 second, got %d; "+
				"a value below 1 switches the session sweeper off, and the short-part budget an "+
				"abandoned upload holds is never given back",
			viper.GetInt("optimizations.multipart_session_cleanup_interval"))
	}

	unmarshalErr := viper.Unmarshal(&cfg, func(dc *mapstructure.DecoderConfig) {
		dc.ErrorUnused = true
	})
	if unmarshalErr != nil {
		// Do not swallow the library's message: it names the offending keys.
		return nil, fmt.Errorf(
			"failed to unmarshal config: %w\n"+
				"A key this version does not define stops the start instead of being ignored. "+
				"Remove it, or fix the spelling; keys removed by a release are listed in its notes",
			unmarshalErr)
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

// licenseFileIsBinding reports whether the operator wrote license_file. When
// they did, that path is the only one read (ADR 0016); when they did not, the
// license loader falls back to the well-known locations.
//
// InConfig, not IsSet: setDefaults fills license_file, and viper's IsSet
// consults the defaults, so it answers true whether or not the key was written.
func licenseFileIsBinding() bool {
	return viper.InConfig("license_file")
}

// LoadAndStartLicense loads configuration and returns license validator for runtime monitoring
func LoadAndStartLicense() (*Config, *license.LicenseValidator, error) {
	cfg, err := Load()
	if err != nil {
		return nil, nil, err
	}

	// Create and configure license validator for runtime monitoring
	licenseToken, err := license.LoadLicense(cfg.LicenseFile, licenseFileIsBinding())
	if err != nil {
		return nil, nil, err
	}
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

	// Listener budgets (ADR 0015). 0 on the two body budgets is Go's "no
	// deadline"; the header and idle budgets keep the values the fixed
	// implementation used.
	viper.SetDefault("read_timeout", 0)
	viper.SetDefault("write_timeout", 0)
	viper.SetDefault("read_header_timeout", 30)
	viper.SetDefault("idle_timeout", 60)

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
	viper.SetDefault("optimizations.multipart_session_cleanup_interval", 300) // 5 minutes default
	viper.SetDefault("optimizations.multipart_session_idle_timeout", 3600)    // 1 hour without a part
	viper.SetDefault("optimizations.multipart_upload_concurrency", 4)         // 4 parallel S3 UploadPart calls
	viper.SetDefault("optimizations.multipart_short_part_buffer_size", 67108864)

	// New encryption defaults
	viper.SetDefault("encryption.metadata_key_prefix", "s3ep-")

	// S3 Security defaults
	viper.SetDefault("s3_security.max_clock_skew_seconds", 900)
	viper.SetDefault("s3_security.max_presign_expiry_seconds", 3600)

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

	// After the encryption block, so GetActiveProvider can be trusted
	if err := validateBackendTransport(cfg); err != nil {
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

	// Validate the listener budgets
	if err := validateListenerBudgets(cfg); err != nil {
		return err
	}

	return nil
}

// backendUsesTLS reports whether target_endpoint addresses the backend over TLS.
// A scheme it does not recognise is an error rather than a guess: the string
// reaches the SDK verbatim, and what the SDK makes of a scheme-less endpoint is
// undefined (ADR 0013 D4).
func backendUsesTLS(endpoint string) (bool, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return false, fmt.Errorf("s3_backend.target_endpoint is not a URL (%q): %w", endpoint, err)
	}
	switch parsed.Scheme {
	case "https":
		return true, nil
	case "http":
		return false, nil
	default:
		return false, fmt.Errorf(
			"s3_backend.target_endpoint must start with https:// or http:// (%q)", endpoint)
	}
}

// validateBackendTransport refuses a plain-HTTP backend under every provider
// that resolves, the exit provider included (ADR 0013 D5): the backend
// credential travels in a SigV4 header either way, and so do bucket names and
// object keys. It is a configuration inconsistency, not a runtime
// one: it fires before a listener or an S3 client exists, and every entry point
// that loads configuration gets it.
//
// When no provider resolves the check abstains — the configuration has other
// problems and this one has nothing to say about them.
func validateBackendTransport(cfg *Config) error {
	usesTLS, err := backendUsesTLS(cfg.S3Backend.TargetEndpoint)
	if err != nil {
		return err
	}
	if usesTLS {
		return nil
	}

	provider, err := cfg.GetActiveProvider()
	if err != nil || provider == nil {
		return nil //nolint:nilerr // not this check's error to report
	}

	return fmt.Errorf(
		"s3_backend.target_endpoint is plain HTTP (%q), and the active encryption provider is %q "+
			"(type %q): the backend credential would travel in a SigV4 header over plaintext and a "+
			"listener on that leg would learn every bucket name, object key and object size. "+
			"aws-sdk-go-v2 also only sends an unseekable streaming body with UNSIGNED-PAYLOAD over "+
			"TLS, so a single-request upload fails with \"failed to seek body to start\". "+
			"Use an https:// endpoint",
		cfg.S3Backend.TargetEndpoint, provider.Alias, provider.Type)
}

// validateListenerBudgets checks the four listener budgets of ADR 0015. The two
// body budgets accept 0, which is what the shipped default is and what makes a
// transfer bounded by the client rather than by the server. The two that bound
// what is not a transfer do not: with every budget at 0 a connection that never
// finishes its headers, and a keep-alive connection that never sends another
// request, would both be held indefinitely.
func validateListenerBudgets(cfg *Config) error {
	for _, b := range []struct {
		key   string
		value int
	}{
		{"read_timeout", cfg.ReadTimeout},
		{"write_timeout", cfg.WriteTimeout},
	} {
		if b.value < 0 {
			return fmt.Errorf("%s: must not be negative, got %d (0 means no limit)", b.key, b.value)
		}
	}
	for _, b := range []struct {
		key   string
		value int
	}{
		{"read_header_timeout", cfg.ReadHeaderTimeout},
		{"idle_timeout", cfg.IdleTimeout},
	} {
		if b.value < 1 {
			return fmt.Errorf(
				"%s: must be at least 1 second, got %d — it is what bounds a connection that is not transferring anything",
				b.key, b.value)
		}
	}
	if cfg.ShutdownTimeout < 0 {
		return fmt.Errorf("shutdown_timeout: must not be negative, got %d", cfg.ShutdownTimeout)
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
	licenseToken, err := license.LoadLicense(cfg.LicenseFile, licenseFileIsBinding())
	if err != nil {
		return err
	}
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
// "encrypted-dek" unprefixed while the read path still looks for "s3ep-", so
// every GET decides the object is not one this proxy wrote. Neither is
// repairable by normalisation - a configuration that would have turned the proxy
// into a shredder has to fail loudly.
// The shape is ADR 0009 D2: at least four characters, starting with a lowercase
// alphanumeric, ending in a dash. The trailing dash is what keeps the namespace
// separable — without it a prefix "s3ep" also claims every client key beginning
// "s3ep", and four characters is short enough for any real name while long
// enough that a prefix cannot collide with a common metadata key by accident.
var metadataKeyPrefixPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{2,}-$`)

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
			"encryption.metadata_key_prefix: lowercase letters, digits and dashes only, "+
				"starting with a letter or a digit, at least four characters, ending in \"-\" "+
				"(%s), got: %q",
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
		return fmt.Errorf(
			"encryption.providers[%d].type: 'tink' is not a provider of this proxy (supported: aes, exit)", index)
	case "aes":
		return validateAESKey(provider.Config, index)
	case "exit":
		// The exit provider takes no configuration: it writes plaintext and reads
		// what is already encrypted through the provider that wrapped it.
	case "none":
		return fmt.Errorf(
			"encryption.providers[%d].type: 'none' is now 'exit'. The exit provider writes "+
				"plaintext and still decrypts objects this proxy encrypted earlier, so keep the "+
				"provider that holds their key configured alongside it", index)
	default:
		return fmt.Errorf("encryption.providers[%d].type: unsupported encryption type: %s (supported: aes, exit)", index, provider.Type)
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
		// The producer uses this as the part size, and every part but the last
		// has to cover whole segments of the stored format (ADR 0003). An
		// unaligned value passes the range check and then fails every upload
		// larger than one part, at the backend, with a 500 — so it is refused
		// here instead.
		if cfg.Optimizations.StreamingSegmentSize%dataencryption.SegmentSize != 0 {
			return fmt.Errorf(
				"optimizations.streaming_segment_size: must be a multiple of %d bytes (64 KiB), got %d",
				dataencryption.SegmentSize, cfg.Optimizations.StreamingSegmentSize)
		}
	}

	if cfg.Optimizations.MultipartShortPartBufferSize != 0 &&
		cfg.Optimizations.MultipartShortPartBufferSize < 5*1024*1024 {
		return fmt.Errorf(
			"optimizations.multipart_short_part_buffer_size: minimum value is 5MB (5242880 bytes), got %d",
			cfg.Optimizations.MultipartShortPartBufferSize)
	}

	// A negative interval would be a sweeper that never runs: the sessions it
	// would have expired keep their buffers (ADR 0017 D8).
	if cfg.Optimizations.MultipartSessionCleanupInterval < 0 {
		return fmt.Errorf(
			"optimizations.multipart_session_cleanup_interval: minimum value is 1, got %d",
			cfg.Optimizations.MultipartSessionCleanupInterval)
	}

	// Validate multipart upload concurrency (1 to 32 range)
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

// presignExpiryHardCap is the longest lifetime max_presign_expiry_seconds may
// be set to: the S3 maximum of seven days. The shipped default is an hour.
const presignExpiryHardCap = 7 * 24 * 60 * 60

// validateS3Security validates S3 security configuration
func validateS3Security(cfg *Config) error {
	sec := cfg.S3Security

	// Validate clock skew settings. 0 is refused rather than silently read as
	// the default: SigV4 timestamps have second granularity and network latency
	// alone exceeds zero tolerance, so the value can only be a misunderstanding
	// of "switch it off" — and a silent fixup is what ADR 0017 D8 forbids.
	if sec.MaxClockSkewSeconds < 1 {
		return fmt.Errorf(
			"s3_security.max_clock_skew_seconds: must be at least 1 second, got %d — "+
				"there is no value that disables the check, and 0 would refuse every request",
			sec.MaxClockSkewSeconds)
	}
	if sec.MaxClockSkewSeconds > 3600 { // 1 hour max
		return fmt.Errorf("s3_security.max_clock_skew_seconds cannot exceed 3600 seconds (1 hour)")
	}

	if sec.MaxPresignExpirySeconds < 1 {
		return fmt.Errorf(
			"s3_security.max_presign_expiry_seconds: must be at least 1 second, got %d",
			sec.MaxPresignExpirySeconds)
	}
	if sec.MaxPresignExpirySeconds > presignExpiryHardCap {
		return fmt.Errorf(
			"s3_security.max_presign_expiry_seconds: must not exceed %d seconds (7 days, the S3 maximum), got %d",
			presignExpiryHardCap, sec.MaxPresignExpirySeconds)
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
	validTypes := []string{"aes", "exit"}
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
