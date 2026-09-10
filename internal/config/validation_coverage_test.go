package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// CfgTestAESKey is a syntactically valid base64 encoded 32 byte AES key.
const CfgTestAESKey = "ZEsubBlmU+Pr61y+JOwO09c0LOrHs5LITaO0D4JzSZE="

// Keys the admission rules must refuse, one per rule.
const (
	// base64 of "a-passphrase-that-is-32-chars-ok"
	CfgPassphraseAESKey = "YS1wYXNzcGhyYXNlLXRoYXQtaXMtMzItY2hhcnMtb2s="
	// base64 of the hex form of 16 zero bytes
	CfgHexAESKey = "MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA="
	// 32 bytes drawn from two values only
	CfgLowEntropyAESKey = "AAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAE="
	// base64 of 16 bytes
	CfgShortAESKey = "AAECAwQFBgcICQoLDA0ODw=="
	// bytes 0..31, the key the Velero V9 scenario uses
	CfgVeleroV9AESKey = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
)

// CfgTestPublicKeyPEM is a placeholder PEM blob; config validation only checks
// that the value is a non-empty string, never that it parses.
const CfgTestPublicKeyPEM = "-----BEGIN PUBLIC KEY-----\nMIIB\n-----END PUBLIC KEY-----"

// CfgTestPrivateKeyPEM mirrors CfgTestPublicKeyPEM for the private half.
const CfgTestPrivateKeyPEM = "-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----"

// CfgValidClients returns a minimal S3 client list that passes validateS3Clients.
func CfgValidClients() []S3ClientCredentials {
	return []S3ClientCredentials{
		{
			Type:        "static",
			AccessKeyID: "clientkey01",
			SecretKey:   "0123456789abcdef",
			Description: "unit test client",
		},
	}
}

// CfgNoneProviderConfig returns a fully valid configuration that needs no license.
func CfgNoneProviderConfig() *Config {
	return &Config{
		S3Backend: S3BackendConfig{TargetEndpoint: "http://localhost:9000"},
		Encryption: EncryptionConfig{
			EncryptionMethodAlias: "passthrough",
			IntegrityVerification: HMACVerificationOff,
			Providers: []EncryptionProvider{
				{Alias: "passthrough", Type: "none"},
			},
		},
		S3Clients: CfgValidClients(),
	}
}

func TestCfgValidateProviderTypes(t *testing.T) {
	tests := []struct {
		name        string
		provider    EncryptionProvider
		index       int
		expectError string
	}{
		{
			name:        "tink is rejected as not implemented",
			provider:    EncryptionProvider{Alias: "t", Type: "tink"},
			index:       0,
			expectError: "encryption.providers[0]: tink encryption is not yet implemented",
		},
		{
			name:        "aes without config map",
			provider:    EncryptionProvider{Alias: "a", Type: "aes"},
			index:       3,
			expectError: "encryption.providers[3]: aes_key is required",
		},
		{
			name:        "aes with empty key",
			provider:    EncryptionProvider{Alias: "a", Type: "aes", Config: map[string]interface{}{"aes_key": ""}},
			index:       1,
			expectError: "encryption.providers[1]: aes_key is required",
		},
		{
			name:        "aes with non string key",
			provider:    EncryptionProvider{Alias: "a", Type: "aes", Config: map[string]interface{}{"aes_key": 12345}},
			index:       0,
			expectError: "aes_key is required",
		},
		{
			name:     "aes with key is accepted",
			provider: EncryptionProvider{Alias: "a", Type: "aes", Config: map[string]interface{}{"aes_key": CfgTestAESKey}},
			index:    0,
		},
		{
			name:        "rsa is no longer a provider type",
			provider:    EncryptionProvider{Alias: "r", Type: "rsa", Config: map[string]interface{}{"public_key_pem": "x", "private_key_pem": "y"}},
			index:       2,
			expectError: "encryption.providers[2].type: unsupported encryption type: rsa (supported: aes, none)",
		},
		{
			name:        "a passphrase is not a key",
			provider:    EncryptionProvider{Alias: "a", Type: "aes", Config: map[string]interface{}{"aes_key": CfgPassphraseAESKey}},
			index:       0,
			expectError: "decodes to printable characters only",
		},
		{
			name:        "base64 of a hex string is refused",
			provider:    EncryptionProvider{Alias: "a", Type: "aes", Config: map[string]interface{}{"aes_key": CfgHexAESKey}},
			index:       0,
			expectError: "decodes to printable characters only",
		},
		{
			name:        "a low entropy key is refused",
			provider:    EncryptionProvider{Alias: "a", Type: "aes", Config: map[string]interface{}{"aes_key": CfgLowEntropyAESKey}},
			index:       1,
			expectError: "decodes to only 2 distinct byte values",
		},
		{
			name:        "base64 of the wrong length is refused",
			provider:    EncryptionProvider{Alias: "a", Type: "aes", Config: map[string]interface{}{"aes_key": CfgShortAESKey}},
			index:       0,
			expectError: "must be base64 of exactly 32 bytes",
		},
		{
			name:        "a 32 character non base64 key is refused",
			provider:    EncryptionProvider{Alias: "a", Type: "aes", Config: map[string]interface{}{"aes_key": "not-base64-but-exactly-32-chars!"}},
			index:       0,
			expectError: "must be base64 of exactly 32 bytes",
		},
		{
			name:     "the velero V9 key is accepted",
			provider: EncryptionProvider{Alias: "a", Type: "aes", Config: map[string]interface{}{"aes_key": CfgVeleroV9AESKey}},
			index:    0,
		},
		{
			name:     "none needs no config",
			provider: EncryptionProvider{Alias: "n", Type: "none"},
			index:    0,
		},
		{
			name:        "empty type is unsupported",
			provider:    EncryptionProvider{Alias: "x", Type: ""},
			index:       0,
			expectError: "unsupported encryption type:  (supported: aes, none)",
		},
		{
			name:        "unknown type is unsupported",
			provider:    EncryptionProvider{Alias: "x", Type: "kms"},
			index:       7,
			expectError: "encryption.providers[7].type: unsupported encryption type: kms",
		},
		{
			name:        "type matching is case sensitive",
			provider:    EncryptionProvider{Alias: "x", Type: "AES", Config: map[string]interface{}{"aes_key": CfgTestAESKey}},
			index:       0,
			expectError: "unsupported encryption type: AES",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := tt.provider
			err := validateProvider(&provider, tt.index)
			if tt.expectError == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.expectError)
		})
	}
}

func TestCfgValidateEncryptionIntegrityModes(t *testing.T) {
	tests := []struct {
		name         string
		mode         string
		expectMode   string
		expectError  string
		expectNoFail bool
	}{
		{name: "off", mode: HMACVerificationOff, expectMode: "off"},
		{name: "lax", mode: HMACVerificationLax, expectMode: "lax"},
		{name: "strict", mode: HMACVerificationStrict, expectMode: "strict"},
		{name: "hybrid", mode: HMACVerificationHybrid, expectMode: "hybrid"},
		{name: "empty defaults to off", mode: "", expectMode: "off"},
		{name: "uppercase is rejected", mode: "STRICT", expectError: "must be one of: 'off', 'lax', 'strict', 'hybrid', got: STRICT"},
		{name: "unknown is rejected", mode: "paranoid", expectError: "got: paranoid"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := CfgNoneProviderConfig()
			cfg.Encryption.IntegrityVerification = tt.mode

			err := validateEncryption(cfg)
			if tt.expectError != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectError)
				// A rejected mode must not be silently rewritten.
				assert.Equal(t, tt.mode, cfg.Encryption.IntegrityVerification)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.expectMode, cfg.Encryption.IntegrityVerification)
		})
	}
}

func TestCfgValidateEncryptionProviderList(t *testing.T) {
	t.Run("alias without providers is rejected", func(t *testing.T) {
		cfg := CfgNoneProviderConfig()
		cfg.Encryption.Providers = nil

		err := validateEncryption(cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "encryption.providers cannot be empty")
	})

	t.Run("providers without alias are rejected", func(t *testing.T) {
		cfg := CfgNoneProviderConfig()
		cfg.Encryption.EncryptionMethodAlias = ""

		err := validateEncryption(cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "encryption.encryption_method_alias is required when using encryption.providers")
	})

	t.Run("neither alias nor providers is allowed", func(t *testing.T) {
		cfg := CfgNoneProviderConfig()
		cfg.Encryption.EncryptionMethodAlias = ""
		cfg.Encryption.Providers = nil

		require.NoError(t, validateEncryption(cfg))
	})

	t.Run("provider with empty alias is rejected", func(t *testing.T) {
		cfg := CfgNoneProviderConfig()
		cfg.Encryption.Providers = []EncryptionProvider{
			{Alias: "passthrough", Type: "none"},
			{Alias: "", Type: "none"},
		}

		err := validateEncryption(cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "encryption.providers[1].alias is required")
	})

	t.Run("duplicate aliases are rejected", func(t *testing.T) {
		cfg := CfgNoneProviderConfig()
		cfg.Encryption.Providers = []EncryptionProvider{
			{Alias: "passthrough", Type: "none"},
			{Alias: "passthrough", Type: "none"},
		}

		err := validateEncryption(cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "duplicate encryption provider alias: passthrough")
	})

	t.Run("inactive provider is validated too", func(t *testing.T) {
		cfg := CfgNoneProviderConfig()
		cfg.Encryption.Providers = []EncryptionProvider{
			{Alias: "passthrough", Type: "none"},
			{Alias: "legacy-aes", Type: "aes"}, // missing aes_key
		}

		err := validateEncryption(cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "encryption.providers[1]: aes_key is required")
	})

	t.Run("multiple valid providers with a matching active alias", func(t *testing.T) {
		cfg := CfgNoneProviderConfig()
		cfg.Encryption.EncryptionMethodAlias = "aes-current"
		cfg.Encryption.Providers = []EncryptionProvider{
			{Alias: "passthrough", Type: "none"},
			{Alias: "aes-current", Type: "aes", Config: map[string]interface{}{"aes_key": CfgTestAESKey}},
			{Alias: "aes-retired", Type: "aes", Config: map[string]interface{}{"aes_key": CfgVeleroV9AESKey}},
		}

		require.NoError(t, validateEncryption(cfg))
	})
}

func TestCfgValidateS3Clients(t *testing.T) {
	tests := []struct {
		name        string
		clients     []S3ClientCredentials
		expectError string
	}{
		{
			name:        "no clients at all",
			clients:     nil,
			expectError: "s3_clients configuration is required",
		},
		{
			name:        "empty client list",
			clients:     []S3ClientCredentials{},
			expectError: "s3_clients configuration is required",
		},
		{
			name:        "missing type",
			clients:     []S3ClientCredentials{{AccessKeyID: "clientkey01", SecretKey: "0123456789abcdef"}},
			expectError: "s3_clients[0].type is required",
		},
		{
			name: "unsupported type",
			clients: []S3ClientCredentials{
				{Type: "static", AccessKeyID: "clientkey01", SecretKey: "0123456789abcdef"},
				{Type: "oidc", AccessKeyID: "clientkey02", SecretKey: "0123456789abcdef"},
			},
			expectError: "s3_clients[1].type: unsupported type 'oidc' (supported: static)",
		},
		{
			name:        "missing access key id",
			clients:     []S3ClientCredentials{{Type: "static", SecretKey: "0123456789abcdef"}},
			expectError: "s3_clients[0].access_key_id is required",
		},
		{
			name:        "missing secret key",
			clients:     []S3ClientCredentials{{Type: "static", AccessKeyID: "clientkey01"}},
			expectError: "s3_clients[0].secret_key is required",
		},
		{
			name:        "access key id one char below minimum",
			clients:     []S3ClientCredentials{{Type: "static", AccessKeyID: "1234567", SecretKey: "0123456789abcdef"}},
			expectError: "s3_clients[0].access_key_id must be at least 8 characters long",
		},
		{
			name:    "access key id exactly at minimum",
			clients: []S3ClientCredentials{{Type: "static", AccessKeyID: "12345678", SecretKey: "0123456789abcdef"}},
		},
		{
			name:        "secret key one char below minimum",
			clients:     []S3ClientCredentials{{Type: "static", AccessKeyID: "clientkey01", SecretKey: "0123456789abcde"}},
			expectError: "s3_clients[0].secret_key must be at least 16 characters long",
		},
		{
			name:    "secret key exactly at minimum",
			clients: []S3ClientCredentials{{Type: "static", AccessKeyID: "clientkey01", SecretKey: "0123456789abcdef"}},
		},
		{
			name: "duplicate access key ids",
			clients: []S3ClientCredentials{
				{Type: "static", AccessKeyID: "clientkey01", SecretKey: "0123456789abcdef"},
				{Type: "static", AccessKeyID: "clientkey02", SecretKey: "fedcba9876543210"},
				{Type: "static", AccessKeyID: "clientkey01", SecretKey: "aaaabbbbccccdddd"},
			},
			expectError: "s3_clients[0] and s3_clients[2] have duplicate access_key_id: clientkey01",
		},
		{
			name: "distinct clients are accepted",
			clients: []S3ClientCredentials{
				{Type: "static", AccessKeyID: "clientkey01", SecretKey: "0123456789abcdef"},
				{Type: "static", AccessKeyID: "clientkey02", SecretKey: "fedcba9876543210"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := CfgNoneProviderConfig()
			cfg.S3Clients = tt.clients
			// Keep the security section in a state that always validates.
			cfg.S3Security = S3SecurityConfig{MaxClockSkewSeconds: 900, MaxRequestsPerMinute: 100}

			err := validateS3Clients(cfg)
			if tt.expectError == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.expectError)
		})
	}
}

func TestCfgValidateS3ClientsPropagatesSecurityError(t *testing.T) {
	cfg := CfgNoneProviderConfig()
	cfg.S3Security = S3SecurityConfig{MaxClockSkewSeconds: 4000}

	err := validateS3Clients(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "s3_security.max_clock_skew_seconds cannot exceed 3600")
}

func TestCfgValidateS3SecurityBoundaries(t *testing.T) {
	tests := []struct {
		name        string
		security    S3SecurityConfig
		expectError string
	}{
		{name: "all zero values are accepted", security: S3SecurityConfig{}},
		{
			name:        "negative clock skew",
			security:    S3SecurityConfig{MaxClockSkewSeconds: -1},
			expectError: "s3_security.max_clock_skew_seconds cannot be negative",
		},
		{name: "clock skew at upper bound", security: S3SecurityConfig{MaxClockSkewSeconds: 3600}},
		{
			name:        "clock skew above upper bound",
			security:    S3SecurityConfig{MaxClockSkewSeconds: 3601},
			expectError: "s3_security.max_clock_skew_seconds cannot exceed 3600 seconds (1 hour)",
		},
		{
			name:        "rate limiting enabled with zero requests",
			security:    S3SecurityConfig{EnableRateLimiting: true},
			expectError: "s3_security.max_requests_per_minute must be positive when rate limiting is enabled",
		},
		{
			name:        "rate limiting enabled with negative requests",
			security:    S3SecurityConfig{EnableRateLimiting: true, MaxRequestsPerMinute: -10},
			expectError: "must be positive when rate limiting is enabled",
		},
		{name: "rate limiting at upper bound", security: S3SecurityConfig{EnableRateLimiting: true, MaxRequestsPerMinute: 10000}},
		{
			name:        "rate limiting above upper bound",
			security:    S3SecurityConfig{EnableRateLimiting: true, MaxRequestsPerMinute: 10001},
			expectError: "s3_security.max_requests_per_minute cannot exceed 10000",
		},
		{
			name:     "invalid request rate is ignored while rate limiting is disabled",
			security: S3SecurityConfig{MaxRequestsPerMinute: 99999},
		},
		{
			name:        "negative failed attempts",
			security:    S3SecurityConfig{MaxFailedAttempts: -1},
			expectError: "s3_security.max_failed_attempts cannot be negative",
		},
		{name: "failed attempts at upper bound", security: S3SecurityConfig{MaxFailedAttempts: 1000}},
		{
			name:        "failed attempts above upper bound",
			security:    S3SecurityConfig{MaxFailedAttempts: 1001},
			expectError: "s3_security.max_failed_attempts cannot exceed 1000",
		},
		{
			name:        "negative unblock seconds",
			security:    S3SecurityConfig{UnblockIPSeconds: -1},
			expectError: "s3_security.unblock_ip_seconds cannot be negative",
		},
		{name: "unblock seconds at upper bound", security: S3SecurityConfig{UnblockIPSeconds: 86400}},
		{
			name:        "unblock seconds above upper bound",
			security:    S3SecurityConfig{UnblockIPSeconds: 86401},
			expectError: "s3_security.unblock_ip_seconds cannot exceed 86400 seconds (24 hours)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{S3Security: tt.security}

			err := validateS3Security(cfg)
			if tt.expectError == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.expectError)
		})
	}
}

func TestCfgValidateOptimizationsBoundaries(t *testing.T) {
	tests := []struct {
		name        string
		opts        OptimizationsConfig
		expectError string
	}{
		{name: "all zero values skip every range check", opts: OptimizationsConfig{}},
		{
			name:        "buffer size one byte below 4KB",
			opts:        OptimizationsConfig{StreamingBufferSize: 4095},
			expectError: "optimizations.streaming_buffer_size: minimum value is 4KB (4096 bytes), got 4095",
		},
		{name: "buffer size exactly 4KB", opts: OptimizationsConfig{StreamingBufferSize: 4096}},
		{name: "buffer size exactly 2MB", opts: OptimizationsConfig{StreamingBufferSize: 2097152}},
		{
			name:        "buffer size one byte above 2MB",
			opts:        OptimizationsConfig{StreamingBufferSize: 2097153},
			expectError: "optimizations.streaming_buffer_size: maximum value is 2MB (2097152 bytes), got 2097153",
		},
		{
			name:        "segment size one byte below 5MB",
			opts:        OptimizationsConfig{StreamingSegmentSize: 5242879},
			expectError: "optimizations.streaming_segment_size: minimum value is 5MB (5242880 bytes), got 5242879",
		},
		{name: "segment size exactly 5MB", opts: OptimizationsConfig{StreamingSegmentSize: 5242880}},
		{name: "segment size exactly 5GB", opts: OptimizationsConfig{StreamingSegmentSize: 5368709120}},
		{
			name:        "segment size one byte above 5GB",
			opts:        OptimizationsConfig{StreamingSegmentSize: 5368709121},
			expectError: "optimizations.streaming_segment_size: maximum value is 5GB (5368709120 bytes), got 5368709121",
		},
		{
			name:        "threshold below 1MB with adaptive buffering enabled",
			opts:        OptimizationsConfig{EnableAdaptiveBuffering: true, StreamingThreshold: 1048575},
			expectError: "optimizations.streaming_threshold: minimum value is 1MB (1048576 bytes), got 1048575",
		},
		{name: "threshold exactly 1MB with adaptive buffering enabled", opts: OptimizationsConfig{EnableAdaptiveBuffering: true, StreamingThreshold: 1048576}},
		{name: "zero threshold with adaptive buffering enabled", opts: OptimizationsConfig{EnableAdaptiveBuffering: true}},
		{
			// Documents the current behaviour: the threshold lower bound is only
			// enforced while adaptive buffering is on.
			name: "tiny threshold is accepted while adaptive buffering is off",
			opts: OptimizationsConfig{StreamingThreshold: 1},
		},
		{name: "concurrency at lower bound", opts: OptimizationsConfig{MultipartUploadConcurrency: 1}},
		{name: "concurrency at upper bound", opts: OptimizationsConfig{MultipartUploadConcurrency: 32}},
		{
			name:        "concurrency above upper bound",
			opts:        OptimizationsConfig{MultipartUploadConcurrency: 33},
			expectError: "optimizations.multipart_upload_concurrency: maximum value is 32, got 33",
		},
		{
			name:        "negative concurrency",
			opts:        OptimizationsConfig{MultipartUploadConcurrency: -1},
			expectError: "optimizations.multipart_upload_concurrency: minimum value is 1, got -1",
		},
		{
			// Documents the current behaviour: the struct tags declare min=60 and
			// min=900, but nothing enforces them.
			name: "session cleanup values below their declared minimum are not enforced",
			opts: OptimizationsConfig{MultipartSessionCleanupInterval: 1, MultipartSessionMaxAge: 1},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{Optimizations: tt.opts}

			err := validateOptimizations(cfg)
			if tt.expectError == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.expectError)
		})
	}
}

func TestCfgValidateRequiresTargetEndpoint(t *testing.T) {
	t.Run("missing everywhere", func(t *testing.T) {
		cfg := CfgNoneProviderConfig()
		cfg.S3Backend.TargetEndpoint = ""

		err := validate(cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "target_endpoint is required (use 's3_backend.target_endpoint' or legacy 'target_endpoint')")
	})

	t.Run("legacy top level endpoint is accepted as fallback", func(t *testing.T) {
		cfg := CfgNoneProviderConfig()
		cfg.S3Backend.TargetEndpoint = ""
		cfg.TargetEndpoint = "http://legacy:9000"

		require.NoError(t, validate(cfg))
	})
}

func TestCfgValidateTLSRequirements(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "server.crt")
	keyFile := filepath.Join(dir, "server.key")
	require.NoError(t, os.WriteFile(certFile, []byte("cert"), 0o600))
	require.NoError(t, os.WriteFile(keyFile, []byte("key"), 0o600))

	tests := []struct {
		name        string
		tls         TLSConfig
		expectError string
	}{
		{name: "disabled TLS ignores missing files", tls: TLSConfig{Enabled: false, CertFile: "/nope/a.crt", KeyFile: "/nope/a.key"}},
		{
			name:        "enabled without cert file",
			tls:         TLSConfig{Enabled: true, KeyFile: keyFile},
			expectError: "tls.cert_file is required when TLS is enabled",
		},
		{
			name:        "enabled without key file",
			tls:         TLSConfig{Enabled: true, CertFile: certFile},
			expectError: "tls.key_file is required when TLS is enabled",
		},
		{
			name:        "cert file does not exist",
			tls:         TLSConfig{Enabled: true, CertFile: filepath.Join(dir, "missing.crt"), KeyFile: keyFile},
			expectError: "TLS certificate file does not exist:",
		},
		{
			name:        "key file does not exist",
			tls:         TLSConfig{Enabled: true, CertFile: certFile, KeyFile: filepath.Join(dir, "missing.key")},
			expectError: "TLS key file does not exist:",
		},
		{name: "both files present", tls: TLSConfig{Enabled: true, CertFile: certFile, KeyFile: keyFile}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := CfgNoneProviderConfig()
			cfg.TLS = tt.tls

			err := validate(cfg)
			if tt.expectError == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.expectError)
		})
	}
}

func TestCfgValidatePropagatesSubValidatorErrors(t *testing.T) {
	t.Run("encryption error", func(t *testing.T) {
		cfg := CfgNoneProviderConfig()
		cfg.Encryption.IntegrityVerification = "bogus"

		err := validate(cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "encryption.integrity_verification must be one of")
	})

	t.Run("optimizations error", func(t *testing.T) {
		cfg := CfgNoneProviderConfig()
		cfg.Optimizations.StreamingBufferSize = 100

		err := validate(cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "optimizations.streaming_buffer_size: minimum value is 4KB")
	})

	t.Run("s3 client error", func(t *testing.T) {
		cfg := CfgNoneProviderConfig()
		cfg.S3Clients = nil

		err := validate(cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "s3_clients configuration is required")
	})
}

func TestCfgValidateLicenseAndEncryption(t *testing.T) {
	// Make sure no ambient license token leaks into the assertions.
	t.Setenv("S3EP_LICENSE", "")
	t.Setenv("S3EP_LICENSE_TOKEN", "")
	t.Setenv("S3_ENCRYPTION_PROXY_LICENSE", "")

	t.Run("none provider works without a license", func(t *testing.T) {
		cfg := CfgNoneProviderConfig()
		cfg.LicenseFile = filepath.Join(t.TempDir(), "absent.jwt")

		require.NoError(t, validateLicenseAndEncryption(cfg))
	})

	t.Run("aes provider is refused without a license", func(t *testing.T) {
		cfg := CfgNoneProviderConfig()
		cfg.LicenseFile = filepath.Join(t.TempDir(), "absent.jwt")
		cfg.Encryption.EncryptionMethodAlias = "aes-current"
		cfg.Encryption.Providers = []EncryptionProvider{
			{Alias: "aes-current", Type: "aes", Config: map[string]interface{}{"aes_key": CfgTestAESKey}},
		}

		err := validateLicenseAndEncryption(cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "license required for encryption provider type 'aes'")
	})

	t.Run("encryption validation runs before the license check", func(t *testing.T) {
		cfg := CfgNoneProviderConfig()
		cfg.LicenseFile = filepath.Join(t.TempDir(), "absent.jwt")
		cfg.Encryption.IntegrityVerification = "nope"

		err := validateLicenseAndEncryption(cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "encryption.integrity_verification must be one of")
	})

	t.Run("unknown active alias skips the license check", func(t *testing.T) {
		// validateEncryption already rejects this, so the loop over providers
		// never finds a match; guard against a future regression.
		cfg := CfgNoneProviderConfig()
		cfg.LicenseFile = filepath.Join(t.TempDir(), "absent.jwt")
		cfg.Encryption.EncryptionMethodAlias = "ghost"

		err := validateLicenseAndEncryption(cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "encryption_method_alias 'ghost' does not match any provider alias")
	})
}

// D-22: a pprof profile of this process contains DEKs, KEK-decrypted key
// material and plaintext object buffers, so its listener may only ever bind
// loopback. That is a startup error rather than the log line it used to be -
// a control that exists only in documentation is worse than none.
func TestCfgValidateMonitoringPprofBindAddress(t *testing.T) {
	tests := []struct {
		name        string
		enabled     bool
		addr        string
		expectError string
	}{
		{name: "pprof off does not look at the address at all", enabled: false, addr: ""},
		{name: "pprof off ignores even a public address", enabled: false, addr: "0.0.0.0:6060"},
		{name: "the default is loopback", enabled: true, addr: "127.0.0.1:6060"},
		{name: "any 127.0.0.0/8 address", enabled: true, addr: "127.9.9.9:6060"},
		{name: "IPv6 loopback", enabled: true, addr: "[::1]:6060"},
		{name: "localhost by name", enabled: true, addr: "localhost:6060"},
		{
			name: "every interface", enabled: true, addr: ":6060",
			expectError: "binds every interface",
		},
		{
			name: "the unspecified address is not loopback", enabled: true, addr: "0.0.0.0:6060",
			expectError: "is not a loopback address",
		},
		{
			name: "a routable address", enabled: true, addr: "10.0.0.5:6060",
			expectError: "is not a loopback address",
		},
		{
			name: "IPv6 unspecified", enabled: true, addr: "[::]:6060",
			expectError: "is not a loopback address",
		},
		{
			// Resolving a name at startup would make the proxy fail to boot
			// without a resolver, and a name that points at loopback today can
			// point elsewhere tomorrow while the process keeps running.
			name:    "a name other than localhost is refused rather than resolved",
			enabled: true, addr: "monitoring.internal:6060",
			expectError: "is a name",
		},
		{
			name: "no port", enabled: true, addr: "127.0.0.1",
			expectError: "is not a valid host:port address",
		},
		{
			name: "empty while enabled", enabled: true, addr: "",
			expectError: "is required when monitoring.pprof_enabled is true",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := CfgNoneProviderConfig()
			cfg.Monitoring.PprofEnabled = tt.enabled
			cfg.Monitoring.PprofBindAddress = tt.addr

			err := validate(cfg)

			if tt.expectError == "" {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), "monitoring.pprof_bind_address",
				"the error must name the field the operator has to change")
			assert.Contains(t, err.Error(), tt.expectError)
		})
	}
}
