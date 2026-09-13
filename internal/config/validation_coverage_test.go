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

// CfgExitProviderConfig returns a fully valid configuration that needs no
// license: the licence gate checks only the active provider, and the exit
// provider is the one an operator selects to leave the product.
// CfgExitProviderConfig is a Config that passes validate(). A Config built in
// code never goes through setDefaults, so every key whose zero value is refused
// has to be spelled out here — that is the point of the refusals, and a builder
// that left them at zero would hide them from every test that uses it.
func CfgExitProviderConfig() *Config {
	return &Config{
		// https, because a plain-HTTP backend is refused under every provider
		// (ADR 0013 D5) and would mask the check each test here is about.
		S3Backend: S3BackendConfig{TargetEndpoint: "https://localhost:9000"},
		Encryption: EncryptionConfig{
			EncryptionMethodAlias: "way-out",
			Providers: []EncryptionProvider{
				{Alias: "way-out", Type: "exit"},
			},
		},
		S3Clients: CfgValidClients(),
		S3Security: S3SecurityConfig{
			MaxClockSkewSeconds:     900,
			MaxPresignExpirySeconds: 3600,
		},
		ReadHeaderTimeout: 30,
		IdleTimeout:       60,
	}
}

func TestCfgValidateProviderTypes(t *testing.T) {
	tests := []struct {
		name     string
		provider EncryptionProvider
		index    int
		// expectError and expectAlso are substrings the message must carry,
		// expectAbsent substrings it must not.
		expectError  string
		expectAlso   []string
		expectAbsent []string
	}{
		{
			// "not yet implemented with the new architecture" is a leftover ADR 0005
			// records under residual risks; ADR 0013 D7 wants the field and the rule
			// it broke, on an arm of its own so an old configuration fails loudly.
			// The exact wording of that rule is still the owner's to pick.
			name:         "tink is refused by name, not as a generic unknown type",
			provider:     EncryptionProvider{Alias: "t", Type: "tink"},
			index:        0,
			expectError:  "encryption.providers[0]",
			expectAlso:   []string{"tink", "supported: aes, exit"},
			expectAbsent: []string{"not yet implemented", "unsupported encryption type"},
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
			expectError: "encryption.providers[2].type: unsupported encryption type: rsa (supported: aes, exit)",
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
			name:     "exit needs no config",
			provider: EncryptionProvider{Alias: "e", Type: "exit"},
			index:    0,
		},
		{
			// The rename is a semantic change, so the old name is refused by
			// name rather than quietly accepted: an operator who kept "none" in
			// their configuration has to read what the exit provider does, and
			// above all keep the provider that holds the old key configured.
			name:        "none is refused and points at exit",
			provider:    EncryptionProvider{Alias: "n", Type: "none"},
			index:       4,
			expectError: "encryption.providers[4].type: 'none' is now 'exit'",
		},
		{
			name:        "empty type is unsupported",
			provider:    EncryptionProvider{Alias: "x", Type: ""},
			index:       0,
			expectError: "unsupported encryption type:  (supported: aes, exit)",
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
			for _, must := range tt.expectAlso {
				assert.Contains(t, err.Error(), must)
			}
			for _, mustNot := range tt.expectAbsent {
				assert.NotContains(t, err.Error(), mustNot)
			}
		})
	}
}

func TestCfgValidateEncryptionProviderList(t *testing.T) {
	t.Run("alias without providers is rejected", func(t *testing.T) {
		cfg := CfgExitProviderConfig()
		cfg.Encryption.Providers = nil

		err := validateEncryption(cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "encryption.providers cannot be empty")
	})

	t.Run("providers without alias are rejected", func(t *testing.T) {
		cfg := CfgExitProviderConfig()
		cfg.Encryption.EncryptionMethodAlias = ""

		err := validateEncryption(cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "encryption.encryption_method_alias is required when using encryption.providers")
	})

	t.Run("neither alias nor providers is allowed", func(t *testing.T) {
		cfg := CfgExitProviderConfig()
		cfg.Encryption.EncryptionMethodAlias = ""
		cfg.Encryption.Providers = nil

		require.NoError(t, validateEncryption(cfg))
	})

	t.Run("provider with empty alias is rejected", func(t *testing.T) {
		cfg := CfgExitProviderConfig()
		cfg.Encryption.Providers = []EncryptionProvider{
			{Alias: "way-out", Type: "exit"},
			{Alias: "", Type: "exit"},
		}

		err := validateEncryption(cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "encryption.providers[1].alias is required")
	})

	t.Run("duplicate aliases are rejected", func(t *testing.T) {
		cfg := CfgExitProviderConfig()
		cfg.Encryption.Providers = []EncryptionProvider{
			{Alias: "way-out", Type: "exit"},
			{Alias: "way-out", Type: "exit"},
		}

		err := validateEncryption(cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "duplicate encryption provider alias: way-out")
	})

	t.Run("inactive provider is validated too", func(t *testing.T) {
		cfg := CfgExitProviderConfig()
		cfg.Encryption.Providers = []EncryptionProvider{
			{Alias: "way-out", Type: "exit"},
			{Alias: "legacy-aes", Type: "aes"}, // missing aes_key
		}

		err := validateEncryption(cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "encryption.providers[1]: aes_key is required")
	})

	t.Run("multiple valid providers with a matching active alias", func(t *testing.T) {
		cfg := CfgExitProviderConfig()
		cfg.Encryption.EncryptionMethodAlias = "aes-current"
		cfg.Encryption.Providers = []EncryptionProvider{
			{Alias: "way-out", Type: "exit"},
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
			cfg := CfgExitProviderConfig()
			cfg.S3Clients = tt.clients
			// Keep the security section in a state that always validates.
			cfg.S3Security = S3SecurityConfig{MaxClockSkewSeconds: 900, MaxPresignExpirySeconds: 3600}

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
	cfg := CfgExitProviderConfig()
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
		{name: "the shipped defaults", security: S3SecurityConfig{MaxClockSkewSeconds: 900, MaxPresignExpirySeconds: 3600}},
		{
			// Neither key has a value that means "off", and 0 used to be read
			// silently as the default on both. A silent fixup is what ADR 0017 D8
			// forbids, and at second granularity a zero skew would refuse every
			// request that ever reached the proxy.
			name:        "zero clock skew is refused, not read as the default",
			security:    S3SecurityConfig{MaxClockSkewSeconds: 0, MaxPresignExpirySeconds: 3600},
			expectError: "s3_security.max_clock_skew_seconds: must be at least 1 second",
		},
		{
			name:        "negative clock skew",
			security:    S3SecurityConfig{MaxClockSkewSeconds: -1, MaxPresignExpirySeconds: 3600},
			expectError: "s3_security.max_clock_skew_seconds: must be at least 1 second",
		},
		{
			name:     "clock skew at upper bound",
			security: S3SecurityConfig{MaxClockSkewSeconds: 3600, MaxPresignExpirySeconds: 3600},
		},
		{
			name:        "clock skew above upper bound",
			security:    S3SecurityConfig{MaxClockSkewSeconds: 3601, MaxPresignExpirySeconds: 3600},
			expectError: "s3_security.max_clock_skew_seconds cannot exceed 3600 seconds (1 hour)",
		},
		{
			name:        "zero pre-signed ceiling is refused",
			security:    S3SecurityConfig{MaxClockSkewSeconds: 900},
			expectError: "s3_security.max_presign_expiry_seconds: must be at least 1 second",
		},
		{
			name:     "the pre-signed ceiling at the S3 maximum",
			security: S3SecurityConfig{MaxClockSkewSeconds: 900, MaxPresignExpirySeconds: 7 * 24 * 60 * 60},
		},
		{
			name:        "the pre-signed ceiling above the S3 maximum",
			security:    S3SecurityConfig{MaxClockSkewSeconds: 900, MaxPresignExpirySeconds: 7*24*60*60 + 1},
			expectError: "s3_security.max_presign_expiry_seconds: must not exceed 604800 seconds",
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
			// A value inside the range but not on a segment boundary used to pass
			// startup and then fail every upload larger than one part, at the
			// backend, with a 500 (ADR 0003).
			name:        "segment size in range but not a multiple of 64 KiB",
			opts:        OptimizationsConfig{StreamingSegmentSize: 10000000},
			expectError: "optimizations.streaming_segment_size: must be a multiple of 65536 bytes (64 KiB), got 10000000",
		},
		{name: "segment size 12MB is a whole number of segments", opts: OptimizationsConfig{StreamingSegmentSize: 12582912}},
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
			// ADR 0013 D7 / ADR 0017 D8: a value that switches a protection off is
			// refused by name - the idle timeout got that check, the cleanup interval
			// was left behind (ADR 0028, residual risks).
			// Open: whether a written 0 is caught here or in the loader beside the
			// idle timeout's zero check. The minimum of 1 itself is not open.
			name:        "cleanup interval below its minimum is refused",
			opts:        OptimizationsConfig{MultipartSessionCleanupInterval: -1},
			expectError: "optimizations.multipart_session_cleanup_interval: minimum value is 1",
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
		cfg := CfgExitProviderConfig()
		cfg.S3Backend.TargetEndpoint = ""

		err := validate(cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "s3_backend.target_endpoint is required")
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
			cfg := CfgExitProviderConfig()
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
		cfg := CfgExitProviderConfig()
		prefix := "S3EP-"
		cfg.Encryption.MetadataKeyPrefix = &prefix

		err := validate(cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "encryption.metadata_key_prefix: lowercase letters, digits and dashes only")
	})

	t.Run("optimizations error", func(t *testing.T) {
		cfg := CfgExitProviderConfig()
		cfg.Optimizations.StreamingSegmentSize = 100

		err := validate(cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "optimizations.streaming_segment_size: minimum value is 5MB")
	})

	t.Run("s3 client error", func(t *testing.T) {
		cfg := CfgExitProviderConfig()
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

	t.Run("the exit provider works without a license", func(t *testing.T) {
		cfg := CfgExitProviderConfig()
		cfg.LicenseFile = filepath.Join(t.TempDir(), "absent.jwt")

		require.NoError(t, validateLicenseAndEncryption(cfg))
	})

	t.Run("aes provider is refused without a license", func(t *testing.T) {
		cfg := CfgExitProviderConfig()
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
		// The aes provider would also fail the license check; the encryption
		// error has to be the one that surfaces.
		cfg := CfgExitProviderConfig()
		cfg.LicenseFile = filepath.Join(t.TempDir(), "absent.jwt")
		cfg.Encryption.EncryptionMethodAlias = "aes-current"
		cfg.Encryption.Providers = []EncryptionProvider{
			{Alias: "aes-current", Type: "aes"}, // missing aes_key
		}

		err := validateLicenseAndEncryption(cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "encryption.providers[0]: aes_key is required")
	})

	t.Run("unknown active alias skips the license check", func(t *testing.T) {
		// validateEncryption already rejects this, so the loop over providers
		// never finds a match; guard against a future regression.
		cfg := CfgExitProviderConfig()
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
			cfg := CfgExitProviderConfig()
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

// ADR 0013 D4 and D5. A plain-HTTP backend is refused under every provider, the
// exit provider included: the backend credential would travel in a SigV4 header
// over plaintext, and aws-sdk-go-v2 refuses to send an unseekable streaming body
// with UNSIGNED-PAYLOAD without TLS, so a single-request upload fails at runtime.
// A scheme the SDK would have to guess at is refused with it.
func TestCfgValidateBackendTransport(t *testing.T) {
	encrypting := func(endpoint string) *Config {
		cfg := CfgExitProviderConfig()
		cfg.S3Backend.TargetEndpoint = endpoint
		cfg.Encryption.EncryptionMethodAlias = "aes"
		cfg.Encryption.Providers = []EncryptionProvider{
			{Alias: "aes", Type: "aes", Config: map[string]interface{}{"aes_key": "k"}},
		}
		return cfg
	}
	exiting := func(endpoint string) *Config {
		cfg := CfgExitProviderConfig()
		cfg.S3Backend.TargetEndpoint = endpoint
		return cfg
	}

	tests := []struct {
		name        string
		cfg         *Config
		expectError string
	}{
		{name: "https under an encrypting provider", cfg: encrypting("https://minio:9000")},
		{
			name:        "plain http under an encrypting provider",
			cfg:         encrypting("http://minio:9000"),
			expectError: "s3_backend.target_endpoint is plain HTTP",
		},
		{
			// The exception this used to admit let the proxy start and then fail
			// every upload below streaming_segment_size with "failed to seek body
			// to start", while larger ones went through the multipart producer
			// and stored fine.
			name:        "plain http under the exit provider",
			cfg:         exiting("http://minio:9000"),
			expectError: "s3_backend.target_endpoint is plain HTTP",
		},
		{name: "https under the exit provider", cfg: exiting("https://minio:9000")},
		{
			name:        "a scheme-less endpoint",
			cfg:         encrypting("minio:9000"),
			expectError: "must start with https:// or http://",
		},
		{
			name:        "a scheme the SDK does not speak",
			cfg:         encrypting("ftp://minio:9000"),
			expectError: "must start with https:// or http://",
		},
		{
			name: "no provider resolves, so the check abstains",
			cfg: func() *Config {
				cfg := CfgExitProviderConfig()
				cfg.S3Backend.TargetEndpoint = "http://minio:9000"
				cfg.Encryption.EncryptionMethodAlias = "does-not-exist"
				return cfg
			}(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateBackendTransport(tt.cfg)
			if tt.expectError == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.expectError)
		})
	}
}
