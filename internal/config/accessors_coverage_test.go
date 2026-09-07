package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCfgGetActiveProviderErrorPaths(t *testing.T) {
	tests := []struct {
		name        string
		cfg         Config
		expectAlias string
		expectError string
	}{
		{
			name:        "no alias and no providers",
			cfg:         Config{},
			expectError: "no encryption providers configured",
		},
		{
			name: "providers without an alias",
			cfg: Config{Encryption: EncryptionConfig{
				Providers: []EncryptionProvider{{Alias: "a", Type: "none"}},
			}},
			expectError: "encryption_method_alias is required when providers are configured",
		},
		{
			name: "alias without a matching provider",
			cfg: Config{Encryption: EncryptionConfig{
				EncryptionMethodAlias: "ghost",
				Providers:             []EncryptionProvider{{Alias: "a", Type: "none"}},
			}},
			expectError: "active encryption provider 'ghost' not found",
		},
		{
			name: "matching provider with an empty type",
			cfg: Config{Encryption: EncryptionConfig{
				EncryptionMethodAlias: "a",
				Providers:             []EncryptionProvider{{Alias: "a", Type: ""}},
			}},
			expectError: "provider 'a' has empty type",
		},
		{
			name: "matching provider with an unknown type",
			cfg: Config{Encryption: EncryptionConfig{
				EncryptionMethodAlias: "a",
				Providers:             []EncryptionProvider{{Alias: "a", Type: "tink"}},
			}},
			expectError: "provider 'a' has invalid type 'tink'",
		},
		{
			name: "second provider is selected",
			cfg: Config{Encryption: EncryptionConfig{
				EncryptionMethodAlias: "b",
				Providers: []EncryptionProvider{
					{Alias: "a", Type: "none"},
					{Alias: "b", Type: "rsa"},
				},
			}},
			expectAlias: "b",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := tt.cfg
			provider, err := cfg.GetActiveProvider()
			if tt.expectError != "" {
				require.Error(t, err)
				assert.Nil(t, provider)
				assert.Contains(t, err.Error(), tt.expectError)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, provider)
			assert.Equal(t, tt.expectAlias, provider.Alias)
		})
	}
}

func TestCfgGetActiveProviderReturnsLivePointer(t *testing.T) {
	cfg := &Config{Encryption: EncryptionConfig{
		EncryptionMethodAlias: "a",
		Providers:             []EncryptionProvider{{Alias: "a", Type: "aes"}},
	}}

	provider, err := cfg.GetActiveProvider()
	require.NoError(t, err)
	provider.Description = "mutated"

	assert.Equal(t, "mutated", cfg.Encryption.Providers[0].Description)
}

func TestCfgIsValidProviderType(t *testing.T) {
	tests := []struct {
		providerType string
		expect       bool
	}{
		{"aes", true},
		{"rsa", true},
		{"none", true},
		{"tink", false},
		{"", false},
		{"AES", false},
		{" aes", false},
	}

	for _, tt := range tests {
		t.Run("type_"+tt.providerType, func(t *testing.T) {
			assert.Equal(t, tt.expect, isValidProviderType(tt.providerType))
		})
	}
}

func TestCfgValidateS3ClientCredentials(t *testing.T) {
	cfg := &Config{S3Clients: []S3ClientCredentials{
		{Type: "static", AccessKeyID: "clientkey01", SecretKey: "0123456789abcdef"},
		{Type: "static", AccessKeyID: "clientkey02", SecretKey: "fedcba9876543210"},
	}}

	tests := []struct {
		name      string
		accessKey string
		secretKey string
		expect    bool
	}{
		{name: "first client matches", accessKey: "clientkey01", secretKey: "0123456789abcdef", expect: true},
		{name: "second client matches", accessKey: "clientkey02", secretKey: "fedcba9876543210", expect: true},
		{name: "wrong secret is rejected", accessKey: "clientkey01", secretKey: "fedcba9876543210", expect: false},
		{name: "unknown access key is rejected", accessKey: "clientkey99", secretKey: "0123456789abcdef", expect: false},
		{name: "empty credentials are rejected", accessKey: "", secretKey: "", expect: false},
		{name: "secret key prefix is not enough", accessKey: "clientkey01", secretKey: "0123456789abcde", expect: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expect, cfg.ValidateS3ClientCredentials(tt.accessKey, tt.secretKey))
		})
	}

	empty := &Config{}
	assert.False(t, empty.ValidateS3ClientCredentials("clientkey01", "0123456789abcdef"))
	assert.False(t, empty.ValidateS3ClientCredentials("", ""))
}

func TestCfgIsS3ClientAuthEnabled(t *testing.T) {
	assert.True(t, (&Config{}).IsS3ClientAuthEnabled())
	assert.True(t, (&Config{S3Clients: CfgValidClients()}).IsS3ClientAuthEnabled())
}

func TestCfgGetS3SecurityConfigAppliesDefaults(t *testing.T) {
	t.Run("zero values are filled in", func(t *testing.T) {
		cfg := &Config{}

		security := cfg.GetS3SecurityConfig()
		assert.Equal(t, 900, security.MaxClockSkewSeconds)
		assert.Equal(t, 100, security.MaxRequestsPerMinute)
		assert.Equal(t, 10, security.MaxFailedAttempts)
		// UnblockIPSeconds has no accessor default: 0 stays 0.
		assert.Equal(t, 0, security.UnblockIPSeconds)
		// The receiver is not mutated - a copy is returned.
		assert.Equal(t, 0, cfg.S3Security.MaxClockSkewSeconds)
	})

	t.Run("configured values are preserved", func(t *testing.T) {
		cfg := &Config{S3Security: S3SecurityConfig{
			StrictSignatureValidation: true,
			MaxClockSkewSeconds:       300,
			EnableRateLimiting:        true,
			MaxRequestsPerMinute:      60,
			EnableSecurityLogging:     true,
			MaxFailedAttempts:         5,
			UnblockIPSeconds:          120,
		}}

		security := cfg.GetS3SecurityConfig()
		assert.Equal(t, 300, security.MaxClockSkewSeconds)
		assert.Equal(t, 60, security.MaxRequestsPerMinute)
		assert.Equal(t, 5, security.MaxFailedAttempts)
		assert.Equal(t, 120, security.UnblockIPSeconds)
		assert.True(t, security.StrictSignatureValidation)
		assert.True(t, security.EnableRateLimiting)
		assert.True(t, security.EnableSecurityLogging)
	})

	t.Run("negative values are left untouched", func(t *testing.T) {
		cfg := &Config{S3Security: S3SecurityConfig{MaxClockSkewSeconds: -1, MaxRequestsPerMinute: -1, MaxFailedAttempts: -1}}

		security := cfg.GetS3SecurityConfig()
		assert.Equal(t, -1, security.MaxClockSkewSeconds)
		assert.Equal(t, -1, security.MaxRequestsPerMinute)
		assert.Equal(t, -1, security.MaxFailedAttempts)
	})
}

func TestCfgStreamingAccessors(t *testing.T) {
	tests := []struct {
		name            string
		opts            OptimizationsConfig
		expectSegment   int64
		expectThreshold int64
		expectBuffer    int
	}{
		{
			name:            "zero values fall back to the documented defaults",
			opts:            OptimizationsConfig{},
			expectSegment:   12 * 1024 * 1024,
			expectThreshold: 5 * 1024 * 1024,
			expectBuffer:    64 * 1024,
		},
		{
			name: "configured values win",
			opts: OptimizationsConfig{
				StreamingSegmentSize: 32 * 1024 * 1024,
				StreamingThreshold:   1024 * 1024,
				StreamingBufferSize:  128 * 1024,
			},
			expectSegment:   32 * 1024 * 1024,
			expectThreshold: 1024 * 1024,
			expectBuffer:    128 * 1024,
		},
		{
			name: "negative values fall back to the defaults as well",
			opts: OptimizationsConfig{
				StreamingSegmentSize: -1,
				StreamingThreshold:   -1,
				StreamingBufferSize:  -1,
			},
			expectSegment:   12 * 1024 * 1024,
			expectThreshold: 5 * 1024 * 1024,
			expectBuffer:    64 * 1024,
		},
		{
			name:            "a single byte still counts as configured",
			opts:            OptimizationsConfig{StreamingSegmentSize: 1, StreamingThreshold: 1, StreamingBufferSize: 1},
			expectSegment:   1,
			expectThreshold: 1,
			expectBuffer:    1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{Optimizations: tt.opts}
			assert.Equal(t, tt.expectSegment, cfg.GetStreamingSegmentSize())
			assert.Equal(t, tt.expectThreshold, cfg.GetStreamingThreshold())
			assert.Equal(t, tt.expectBuffer, cfg.GetStreamingBufferSize())
		})
	}
}

func TestCfgGetAllProvidersReflectsSlice(t *testing.T) {
	cfg := &Config{}
	assert.Empty(t, cfg.GetAllProviders())

	cfg.Encryption.Providers = []EncryptionProvider{{Alias: "a", Type: "none"}, {Alias: "b", Type: "aes"}}
	providers := cfg.GetAllProviders()
	require.Len(t, providers, 2)
	assert.Equal(t, "b", providers[1].Alias)
}

func TestCfgGetProviderByAliasIsCaseSensitive(t *testing.T) {
	cfg := &Config{Encryption: EncryptionConfig{
		Providers: []EncryptionProvider{{Alias: "Primary", Type: "none"}},
	}}

	provider, err := cfg.GetProviderByAlias("Primary")
	require.NoError(t, err)
	assert.Equal(t, "Primary", provider.Alias)

	_, err = cfg.GetProviderByAlias("primary")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "encryption provider with alias 'primary' not found")

	_, err = cfg.GetProviderByAlias("")
	require.Error(t, err)
}
