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
				Providers: []EncryptionProvider{{Alias: "a", Type: "exit"}},
			}},
			expectError: "encryption_method_alias is required when providers are configured",
		},
		{
			name: "alias without a matching provider",
			cfg: Config{Encryption: EncryptionConfig{
				EncryptionMethodAlias: "ghost",
				Providers:             []EncryptionProvider{{Alias: "a", Type: "exit"}},
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
					{Alias: "a", Type: "exit"},
					{Alias: "b", Type: "aes"},
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
		{"exit", true},
		// "none" was renamed to "exit" and is refused by name, not accepted as
		// a synonym.
		{"none", false},
		{"rsa", false},
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

func TestCfgStreamingAccessors(t *testing.T) {
	tests := []struct {
		name          string
		opts          OptimizationsConfig
		expectSegment int64
	}{
		{
			name:          "zero values fall back to the documented defaults",
			opts:          OptimizationsConfig{},
			expectSegment: 12 * 1024 * 1024,
		},
		{
			name:          "configured values win",
			opts:          OptimizationsConfig{StreamingSegmentSize: 32 * 1024 * 1024},
			expectSegment: 32 * 1024 * 1024,
		},
		{
			name:          "negative values fall back to the defaults as well",
			opts:          OptimizationsConfig{StreamingSegmentSize: -1},
			expectSegment: 12 * 1024 * 1024,
		},
		{
			name:          "a single byte still counts as configured",
			opts:          OptimizationsConfig{StreamingSegmentSize: 1},
			expectSegment: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{Optimizations: tt.opts}
			assert.Equal(t, tt.expectSegment, cfg.GetStreamingSegmentSize())
		})
	}
}

func TestCfgGetAllProvidersReflectsSlice(t *testing.T) {
	cfg := &Config{}
	assert.Empty(t, cfg.GetAllProviders())

	cfg.Encryption.Providers = []EncryptionProvider{{Alias: "a", Type: "exit"}, {Alias: "b", Type: "aes"}}
	providers := cfg.GetAllProviders()
	require.Len(t, providers, 2)
	assert.Equal(t, "b", providers[1].Alias)
}
