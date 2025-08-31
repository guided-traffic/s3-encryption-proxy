package providers

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFactory_CreateProvider(t *testing.T) {
	factory := NewFactory()

	tests := []struct {
		name      string
		config    *ProviderConfig
		wantError bool
		wantType  string
	}{
		{
			name: "valid AES-GCM config",
			config: &ProviderConfig{
				Type:   ProviderTypeAESGCM,
				AESKey: "1UR+yQO2Ap3NJabyhkwSm0qk/vllEa2Jae+NSxyVas8=", // 32-byte base64 key
			},
			wantError: false,
			wantType:  "*providers.AESGCMProvider",
		},
		{
			name: "valid Tink config",
			config: &ProviderConfig{
				Type:   ProviderTypeTink,
				KEKUri: "gcp-kms://projects/test/locations/global/keyRings/test/cryptoKeys/test",
			},
			wantError: false,
			wantType:  "*providers.TinkProvider",
		},
		{
			name: "AES-GCM without key",
			config: &ProviderConfig{
				Type: ProviderTypeAESGCM,
			},
			wantError: true,
		},
		{
			name: "Tink without KEK URI",
			config: &ProviderConfig{
				Type: ProviderTypeTink,
			},
			wantError: true,
		},
		{
			name: "unsupported provider type",
			config: &ProviderConfig{
				Type: "unsupported",
			},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider, err := factory.CreateProvider(tt.config)
			if tt.wantError {
				assert.Error(t, err)
				assert.Nil(t, provider)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, provider)
				// Provider was created successfully
			}
		})
	}
}

func TestFactory_ValidateProviderConfig(t *testing.T) {
	factory := NewFactory()

	tests := []struct {
		name      string
		config    *ProviderConfig
		wantError bool
	}{
		{
			name:      "nil config",
			config:    nil,
			wantError: true,
		},
		{
			name: "valid AES-GCM config",
			config: &ProviderConfig{
				Type:   ProviderTypeAESGCM,
				AESKey: "test-key",
			},
			wantError: false,
		},
		{
			name: "AES-GCM without key",
			config: &ProviderConfig{
				Type: ProviderTypeAESGCM,
			},
			wantError: true,
		},
		{
			name: "valid Tink config",
			config: &ProviderConfig{
				Type:   ProviderTypeTink,
				KEKUri: "test-uri",
			},
			wantError: false,
		},
		{
			name: "Tink without KEK URI",
			config: &ProviderConfig{
				Type: ProviderTypeTink,
			},
			wantError: true,
		},
		{
			name: "unsupported type",
			config: &ProviderConfig{
				Type: "invalid",
			},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := factory.ValidateProviderConfig(tt.config)
			if tt.wantError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestFactory_GetSupportedProviders(t *testing.T) {
	factory := NewFactory()

	providers := factory.GetSupportedProviders()

	assert.Len(t, providers, 2)
	assert.Contains(t, providers, ProviderTypeAESGCM)
	assert.Contains(t, providers, ProviderTypeTink)
}

func TestProviderType_Constants(t *testing.T) {
	assert.Equal(t, ProviderType("aes256-gcm"), ProviderTypeAESGCM)
	assert.Equal(t, ProviderType("tink"), ProviderTypeTink)
}
