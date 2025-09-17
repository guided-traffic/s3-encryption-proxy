package encryption

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/guided-traffic/s3-encryption-proxy/internal/config"
)

// MockKeyEncryptor implements KeyEncryptor for testing
type MockKeyEncryptor struct {
	mock.Mock
	fingerprint string
}

func (m *MockKeyEncryptor) EncryptDEK(ctx context.Context, dek []byte) ([]byte, string, error) {
	args := m.Called(ctx, dek)
	return args.Get(0).([]byte), args.String(1), args.Error(2)
}

func (m *MockKeyEncryptor) DecryptDEK(ctx context.Context, encryptedDEK []byte, keyID string) ([]byte, error) {
	args := m.Called(ctx, encryptedDEK, keyID)
	return args.Get(0).([]byte), args.Error(1)
}

func (m *MockKeyEncryptor) Fingerprint() string {
	return m.fingerprint
}

func (m *MockKeyEncryptor) SetFingerprint(fp string) {
	m.fingerprint = fp
}

func TestNewProviderManager(t *testing.T) {
	tests := []struct {
		name      string
		config    *config.Config
		wantErr   bool
		expectErr string
	}{
		{
			name: "successful initialization with AES provider",
			config: &config.Config{
				Encryption: config.EncryptionConfig{
					EncryptionMethodAlias: "aes-provider",
					Providers: []config.EncryptionProvider{
						{
							Alias: "aes-provider",
							Type:  "aes",
							Config: map[string]interface{}{
								"aes_key": "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=", // base64 encoded 32-byte key
							},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "successful initialization with none provider",
			config: &config.Config{
				Encryption: config.EncryptionConfig{
					EncryptionMethodAlias: "none-provider",
					Providers: []config.EncryptionProvider{
						{
							Alias: "none-provider",
							Type:  "none",
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "missing active provider",
			config: &config.Config{
				Encryption: config.EncryptionConfig{
					EncryptionMethodAlias: "missing-provider",
					Providers: []config.EncryptionProvider{
						{
							Alias: "other-provider",
							Type:  "aes",
							Config: map[string]interface{}{
								"aes_key": "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
							},
						},
					},
				},
			},
			wantErr:   true,
			expectErr: "active encryption provider 'missing-provider' not found",
		},
		{
			name: "unsupported provider type",
			config: &config.Config{
				Encryption: config.EncryptionConfig{
					EncryptionMethodAlias: "unsupported-provider",
					Providers: []config.EncryptionProvider{
						{
							Alias: "unsupported-provider",
							Type:  "unsupported",
						},
					},
				},
			},
			wantErr:   true,
			expectErr: "has invalid type 'unsupported'",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pm, err := NewProviderManager(tt.config)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, pm)
				if tt.expectErr != "" {
					assert.Contains(t, err.Error(), tt.expectErr)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, pm)
				assert.Equal(t, tt.config, pm.config)
				assert.NotEmpty(t, pm.activeAlias)
				assert.NotEmpty(t, pm.activeFingerprint)
			}
		})
	}
}

func TestProviderManager_NewProviderManager(t *testing.T) {

	tests := []struct {
		name        string
		config      *config.Config
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid AES provider",
			config: &config.Config{
				Encryption: config.EncryptionConfig{
					EncryptionMethodAlias: "test-aes",
					Providers: []config.EncryptionProvider{
						{
							Alias: "test-aes",
							Type:  "aes",
							Config: map[string]interface{}{
								"aes_key": "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=", // 32-byte base64 key
							},
						},
					},
				},
			},
			expectError: false,
		},
		{
			name: "valid none provider",
			config: &config.Config{
				Encryption: config.EncryptionConfig{
					EncryptionMethodAlias: "test-none",
					Providers: []config.EncryptionProvider{
						{
							Alias: "test-none",
							Type:  "none",
							Config: map[string]interface{}{},
						},
					},
				},
			},
			expectError: false,
		},
		{
			name: "multiple providers",
			config: &config.Config{
				Encryption: config.EncryptionConfig{
					EncryptionMethodAlias: "active-aes",
					Providers: []config.EncryptionProvider{
						{
							Alias: "active-aes",
							Type:  "aes",
							Config: map[string]interface{}{
								"aes_key": "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=",
							},
						},
						{
							Alias: "backup-aes",
							Type:  "aes",
							Config: map[string]interface{}{
								"aes_key": "ZGJjYWVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=",
							},
						},
					},
				},
			},
			expectError: false,
		},
		{
			name: "unsupported provider type",
			config: &config.Config{
				Encryption: config.EncryptionConfig{
					EncryptionMethodAlias: "test-invalid",
					Providers: []config.EncryptionProvider{
						{
							Alias: "test-invalid",
							Type:  "invalid-type",
							Config: map[string]interface{}{},
						},
					},
				},
			},
			expectError: true,
			errorMsg:    "failed to get active provider",
		},
		{
			name: "active provider not found",
			config: &config.Config{
				Encryption: config.EncryptionConfig{
					EncryptionMethodAlias: "missing-provider",
					Providers: []config.EncryptionProvider{
						{
							Alias: "test-aes",
							Type:  "aes",
							Config: map[string]interface{}{
								"aes_key": "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=",
							},
						},
					},
				},
			},
			expectError: true,
			errorMsg:    "failed to get active provider",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pm, err := NewProviderManager(tt.config)

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
				assert.Nil(t, pm)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, pm)

				// Verify configuration
				assert.Equal(t, tt.config.Encryption.EncryptionMethodAlias, pm.GetActiveProviderAlias())
				assert.NotEmpty(t, pm.GetActiveFingerprint())

				// Verify all providers are registered
				aliases := pm.GetProviderAliases()
				assert.Len(t, aliases, len(tt.config.Encryption.Providers))
			}
		})
	}
}

func TestProviderManager_EncryptDecryptDEK(t *testing.T) {

	// Setup test configuration with AES provider
	cfg := &config.Config{
		Encryption: config.EncryptionConfig{
			EncryptionMethodAlias: "test-aes",
			Providers: []config.EncryptionProvider{
				{
					Alias: "test-aes",
					Type:  "aes",
					Config: map[string]interface{}{
						"aes_key": "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=",
					},
				},
			},
		},
	}

	pm, err := NewProviderManager(cfg)
	require.NoError(t, err)
	require.NotNil(t, pm)

	// Test data
	testDEK := []byte("test-data-encryption-32-byte-key") // Exactly 32 bytes
	require.Len(t, testDEK, 32) // AES-256 requires 32-byte key

	t.Run("encrypt DEK with active provider", func(t *testing.T) {
		encryptedDEK, err := pm.EncryptDEK(testDEK, "test-object-key")
		assert.NoError(t, err)
		assert.NotNil(t, encryptedDEK)
		assert.NotEqual(t, testDEK, encryptedDEK)
		assert.Greater(t, len(encryptedDEK), 0)
	})

	t.Run("encrypt DEK with nonexistent provider", func(t *testing.T) {
		// This test needs to be adjusted since EncryptDEK now uses the active provider
		// Let's test with invalid DEK instead
		_, err := pm.EncryptDEK([]byte{}, "test-object-key")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "DEK cannot be empty")
	})

	t.Run("encrypt empty DEK", func(t *testing.T) {
		_, err := pm.EncryptDEK([]byte{}, "test-object-key")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "DEK cannot be empty")
	})

	t.Run("encrypt and decrypt DEK round trip", func(t *testing.T) {
		// Encrypt with active provider
		encryptedDEK, err := pm.EncryptDEK(testDEK, "test-object-key")
		require.NoError(t, err)

		// Decrypt with fingerprint
		fingerprint := pm.GetActiveFingerprint()
		decryptedDEK, err := pm.DecryptDEK(encryptedDEK, fingerprint, "test-object-key")
		assert.NoError(t, err)
		assert.Equal(t, testDEK, decryptedDEK)
	})

	t.Run("decrypt with invalid fingerprint", func(t *testing.T) {
		encryptedDEK, err := pm.EncryptDEK(testDEK, "test-object-key")
		require.NoError(t, err)

		_, err = pm.DecryptDEK(encryptedDEK, "invalid-fingerprint", "test-object-key")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no provider found with fingerprint")
	})

	t.Run("decrypt empty encrypted DEK", func(t *testing.T) {
		fingerprint := pm.GetActiveFingerprint()
		_, err := pm.DecryptDEK([]byte{}, fingerprint, "test-object-key")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "encrypted DEK cannot be empty")
	})
}

func TestProviderManager_NoneProvider(t *testing.T) {

	// Setup test configuration with none provider
	cfg := &config.Config{
		Encryption: config.EncryptionConfig{
			EncryptionMethodAlias: "test-none",
			Providers: []config.EncryptionProvider{
				{
					Alias: "test-none",
					Type:  "none",
					Config: map[string]interface{}{},
				},
			},
		},
	}

	pm, err := NewProviderManager(cfg)
	require.NoError(t, err)
	require.NotNil(t, pm)

	// Test data
	testDEK := []byte("test-data-encryption-key")

	t.Run("none provider fingerprint", func(t *testing.T) {
		assert.Equal(t, "none-provider-fingerprint", pm.GetActiveFingerprint())
	})

	t.Run("none provider encrypt DEK returns as-is", func(t *testing.T) {
		encryptedDEK, err := pm.EncryptDEK(testDEK, "test-object-key")
		assert.NoError(t, err)
		assert.Equal(t, testDEK, encryptedDEK)
	})

	t.Run("none provider decrypt DEK returns as-is", func(t *testing.T) {
		fingerprint := pm.GetActiveFingerprint()
		decryptedDEK, err := pm.DecryptDEK(testDEK, fingerprint, "test-object-key")
		assert.NoError(t, err)
		assert.Equal(t, testDEK, decryptedDEK)
	})
}

func TestProviderManager_Cache(t *testing.T) {

	// Setup test configuration
	cfg := &config.Config{
		Encryption: config.EncryptionConfig{
			EncryptionMethodAlias: "test-aes",
			Providers: []config.EncryptionProvider{
				{
					Alias: "test-aes",
					Type:  "aes",
					Config: map[string]interface{}{
						"aes_key": "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=",
					},
				},
			},
		},
	}

	pm, err := NewProviderManager(cfg)
	require.NoError(t, err)

	testDEK := []byte("test-data-encryption-32-byte-key")
	fingerprint := pm.GetActiveFingerprint()

	// Encrypt DEK first
	encryptedDEK, err := pm.EncryptDEK(testDEK, "test-object-key")
	require.NoError(t, err)

	t.Run("cache DEK after first decryption", func(t *testing.T) {
		// First decryption should cache the result
		decryptedDEK1, err := pm.DecryptDEK(encryptedDEK, fingerprint, "test-object-key")
		assert.NoError(t, err)
		assert.Equal(t, testDEK, decryptedDEK1)

		// Second decryption should use cache (should be fast and identical)
		decryptedDEK2, err := pm.DecryptDEK(encryptedDEK, fingerprint, "test-object-key")
		assert.NoError(t, err)
		assert.Equal(t, testDEK, decryptedDEK2)
		assert.Equal(t, decryptedDEK1, decryptedDEK2)
	})

	t.Run("clear cache", func(t *testing.T) {
		pm.ClearCache()

		// After clearing cache, decryption should still work
		decryptedDEK, err := pm.DecryptDEK(encryptedDEK, fingerprint, "test-object-key")
		assert.NoError(t, err)
		assert.Equal(t, testDEK, decryptedDEK)
	})
}

func TestProviderManager_GetProviderInfo(t *testing.T) {

	// Setup test configuration with multiple providers
	cfg := &config.Config{
		Encryption: config.EncryptionConfig{
			EncryptionMethodAlias: "active-aes",
			Providers: []config.EncryptionProvider{
				{
					Alias: "active-aes",
					Type:  "aes",
					Config: map[string]interface{}{
						"aes_key": "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=",
					},
				},
				{
					Alias: "backup-none",
					Type:  "none",
					Config: map[string]interface{}{},
				},
			},
		},
	}

	pm, err := NewProviderManager(cfg)
	require.NoError(t, err)

	t.Run("get all provider aliases", func(t *testing.T) {
		aliases := pm.GetProviderAliases()
		assert.Len(t, aliases, 2)
		assert.Contains(t, aliases, "active-aes")
		assert.Contains(t, aliases, "backup-none")
	})

	t.Run("get all providers", func(t *testing.T) {
		providers := pm.GetAllProviders()
		assert.Len(t, providers, 2)

		// Check active provider
		var activeProvider, backupProvider *ProviderInfo
		for _, provider := range providers {
			if provider.Alias == "active-aes" {
				activeProvider = &provider
			} else if provider.Alias == "backup-none" {
				backupProvider = &provider
			}
		}

		require.NotNil(t, activeProvider)
		assert.True(t, activeProvider.IsActive)
		assert.Equal(t, "aes", activeProvider.Type)
		assert.NotEmpty(t, activeProvider.Fingerprint)
		assert.NotNil(t, activeProvider.Encryptor)

		require.NotNil(t, backupProvider)
		assert.False(t, backupProvider.IsActive)
		assert.Equal(t, "none", backupProvider.Type)
		assert.Equal(t, "none-provider-fingerprint", backupProvider.Fingerprint)
		assert.Nil(t, backupProvider.Encryptor)
	})

	t.Run("get provider by fingerprint", func(t *testing.T) {
		activeFingerprint := pm.GetActiveFingerprint()
		provider, err := pm.GetProviderByFingerprint(activeFingerprint)
		assert.NoError(t, err)
		assert.NotNil(t, provider)
		assert.Equal(t, activeFingerprint, provider.Fingerprint())
	})

	t.Run("get provider by invalid fingerprint", func(t *testing.T) {
		_, err := pm.GetProviderByFingerprint("invalid-fingerprint")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no provider found with fingerprint")
	})
}

func TestProviderManager_ValidateConfiguration(t *testing.T) {

	t.Run("valid configuration", func(t *testing.T) {
		cfg := &config.Config{
			Encryption: config.EncryptionConfig{
				EncryptionMethodAlias: "test-aes",
				Providers: []config.EncryptionProvider{
					{
						Alias: "test-aes",
						Type:  "aes",
						Config: map[string]interface{}{
							"aes_key": "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=",
						},
					},
				},
			},
		}

		pm, err := NewProviderManager(cfg)
		require.NoError(t, err)

		err = pm.ValidateConfiguration()
		assert.NoError(t, err)
	})

	t.Run("invalid configuration - no active fingerprint", func(t *testing.T) {
		pm := &ProviderManager{
			activeFingerprint:   "",
			registeredProviders: make(map[string]ProviderInfo),
		}

		err := pm.ValidateConfiguration()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no active provider fingerprint set")
	})

	t.Run("invalid configuration - no providers", func(t *testing.T) {
		pm := &ProviderManager{
			activeFingerprint:   "test-fingerprint",
			registeredProviders: make(map[string]ProviderInfo),
		}

		err := pm.ValidateConfiguration()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no providers registered")
	})
}
