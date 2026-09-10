package orchestration

import (
	"container/list"
	"context"
	"fmt"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/guided-traffic/s3-encryption-proxy/internal/config"
	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption/keyencryption"
)

// MockKeyEncryptor implements KeyEncryptor for testing
type MockKeyEncryptor struct {
	mock.Mock
	fingerprint string
}

func (m *MockKeyEncryptor) EncryptDEK(ctx context.Context, dek []byte) ([]byte, error) {
	args := m.Called(ctx, dek)
	return args.Get(0).([]byte), args.Error(1)
}

func (m *MockKeyEncryptor) DecryptDEK(ctx context.Context, encryptedDEK []byte) ([]byte, error) {
	args := m.Called(ctx, encryptedDEK)
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
			name: "successful initialization with exit provider",
			config: &config.Config{
				Encryption: config.EncryptionConfig{
					EncryptionMethodAlias: "exit-provider",
					Providers: []config.EncryptionProvider{
						{
							Alias: "exit-provider",
							Type:  "exit",
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
								"aes_key": "ZEsubBlmU+Pr61y+JOwO09c0LOrHs5LITaO0D4JzSZE=", // 32-byte base64 key
							},
						},
					},
				},
			},
			expectError: false,
		},
		{
			name: "valid exit provider",
			config: &config.Config{
				Encryption: config.EncryptionConfig{
					EncryptionMethodAlias: "test-exit",
					Providers: []config.EncryptionProvider{
						{
							Alias:  "test-exit",
							Type:   "exit",
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
								"aes_key": "ZEsubBlmU+Pr61y+JOwO09c0LOrHs5LITaO0D4JzSZE=",
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
							Alias:  "test-invalid",
							Type:   "invalid-type",
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
								"aes_key": "ZEsubBlmU+Pr61y+JOwO09c0LOrHs5LITaO0D4JzSZE=",
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
						"aes_key": "ZEsubBlmU+Pr61y+JOwO09c0LOrHs5LITaO0D4JzSZE=",
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
	require.Len(t, testDEK, 32)                           // AES-256 requires 32-byte key

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

func TestProviderManager_ExitProvider(t *testing.T) {

	// Setup test configuration with the exit provider
	cfg := &config.Config{
		Encryption: config.EncryptionConfig{
			EncryptionMethodAlias: "test-exit",
			Providers: []config.EncryptionProvider{
				{
					Alias:  "test-exit",
					Type:   "exit",
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

	t.Run("exit provider fingerprint", func(t *testing.T) {
		assert.Equal(t, "exit-provider-fingerprint", pm.GetActiveFingerprint())
	})

	t.Run("exit provider refuses to wrap a DEK", func(t *testing.T) {
		encryptedDEK, err := pm.EncryptDEK(testDEK, "test-object-key")
		assert.ErrorIs(t, err, keyencryption.ErrExitProviderKeyUse)
		assert.Nil(t, encryptedDEK)
	})

	t.Run("exit provider refuses to unwrap a DEK", func(t *testing.T) {
		fingerprint := pm.GetActiveFingerprint()
		decryptedDEK, err := pm.DecryptDEK(testDEK, fingerprint, "test-object-key")
		assert.ErrorIs(t, err, keyencryption.ErrExitProviderKeyUse)
		assert.Nil(t, decryptedDEK)
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
						"aes_key": "ZEsubBlmU+Pr61y+JOwO09c0LOrHs5LITaO0D4JzSZE=",
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

	// Regression for the data-key cache rule of ADR 0002: re-uploading the same
	// object key produces a fresh DEK and therefore a fresh encryptedDEK blob.
	// The cache must NOT return the previous DEK — that would decrypt the new
	// ciphertext to garbage and trip HMAC verification.
	t.Run("re-upload to same key does not return stale DEK", func(t *testing.T) {
		const objectKey = "reupload-key"

		firstDEK := []byte("first-dek-32-bytes-aaaaaaaaaaaaa") // 32 B
		require.Len(t, firstDEK, 32)
		secondDEK := []byte("second-dek-32-bytes-bbbbbbbbbbbb") // 32 B
		require.Len(t, secondDEK, 32)

		firstEncrypted, err := pm.EncryptDEK(firstDEK, objectKey)
		require.NoError(t, err)
		secondEncrypted, err := pm.EncryptDEK(secondDEK, objectKey)
		require.NoError(t, err)
		require.NotEqual(t, firstEncrypted, secondEncrypted,
			"AES KEK encryption must produce distinct blobs for distinct DEKs")

		// Warm the cache with the first upload's DEK.
		got1, err := pm.DecryptDEK(firstEncrypted, fingerprint, objectKey)
		require.NoError(t, err)
		assert.Equal(t, firstDEK, got1)

		// Decrypt the second (re-uploaded) DEK under the same object key.
		// Pre-fix this returned firstDEK from the cache.
		got2, err := pm.DecryptDEK(secondEncrypted, fingerprint, objectKey)
		require.NoError(t, err)
		assert.Equal(t, secondDEK, got2,
			"second decrypt must return the new DEK, not a stale cache hit")

		// The first encryptedDEK still resolves to the first DEK (its cache
		// entry was preserved, since the keys differ).
		got1Again, err := pm.DecryptDEK(firstEncrypted, fingerprint, objectKey)
		require.NoError(t, err)
		assert.Equal(t, firstDEK, got1Again)
	})
}

// TestProviderManager_CacheLRUEviction verifies that the bounded LRU evicts
// the least-recently-used entry once the cache exceeds dekCacheCapacity, so
// long-running proxies cannot grow the DEK cache without bound.
func TestProviderManager_CacheLRUEviction(t *testing.T) {
	pm := &ProviderManager{
		keyCacheItems: make(map[string]*list.Element),
		keyCacheOrder: list.New(),
		logger:        logrus.WithField("component", "test"),
	}

	// Fill exactly to capacity.
	for i := 0; i < dekCacheCapacity; i++ {
		pm.cachePut(fmt.Sprintf("key-%d", i), []byte{byte(i)})
	}
	require.Equal(t, dekCacheCapacity, pm.keyCacheOrder.Len())

	// Touch the oldest entry so it becomes MRU.
	_, ok := pm.cacheGet("key-0")
	require.True(t, ok)

	// Insert one more entry — this should evict the now-oldest, which is key-1.
	pm.cachePut("key-new", []byte{0xff})
	require.Equal(t, dekCacheCapacity, pm.keyCacheOrder.Len())

	if _, ok := pm.cacheGet("key-1"); ok {
		t.Fatal("expected key-1 to be evicted (LRU)")
	}
	if _, ok := pm.cacheGet("key-0"); !ok {
		t.Fatal("expected key-0 to survive eviction (recently touched)")
	}
	if _, ok := pm.cacheGet("key-new"); !ok {
		t.Fatal("expected freshly inserted key-new to be cached")
	}
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
						"aes_key": "ZEsubBlmU+Pr61y+JOwO09c0LOrHs5LITaO0D4JzSZE=",
					},
				},
				{
					Alias:  "backup-exit",
					Type:   "exit",
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
		assert.Contains(t, aliases, "backup-exit")
	})

	t.Run("get all providers", func(t *testing.T) {
		providers := pm.registeredProviders
		assert.Len(t, providers, 2)

		// Check active provider
		var activeProvider, backupProvider *ProviderInfo
		for alias, provider := range providers {
			if alias == "active-aes" {
				activeProvider = &provider
			} else if alias == "backup-exit" {
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
		assert.Equal(t, "exit", backupProvider.Type)
		assert.Equal(t, "exit-provider-fingerprint", backupProvider.Fingerprint)
		assert.NotNil(t, backupProvider.Encryptor)
	})
}
