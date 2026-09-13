package orchestration

import (
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/guided-traffic/s3-encryption-proxy/internal/config"
)

func TestNewManager(t *testing.T) {
	tests := []struct {
		name        string
		config      *config.Config
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid configuration with AES provider",
			config: &config.Config{
				Encryption: config.EncryptionConfig{
					EncryptionMethodAlias: "test-aes",
					MetadataKeyPrefix:     func(s string) *string { return &s }("s3ep-"),
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
			expectError: false,
		},
		{
			name: "valid configuration with the exit provider",
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
			name: "valid configuration with multiple providers",
			config: &config.Config{
				Encryption: config.EncryptionConfig{
					EncryptionMethodAlias: "active-aes",
					MetadataKeyPrefix:     func(s string) *string { return &s }("custom-"),
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
			name:        "nil configuration",
			config:      nil,
			expectError: true,
			errorMsg:    "configuration cannot be nil",
		},
		{
			name: "invalid provider configuration",
			config: &config.Config{
				Encryption: config.EncryptionConfig{
					EncryptionMethodAlias: "invalid-provider",
					Providers: []config.EncryptionProvider{
						{
							Alias:  "invalid-provider",
							Type:   "invalid-type",
							Config: map[string]interface{}{},
						},
					},
				},
			},
			expectError: true,
			errorMsg:    "failed to create provider manager",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manager, err := NewManager(tt.config)

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
				assert.Nil(t, manager)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, manager)

				// Verify provider manager integration: every configured provider
				// is loaded, and the configured alias is the active one.
				providers := manager.GetLoadedProviders()
				require.Len(t, providers, len(tt.config.Encryption.Providers))
				for _, provider := range providers {
					assert.Equal(t, provider.Alias == tt.config.Encryption.EncryptionMethodAlias,
						provider.IsActive)
				}
			}
		})
	}
}

func TestManager_ComponentIntegration(t *testing.T) {
	// Setup test configuration
	config := &config.Config{
		Encryption: config.EncryptionConfig{
			EncryptionMethodAlias: "test-aes",
			MetadataKeyPrefix:     func(s string) *string { return &s }("s3ep-"),
			Providers: []config.EncryptionProvider{
				{
					Alias: "test-aes",
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

	manager, err := NewManager(config)
	require.NoError(t, err)
	require.NotNil(t, manager)

	t.Run("provider manager integration", func(t *testing.T) {
		loadedProviders := manager.GetLoadedProviders()
		require.Len(t, loadedProviders, 2)

		byAlias := map[string]ProviderSummary{}
		for _, provider := range loadedProviders {
			byAlias[provider.Alias] = provider
		}

		require.Contains(t, byAlias, "test-aes")
		assert.Equal(t, "aes", byAlias["test-aes"].Type)
		assert.True(t, byAlias["test-aes"].IsActive)
		assert.NotEmpty(t, byAlias["test-aes"].Fingerprint)

		require.Contains(t, byAlias, "backup-exit")
		assert.Equal(t, "exit", byAlias["backup-exit"].Type)
		assert.False(t, byAlias["backup-exit"].IsActive)
	})

	t.Run("manager accessors", func(t *testing.T) {
		assert.Equal(t, "s3ep-", manager.GetMetadataKeyPrefix())
		assert.False(t, manager.IsExitProvider())
	})
}

func TestManager_ValidateConfiguration(t *testing.T) {
	// Create a manager with valid configuration
	config := &config.Config{
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

	manager, err := NewManager(config)
	require.NoError(t, err)
	assert.NotNil(t, manager)
}

func TestManager_LoggingIntegration(t *testing.T) {
	// Setup test configuration
	config := &config.Config{
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

	// Capture log output
	oldLevel := logrus.GetLevel()
	logrus.SetLevel(logrus.DebugLevel)
	defer logrus.SetLevel(oldLevel)

	manager, err := NewManager(config)
	require.NoError(t, err)
	require.NotNil(t, manager)

	// Test that components have proper logging context
	assert.NotNil(t, manager.logger)
	assert.Equal(t, "encryption_manager", manager.logger.Data["component"])
}

func TestManager_ExitProvider(t *testing.T) {
	// Setup test configuration with the exit provider
	config := &config.Config{
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

	manager, err := NewManager(config)
	require.NoError(t, err)

	t.Run("the exit provider is reported as active", func(t *testing.T) {
		assert.True(t, manager.IsExitProvider())

		providers := manager.GetLoadedProviders()
		require.Len(t, providers, 1)
		assert.Equal(t, "exit", providers[0].Type)
		assert.Equal(t, "exit-provider-fingerprint", providers[0].Fingerprint)
		assert.True(t, providers[0].IsActive)
	})
}
