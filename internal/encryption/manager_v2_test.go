package encryption

import (
	"context"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/guided-traffic/s3-encryption-proxy/internal/config"
)

func TestNewManagerV2(t *testing.T) {
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
								"aes_key": "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=",
							},
						},
					},
				},
			},
			expectError: false,
		},
		{
			name: "valid configuration with none provider",
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
							Alias: "invalid-provider",
							Type:  "invalid-type",
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
			manager, err := NewManagerV2(tt.config)

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
				assert.Nil(t, manager)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, manager)

				// Verify components are properly initialized
				assert.NotNil(t, manager.GetProviderManager())
				assert.NotNil(t, manager.GetMetadataManager())

				// Verify configuration is accessible
				assert.Equal(t, tt.config, manager.config)

				// Verify provider manager integration
				assert.Equal(t, tt.config.Encryption.EncryptionMethodAlias, manager.GetActiveProviderAlias())
				assert.NotEmpty(t, manager.GetActiveFingerprint())

				// Verify metadata manager integration
				expectedPrefix := "s3ep-" // default
				if tt.config.Encryption.MetadataKeyPrefix != nil {
					expectedPrefix = *tt.config.Encryption.MetadataKeyPrefix
				}
				assert.Equal(t, expectedPrefix, manager.GetMetadataManager().GetPrefix())
			}
		})
	}
}

func TestManagerV2_ComponentIntegration(t *testing.T) {
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

	manager, err := NewManagerV2(config)
	require.NoError(t, err)
	require.NotNil(t, manager)

	t.Run("provider manager integration", func(t *testing.T) {
		pm := manager.GetProviderManager()
		assert.NotNil(t, pm)

		// Test provider functionality
		aliases := pm.GetProviderAliases()
		assert.Len(t, aliases, 2)
		assert.Contains(t, aliases, "test-aes")
		assert.Contains(t, aliases, "backup-none")

		// Test DEK operations
		testDEK := []byte("test-data-encryption-key-32-bytes")
		encryptedDEK, err := pm.EncryptDEK(context.Background(), testDEK, "test-aes")
		assert.NoError(t, err)
		assert.NotNil(t, encryptedDEK)

		fingerprint := pm.GetActiveFingerprint()
		decryptedDEK, err := pm.DecryptDEK(context.Background(), encryptedDEK, fingerprint)
		assert.NoError(t, err)
		assert.Equal(t, testDEK, decryptedDEK)
	})

	t.Run("metadata manager integration", func(t *testing.T) {
		mm := manager.GetMetadataManager()
		assert.NotNil(t, mm)

		// Test metadata functionality
		assert.Equal(t, "s3ep-", mm.GetPrefix())

		fullKey := mm.BuildMetadataKey("test-key")
		assert.Equal(t, "s3ep-test-key", fullKey)

		baseKey := mm.ExtractMetadataKey(fullKey)
		assert.Equal(t, "test-key", baseKey)

		// Test encryption metadata detection
		assert.True(t, mm.IsEncryptionMetadata("s3ep-encrypted-dek"))
		assert.False(t, mm.IsEncryptionMetadata("user-custom-header"))
	})

	t.Run("configuration validation", func(t *testing.T) {
		err := manager.ValidateConfiguration()
		assert.NoError(t, err)
	})

	t.Run("manager accessors", func(t *testing.T) {
		assert.Equal(t, "test-aes", manager.GetActiveProviderAlias())
		assert.NotEmpty(t, manager.GetActiveFingerprint())

		aliases := manager.GetProviderAliases()
		assert.Len(t, aliases, 2)
		assert.Contains(t, aliases, "test-aes")
		assert.Contains(t, aliases, "backup-none")
	})
}

func TestManagerV2_ValidateConfiguration(t *testing.T) {
	// Create a manager with valid configuration
	config := &config.Config{
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

	manager, err := NewManagerV2(config)
	require.NoError(t, err)

	t.Run("valid configuration", func(t *testing.T) {
		err := manager.ValidateConfiguration()
		assert.NoError(t, err)
	})

	t.Run("provider manager validation failure", func(t *testing.T) {
		// Manually break provider manager to test validation
		manager.providerManager.activeFingerprint = ""

		err := manager.ValidateConfiguration()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no active provider fingerprint set")
	})
}

func TestManagerV2_LoggingIntegration(t *testing.T) {
	// Setup test configuration
	config := &config.Config{
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

	// Capture log output
	oldLevel := logrus.GetLevel()
	logrus.SetLevel(logrus.DebugLevel)
	defer logrus.SetLevel(oldLevel)

	manager, err := NewManagerV2(config)
	require.NoError(t, err)
	require.NotNil(t, manager)

	// Test that components have proper logging context
	assert.NotNil(t, manager.logger)
	assert.Equal(t, "encryption_manager_v2", manager.logger.Data["component"])
}
