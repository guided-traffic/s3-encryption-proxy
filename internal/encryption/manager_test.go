package encryption

import (
	"context"
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
			manager, err := NewManager(tt.config)

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
				assert.Nil(t, manager)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, manager)

				// Verify manager is properly initialized with valid methods
				assert.NotEmpty(t, manager.GetProviderAliases())

				// Verify configuration is accessible
				assert.Equal(t, tt.config.Encryption.EncryptionMethodAlias, manager.GetActiveProviderAlias())

				// Verify provider manager integration
				providers := manager.GetLoadedProviders()
				assert.NotEmpty(t, providers)
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

	manager, err := NewManager(config)
	require.NoError(t, err)
	require.NotNil(t, manager)

	t.Run("provider manager integration", func(t *testing.T) {
		// Test provider functionality using manager methods
		aliases := manager.GetProviderAliases()
		t.Logf("Found aliases: %v", aliases) // Debug output
		assert.NotEmpty(t, aliases)
		assert.Contains(t, aliases, "test-aes")

		// Test active provider
		activeAlias := manager.GetActiveProviderAlias()
		t.Logf("Active alias: %s", activeAlias) // Debug output
		assert.Equal(t, "test-aes", activeAlias)

		// Test loaded providers summary (this should work)
		loadedProviders := manager.GetLoadedProviders()
		t.Logf("Loaded providers: %d", len(loadedProviders)) // Debug output
		assert.NotEmpty(t, loadedProviders)

		// Verify we have the expected provider
		foundTestAES := false
		for _, provider := range loadedProviders {
			if provider.Alias == "test-aes" {
				foundTestAES = true
				assert.Equal(t, "aes", provider.Type)
				break
			}
		}
		assert.True(t, foundTestAES, "Should find test-aes provider in loaded providers")
	})

	t.Run("metadata functionality validation", func(t *testing.T) {
		// Test that the manager can handle metadata operations through encryption/decryption
		// Since MetadataManager is not directly accessible, we test through operations

		testData := []byte("test data for metadata operations")
		result, err := manager.EncryptData(context.Background(), testData, "test-object-key")
		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.NotEmpty(t, result.Metadata)

		// Verify metadata contains expected keys (encrypted DEK, etc.)
		hasEncryptedDEK := false
		for key := range result.Metadata {
			if key == "s3ep-encrypted-dek" {
				hasEncryptedDEK = true
				break
			}
		}
		assert.True(t, hasEncryptedDEK, "Metadata should contain encrypted DEK")
	})

	t.Run("manager accessors", func(t *testing.T) {
		assert.Equal(t, "test-aes", manager.GetActiveProviderAlias())

		aliases := manager.GetProviderAliases()
		assert.Len(t, aliases, 2)
		assert.Contains(t, aliases, "test-aes")
		assert.Contains(t, aliases, "backup-none")
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
						"aes_key": "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=",
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

	manager, err := NewManager(config)
	require.NoError(t, err)
	require.NotNil(t, manager)

	// Test that components have proper logging context
	assert.NotNil(t, manager.logger)
	assert.Equal(t, "encryption_manager", manager.logger.Data["component"])
}
