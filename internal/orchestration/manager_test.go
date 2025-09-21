package orchestration

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/guided-traffic/s3-encryption-proxy/internal/config"
)

// calculateSHA256ForManagerTest computes SHA256 hash of data for test comparisons
func calculateSHA256ForManagerTest(data []byte) string {
	hash := sha256.Sum256(data)
	return fmt.Sprintf("%x", hash)
}

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
		testDataReader := bufio.NewReader(bytes.NewReader(testData))

		result, err := manager.EncryptData(context.Background(), testDataReader, "test-object-key")
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

		// Test round-trip by reading the encrypted data and decrypting it
		encryptedData, err := io.ReadAll(result.EncryptedDataReader)
		assert.NoError(t, err)
		assert.NotEmpty(t, encryptedData)

		// Verify the encrypted data is different from original
		assert.NotEqual(t, calculateSHA256ForManagerTest(testData), calculateSHA256ForManagerTest(encryptedData),
			"Encrypted data should be different from original")

		// Test decryption
		encryptedDataReader := bufio.NewReader(bytes.NewReader(encryptedData))
		decryptedReader, err := manager.DecryptData(context.Background(), encryptedDataReader, result.Metadata, "test-object-key")
		assert.NoError(t, err)
		assert.NotNil(t, decryptedReader)

		// Read decrypted data and verify it matches original
		decryptedData, err := io.ReadAll(decryptedReader)
		assert.NoError(t, err)
		assert.Equal(t, calculateSHA256ForManagerTest(testData), calculateSHA256ForManagerTest(decryptedData),
			"Decrypted data should match original")
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

func TestManager_StreamingOperations(t *testing.T) {
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
			},
		},
	}

	manager, err := NewManager(config)
	require.NoError(t, err)

	ctx := context.Background()

	t.Run("encrypt and decrypt small data stream", func(t *testing.T) {
		originalData := []byte("small test data for streaming")
		dataReader := bufio.NewReader(bytes.NewReader(originalData))

		// Encrypt the data
		result, err := manager.EncryptData(ctx, dataReader, "test-small-object")
		require.NoError(t, err)
		require.NotNil(t, result)
		require.NotNil(t, result.EncryptedDataReader)
		require.NotEmpty(t, result.Metadata)

		// Read encrypted data
		encryptedData, err := io.ReadAll(result.EncryptedDataReader)
		require.NoError(t, err)
		require.NotEmpty(t, encryptedData)

		// Verify encrypted data is different from original
		assert.NotEqual(t, calculateSHA256ForManagerTest(originalData), calculateSHA256ForManagerTest(encryptedData))

		// Decrypt the data
		encryptedReader := bufio.NewReader(bytes.NewReader(encryptedData))
		decryptedReader, err := manager.DecryptData(ctx, encryptedReader, result.Metadata, "test-small-object")
		require.NoError(t, err)
		require.NotNil(t, decryptedReader)

		// Verify decrypted data matches original
		decryptedData, err := io.ReadAll(decryptedReader)
		require.NoError(t, err)
		assert.Equal(t, calculateSHA256ForManagerTest(originalData), calculateSHA256ForManagerTest(decryptedData))
	})

	t.Run("encrypt and decrypt large data stream", func(t *testing.T) {
		// Create larger test data (>1MB) to trigger CTR mode
		originalData := make([]byte, 1024*1024+1000) // ~1MB
		for i := range originalData {
			originalData[i] = byte(i % 256)
		}
		dataReader := bufio.NewReader(bytes.NewReader(originalData))

		// Encrypt the data
		result, err := manager.EncryptData(ctx, dataReader, "test-large-object")
		require.NoError(t, err)
		require.NotNil(t, result)
		require.NotNil(t, result.EncryptedDataReader)
		require.NotEmpty(t, result.Metadata)

		// Read encrypted data
		encryptedData, err := io.ReadAll(result.EncryptedDataReader)
		require.NoError(t, err)
		require.NotEmpty(t, encryptedData)

		// Verify encrypted data is different from original
		assert.NotEqual(t, calculateSHA256ForManagerTest(originalData), calculateSHA256ForManagerTest(encryptedData))

		// Decrypt the data
		encryptedReader := bufio.NewReader(bytes.NewReader(encryptedData))
		decryptedReader, err := manager.DecryptData(ctx, encryptedReader, result.Metadata, "test-large-object")
		require.NoError(t, err)
		require.NotNil(t, decryptedReader)

		// Verify decrypted data matches original
		decryptedData, err := io.ReadAll(decryptedReader)
		require.NoError(t, err)
		assert.Equal(t, calculateSHA256ForManagerTest(originalData), calculateSHA256ForManagerTest(decryptedData))
	})

	t.Run("encrypt with specific GCM algorithm", func(t *testing.T) {
		originalData := []byte("test data for explicit GCM encryption")
		dataReader := bufio.NewReader(bytes.NewReader(originalData))

		// Encrypt using GCM explicitly
		result, err := manager.EncryptGCM(ctx, dataReader, "test-gcm-object")
		require.NoError(t, err)
		require.NotNil(t, result)
		require.NotEmpty(t, result.Metadata)
		assert.Contains(t, []string{"aes-gcm", "aes-gcm"}, result.Algorithm)

		// Verify metadata contains algorithm info
		assert.Contains(t, []string{"aes-gcm", "aes-gcm"}, result.Metadata["s3ep-dek-algorithm"])

		// Debug: print metadata
		t.Logf("GCM metadata: %+v", result.Metadata)

		// Read and verify round-trip
		encryptedData, err := io.ReadAll(result.EncryptedDataReader)
		require.NoError(t, err)

		encryptedReader := bufio.NewReader(bytes.NewReader(encryptedData))
		decryptedReader, err := manager.DecryptData(ctx, encryptedReader, result.Metadata, "test-gcm-object")
		require.NoError(t, err)

		decryptedData, err := io.ReadAll(decryptedReader)
		require.NoError(t, err)
		assert.Equal(t, calculateSHA256ForManagerTest(originalData), calculateSHA256ForManagerTest(decryptedData))
	})

	t.Run("encrypt with specific CTR algorithm", func(t *testing.T) {
		originalData := []byte("test data for explicit CTR encryption")
		dataReader := bufio.NewReader(bytes.NewReader(originalData))

		// Encrypt using CTR explicitly
		result, err := manager.EncryptCTR(ctx, dataReader, "test-ctr-object")
		require.NoError(t, err)
		require.NotNil(t, result)
		require.NotEmpty(t, result.Metadata)
		assert.Contains(t, []string{"aes-ctr"}, result.Algorithm)

		// Verify metadata contains algorithm info
		assert.Contains(t, []string{"aes-ctr"}, result.Metadata["s3ep-dek-algorithm"])

		// Debug: print metadata
		t.Logf("CTR metadata: %+v", result.Metadata)

		// Read and verify round-trip
		encryptedData, err := io.ReadAll(result.EncryptedDataReader)
		require.NoError(t, err)

		encryptedReader := bufio.NewReader(bytes.NewReader(encryptedData))
		decryptedReader, err := manager.DecryptData(ctx, encryptedReader, result.Metadata, "test-ctr-object")
		require.NoError(t, err)

		decryptedData, err := io.ReadAll(decryptedReader)
		require.NoError(t, err)
		assert.Equal(t, calculateSHA256ForManagerTest(originalData), calculateSHA256ForManagerTest(decryptedData))
	})
}

func TestManager_NoneProvider(t *testing.T) {
	// Setup test configuration with none provider
	config := &config.Config{
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

	manager, err := NewManager(config)
	require.NoError(t, err)

	ctx := context.Background()
	originalData := []byte("test data for none provider")
	dataReader := bufio.NewReader(bytes.NewReader(originalData))

	t.Run("none provider pass-through", func(t *testing.T) {
		// Encrypt should return data unchanged
		result, err := manager.EncryptData(ctx, dataReader, "test-none-object")
		require.NoError(t, err)
		require.NotNil(t, result)
		require.NotNil(t, result.EncryptedDataReader)

		// Should have no metadata
		assert.Empty(t, result.Metadata)

		// Data should be unchanged (pass-through)
		returnedData, err := io.ReadAll(result.EncryptedDataReader)
		require.NoError(t, err)
		assert.Equal(t, calculateSHA256ForManagerTest(originalData), calculateSHA256ForManagerTest(returnedData))

		// Decrypt should also pass through unchanged
		dataReader2 := bufio.NewReader(bytes.NewReader(originalData))
		decryptedReader, err := manager.DecryptData(ctx, dataReader2, result.Metadata, "test-none-object")
		require.NoError(t, err)

		decryptedData, err := io.ReadAll(decryptedReader)
		require.NoError(t, err)
		assert.Equal(t, calculateSHA256ForManagerTest(originalData), calculateSHA256ForManagerTest(decryptedData))
	})
}
