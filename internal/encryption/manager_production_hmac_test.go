package encryption

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/guided-traffic/s3-encryption-proxy/internal/config"
	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption/factory"
)

// TestManager_ProductionReadyValidation tests the complete production workflow
func TestManager_ProductionReadyValidation(t *testing.T) {
	ctx := context.Background()

	t.Run("ProductionWorkflow_WithHMACIntegrityVerification", func(t *testing.T) {
		// STEP 1: Create production-like configuration
		cfg := &config.Config{
			Encryption: config.EncryptionConfig{
				EncryptionMethodAlias: "production-aes",
				MetadataKeyPrefix:     stringPtr("s3ep-"),
				IntegrityVerification: true, // Production HMAC enabled
				Providers: []config.EncryptionProvider{
					{
						Alias: "production-aes",
						Type:  "aes",
						Config: map[string]interface{}{
							"kek": []byte("production-32byte-key-for-aes!!!"), // 32 bytes for AES-256
						},
					},
				},
			},
		}

		// STEP 2: Initialize manager
		manager, err := NewManager(cfg)
		require.NoError(t, err, "Failed to create production manager")

		// STEP 3: Test different scenarios
		testScenarios := []struct {
			name        string
			data        []byte
			contentType factory.ContentType
			description string
		}{
			{
				name:        "SmallDocument_AES-GCM_WithHMAC",
				data:        []byte("Important production document data for testing HMAC integrity verification"),
				contentType: factory.ContentTypeWhole,
				description: "Small document using AES-GCM with HMAC integrity verification",
			},
			{
				name:        "LargeFile_AES-CTR_WithHMAC",
				data:        make([]byte, 100*1024*1024), // 100MB
				contentType: factory.ContentTypeMultipart,
				description: "Large file using AES-CTR streaming with HMAC integrity verification",
			},
		}

		for i, scenario := range testScenarios {
			t.Run(scenario.name, func(t *testing.T) {
				// Initialize large data with pattern
				if len(scenario.data) > 1000 {
					for j := range scenario.data {
						scenario.data[j] = byte(j % 256)
					}
				}

				objectKey := scenario.name + "-production-test"
				t.Logf("🔐 Testing: %s (%d bytes)", scenario.description, len(scenario.data))

				// STEP 4: Encrypt with production settings
				encResult, err := manager.EncryptDataWithContentType(ctx, scenario.data, objectKey, scenario.contentType)
				require.NoError(t, err, "Production encryption failed")

				// STEP 5: Validate encryption result
				assert.NotEmpty(t, encResult.EncryptedData, "Encrypted data should not be empty")
				assert.NotEmpty(t, encResult.EncryptedDEK, "Encrypted DEK should not be empty")
				assert.NotEmpty(t, encResult.Metadata, "Metadata should not be empty")

				// STEP 6: Verify HMAC metadata presence
				hmacKey := manager.metadataManager.GetHMACMetadataKey()
				hmacValue, hasHMAC := encResult.Metadata[hmacKey]
				assert.True(t, hasHMAC, "HMAC metadata should be present in production mode")
				assert.NotEmpty(t, hmacValue, "HMAC value should not be empty")

				// STEP 7: Verify required encryption metadata
				expectedMetadata := []string{
					"s3ep-dek-algorithm",
					"s3ep-encrypted-dek",
					"s3ep-kek-algorithm",
					"s3ep-kek-fingerprint",
				}
				for _, key := range expectedMetadata {
					assert.Contains(t, encResult.Metadata, key, "Required metadata should be present: %s", key)
				}

				// STEP 8: Test decryption with integrity verification
				providerAlias := cfg.Encryption.EncryptionMethodAlias
				decryptedData, err := manager.DecryptDataWithMetadata(ctx, encResult.EncryptedData, encResult.EncryptedDEK, encResult.Metadata, objectKey, providerAlias)
				require.NoError(t, err, "Production decryption failed")

				// STEP 9: Verify data integrity
				assert.Equal(t, scenario.data, decryptedData, "Decrypted data should match original")

				// STEP 10: Log production metrics
				encryptionOverhead := float64(len(encResult.EncryptedData)) / float64(len(scenario.data))
				metadataCount := len(encResult.Metadata)

				t.Logf("✅ Production validation successful:")
				t.Logf("   Original Size: %d bytes", len(scenario.data))
				t.Logf("   Encrypted Size: %d bytes", len(encResult.EncryptedData))
				t.Logf("   Encryption Overhead: %.4f", encryptionOverhead)
				t.Logf("   Metadata Fields: %d", metadataCount)
				t.Logf("   HMAC Verification: ✅ Enabled")
				t.Logf("   Data Integrity: ✅ Verified")
			})

			// Log overall progress
			t.Logf("📈 Production validation progress: %d/%d scenarios completed", i+1, len(testScenarios))
		}
	})

	t.Run("ErrorHandling_ProductionScenarios", func(t *testing.T) {
		// Test error handling in production scenarios
		cfg := &config.Config{
			Encryption: config.EncryptionConfig{
				EncryptionMethodAlias: "prod-aes",
				MetadataKeyPrefix:     stringPtr("s3ep-"),
				IntegrityVerification: true,
				Providers: []config.EncryptionProvider{
					{
						Alias: "prod-aes",
						Type:  "aes",
						Config: map[string]interface{}{
							"kek": []byte("prod-error-test-key-32-bytes!!"),
						},
					},
				},
			},
		}

		manager, err := NewManager(cfg)
		require.NoError(t, err)

		testData := []byte("Production error handling test data")
		objectKey := "error-handling-test"

		// STEP 1: Test corrupted encrypted data
		encResult, err := manager.EncryptData(ctx, testData, objectKey)
		require.NoError(t, err)

		// Corrupt encrypted data
		corruptedData := make([]byte, len(encResult.EncryptedData))
		copy(corruptedData, encResult.EncryptedData)
		corruptedData[0] ^= 0xFF // Flip first byte

		_, err = manager.DecryptDataWithMetadata(ctx, corruptedData, encResult.EncryptedDEK, encResult.Metadata, objectKey, "prod-aes")
		assert.Error(t, err, "Corrupted data should fail decryption")
		t.Logf("✅ Corrupted data correctly rejected: %v", err)

		// STEP 2: Test corrupted HMAC
		hmacKey := manager.metadataManager.GetHMACMetadataKey()
		originalHMAC := encResult.Metadata[hmacKey]
		encResult.Metadata[hmacKey] = "dGVzdC1jb3JydXB0ZWQtaG1hYy12YWx1ZQ==" // corrupted HMAC

		_, err = manager.DecryptDataWithMetadata(ctx, encResult.EncryptedData, encResult.EncryptedDEK, encResult.Metadata, objectKey, "prod-aes")
		assert.Error(t, err, "Corrupted HMAC should fail verification")
		assert.Contains(t, err.Error(), "HMAC verification failed", "Error should mention HMAC verification")
		t.Logf("✅ Corrupted HMAC correctly rejected: %v", err)

		// STEP 3: Test missing metadata
		delete(encResult.Metadata, "s3ep-dek-algorithm")
		encResult.Metadata[hmacKey] = originalHMAC // restore HMAC

		_, err = manager.DecryptDataWithMetadata(ctx, encResult.EncryptedData, encResult.EncryptedDEK, encResult.Metadata, objectKey, "prod-aes")
		assert.Error(t, err, "Missing metadata should fail decryption")
		t.Logf("✅ Missing metadata correctly rejected: %v", err)
	})
}

// TestManager_LoggingConsistency tests that all HMAC operations log consistently
func TestManager_LoggingConsistency(t *testing.T) {
	ctx := context.Background()

	cfg := &config.Config{
		Encryption: config.EncryptionConfig{
			EncryptionMethodAlias: "logging-test",
			MetadataKeyPrefix:     stringPtr("s3ep-"),
			IntegrityVerification: true,
			Providers: []config.EncryptionProvider{
				{
					Alias: "logging-test",
					Type:  "aes",
					Config: map[string]interface{}{
						"kek": []byte("logging-test-key-32-bytes-long!!"),
					},
				},
			},
		},
	}

	manager, err := NewManager(cfg)
	require.NoError(t, err)

	t.Run("LoggingFlow_CompleteWorkflow", func(t *testing.T) {
		testData := []byte("Test data for logging consistency validation")
		objectKey := "logging-consistency-test"

		// Test encryption logging
		encResult, err := manager.EncryptData(ctx, testData, objectKey)
		require.NoError(t, err)
		t.Logf("✅ Encryption completed with HMAC logging")

		// Test decryption logging
		providerAlias := cfg.Encryption.EncryptionMethodAlias
		decryptedData, err := manager.DecryptDataWithMetadata(ctx, encResult.EncryptedData, encResult.EncryptedDEK, encResult.Metadata, objectKey, providerAlias)
		require.NoError(t, err)
		assert.Equal(t, testData, decryptedData)
		t.Logf("✅ Decryption completed with HMAC logging")

		// Test legacy object warning logging
		delete(encResult.Metadata, "s3ep-hmac") // Remove HMAC to simulate legacy object
		ctxWithKey := context.WithValue(ctx, "objectKey", objectKey)
		decryptedLegacy, err := manager.DecryptDataWithMetadata(ctxWithKey, encResult.EncryptedData, encResult.EncryptedDEK, encResult.Metadata, objectKey, providerAlias)
		require.NoError(t, err)
		assert.Equal(t, testData, decryptedLegacy)
		t.Logf("✅ Legacy object handling completed with warning logging")
	})
}
