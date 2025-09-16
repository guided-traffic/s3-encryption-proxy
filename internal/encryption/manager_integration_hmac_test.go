package encryption

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/guided-traffic/s3-encryption-proxy/internal/config"
	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption/factory"
)

// TestManager_HMACIntegration_EndToEnd tests complete HMAC workflow: Config->Manager->Factory->Provider
func TestManager_HMACIntegration_EndToEnd(t *testing.T) {
	ctx := context.Background()

	// Test scenarios: HMAC enabled vs disabled, different content types, legacy objects
	testScenarios := []struct {
		name                  string
		integrityVerification bool
		contentType           factory.ContentType
		dataSize              int
		expectHMAC            bool
		description           string
	}{
		{
			name:                  "HMACEnabled_SmallObject_AES-GCM",
			integrityVerification: true,
			contentType:           factory.ContentTypeWhole,
			dataSize:              1024, // 1KB
			expectHMAC:            true,
			description:           "Small object with HMAC enabled should use AES-GCM with HMAC",
		},
		{
			name:                  "HMACEnabled_LargeObject_AES-CTR",
			integrityVerification: true,
			contentType:           factory.ContentTypeMultipart,
			dataSize:              50 * 1024 * 1024, // 50MB
			expectHMAC:            true,
			description:           "Large object with HMAC enabled should use AES-CTR with HMAC",
		},
		{
			name:                  "HMACDisabled_SmallObject",
			integrityVerification: false,
			contentType:           factory.ContentTypeWhole,
			dataSize:              1024,
			expectHMAC:            false,
			description:           "HMAC disabled should not include HMAC metadata",
		},
		{
			name:                  "HMACDisabled_LargeObject",
			integrityVerification: false,
			contentType:           factory.ContentTypeMultipart,
			dataSize:              10 * 1024 * 1024, // 10MB
			expectHMAC:            false,
			description:           "HMAC disabled for large objects should not include HMAC",
		},
	}

	for _, scenario := range testScenarios {
		t.Run(scenario.name, func(t *testing.T) {
			t.Logf("🧪 Testing: %s", scenario.description)

			// STEP 1: Create config with specified HMAC setting
			cfg := createTestConfigWithHMAC(t, scenario.integrityVerification)

			// STEP 2: Create manager with config
			manager, err := NewManager(cfg)
			require.NoError(t, err, "Failed to create manager")

			// STEP 3: Create test data
			testData := make([]byte, scenario.dataSize)
			for i := range testData {
				testData[i] = byte(i % 256)
			}
			objectKey := fmt.Sprintf("test-object-%s", scenario.name)

			// STEP 4: Encrypt data
			encResult, err := manager.EncryptDataWithContentType(ctx, testData, objectKey, scenario.contentType)
			require.NoError(t, err, "Encryption failed")
			require.NotNil(t, encResult, "Encryption result is nil")

			// STEP 5: Verify HMAC presence in metadata
			hmacKey := manager.metadataManager.GetHMACMetadataKey()
			_, hasHMAC := encResult.Metadata[hmacKey]

			if scenario.expectHMAC {
				assert.True(t, hasHMAC, "HMAC metadata should be present when integrity verification is enabled")
				t.Logf("✅ HMAC metadata found: %s=%s...", hmacKey, encResult.Metadata[hmacKey][:8])
			} else {
				assert.False(t, hasHMAC, "HMAC metadata should not be present when integrity verification is disabled")
				t.Logf("✅ No HMAC metadata found (as expected)")
			}

			// STEP 6: Verify other encryption metadata
			assert.NotEmpty(t, encResult.EncryptedData, "Encrypted data should not be empty")
			assert.NotEmpty(t, encResult.EncryptedDEK, "Encrypted DEK should not be empty")
			assert.NotEmpty(t, encResult.Metadata, "Metadata should not be empty")

			// Check for required encryption metadata
			assert.Contains(t, encResult.Metadata, "s3ep-dek-algorithm", "DEK algorithm should be present")
			assert.Contains(t, encResult.Metadata, "s3ep-encrypted-dek", "Encrypted DEK should be present")
			assert.Contains(t, encResult.Metadata, "s3ep-kek-fingerprint", "KEK fingerprint should be present")

			// STEP 7: Decrypt data and verify integrity
			providerAlias := cfg.Encryption.EncryptionMethodAlias
			decryptedData, err := manager.DecryptDataWithMetadata(ctx, encResult.EncryptedData, encResult.EncryptedDEK, encResult.Metadata, objectKey, providerAlias)
			require.NoError(t, err, "Decryption failed")

			// STEP 8: Verify data integrity
			assert.Equal(t, testData, decryptedData, "Decrypted data should match original")
			t.Logf("✅ Data integrity verified: %d bytes", len(decryptedData))

			// STEP 9: Log performance metrics
			encryptionRatio := float64(len(encResult.EncryptedData)) / float64(len(testData))
			t.Logf("📊 Performance: Original=%d bytes, Encrypted=%d bytes, Ratio=%.3f",
				len(testData), len(encResult.EncryptedData), encryptionRatio)
		})
	}
}

// TestManager_HMACIntegration_BackwardCompatibility tests legacy object handling
func TestManager_HMACIntegration_BackwardCompatibility(t *testing.T) {
	ctx := context.Background()

	t.Run("LegacyObject_WithoutHMAC_ShouldDecryptWithWarning", func(t *testing.T) {
		// STEP 1: Create manager with HMAC enabled
		cfg := createTestConfigWithHMAC(t, true)
		manager, err := NewManager(cfg)
		require.NoError(t, err)

		// STEP 2: Create legacy object (without HMAC)
		testData := []byte("Legacy test data without HMAC metadata")
		objectKey := "legacy-object-test"

		// Encrypt with HMAC disabled to simulate legacy object
		cfg.Encryption.IntegrityVerification = false
		legacyManager, err := NewManager(cfg)
		require.NoError(t, err)

		encResult, err := legacyManager.EncryptData(ctx, testData, objectKey)
		require.NoError(t, err)

		// Verify no HMAC in metadata
		hmacKey := manager.metadataManager.GetHMACMetadataKey()
		_, hasHMAC := encResult.Metadata[hmacKey]
		assert.False(t, hasHMAC, "Legacy object should not have HMAC metadata")

		// STEP 3: Try to decrypt with HMAC-enabled manager (should succeed with warning)
		cfg.Encryption.IntegrityVerification = true // Re-enable for decryption
		hmacEnabledManager, err := NewManager(cfg)
		require.NoError(t, err)

		providerAlias := cfg.Encryption.EncryptionMethodAlias
		decryptedData, err := hmacEnabledManager.DecryptDataWithMetadata(ctx, encResult.EncryptedData, encResult.EncryptedDEK, encResult.Metadata, objectKey, providerAlias)
		require.NoError(t, err, "Legacy object decryption should succeed despite missing HMAC")

		assert.Equal(t, testData, decryptedData, "Legacy object data should be correctly decrypted")
		t.Logf("✅ Legacy object decrypted successfully: %d bytes", len(decryptedData))
	})

	t.Run("CorruptedHMAC_ShouldFailVerification", func(t *testing.T) {
		// STEP 1: Create manager with HMAC enabled
		cfg := createTestConfigWithHMAC(t, true)
		manager, err := NewManager(cfg)
		require.NoError(t, err)

		// STEP 2: Encrypt data with HMAC
		testData := []byte("Test data for HMAC corruption test")
		objectKey := "corrupted-hmac-test"

		encResult, err := manager.EncryptData(ctx, testData, objectKey)
		require.NoError(t, err)

		// STEP 3: Corrupt HMAC in metadata
		hmacKey := manager.metadataManager.GetHMACMetadataKey()
		originalHMAC := encResult.Metadata[hmacKey]
		encResult.Metadata[hmacKey] = "dGVzdC1jb3JydXB0ZWQtaG1hYy12YWx1ZQ==" // base64 encoded "test-corrupted-hmac-value"

		t.Logf("🔧 Corrupted HMAC: %s -> %s", originalHMAC[:16]+"...", encResult.Metadata[hmacKey][:16]+"...")

		// STEP 4: Try to decrypt (should fail HMAC verification)
		providerAlias := cfg.Encryption.EncryptionMethodAlias
		_, err = manager.DecryptDataWithMetadata(ctx, encResult.EncryptedData, encResult.EncryptedDEK, encResult.Metadata, objectKey, providerAlias)
		require.Error(t, err, "Decryption should fail with corrupted HMAC")
		assert.Contains(t, err.Error(), "HMAC verification failed", "Error should mention HMAC verification failure")

		t.Logf("✅ Corrupted HMAC correctly rejected: %v", err)
	})
}

// TestManager_HMACIntegration_PerformanceImpact measures HMAC performance overhead
func TestManager_HMACIntegration_PerformanceImpact(t *testing.T) {
	ctx := context.Background()

	testSizes := []struct {
		name string
		size int
	}{
		{"1KB", 1024},
		{"100KB", 100 * 1024},
		{"1MB", 1024 * 1024},
		{"10MB", 10 * 1024 * 1024},
	}

	for _, testSize := range testSizes {
		t.Run(fmt.Sprintf("PerformanceImpact_%s", testSize.name), func(t *testing.T) {
			// Create test data
			testData := make([]byte, testSize.size)
			for i := range testData {
				testData[i] = byte(i % 256)
			}
			objectKey := fmt.Sprintf("perf-test-%s", testSize.name)

			// Test without HMAC
			cfgNoHMAC := createTestConfigWithHMAC(t, false)
			managerNoHMAC, err := NewManager(cfgNoHMAC)
			require.NoError(t, err)

			// Test with HMAC
			cfgWithHMAC := createTestConfigWithHMAC(t, true)
			managerWithHMAC, err := NewManager(cfgWithHMAC)
			require.NoError(t, err)

			// Benchmark encryption without HMAC
			encResultNoHMAC, err := managerNoHMAC.EncryptData(ctx, testData, objectKey)
			require.NoError(t, err)

			// Benchmark encryption with HMAC
			encResultWithHMAC, err := managerWithHMAC.EncryptData(ctx, testData, objectKey)
			require.NoError(t, err)

			// Calculate overhead
			sizeNoHMAC := len(encResultNoHMAC.EncryptedData)
			sizeWithHMAC := len(encResultWithHMAC.EncryptedData)
			metadataCountNoHMAC := len(encResultNoHMAC.Metadata)
			metadataCountWithHMAC := len(encResultWithHMAC.Metadata)

			t.Logf("📊 Performance Impact for %s:", testSize.name)
			t.Logf("   Data Size: %d bytes", testSize.size)
			t.Logf("   Encrypted Size (No HMAC): %d bytes", sizeNoHMAC)
			t.Logf("   Encrypted Size (With HMAC): %d bytes", sizeWithHMAC)
			t.Logf("   Metadata Count (No HMAC): %d", metadataCountNoHMAC)
			t.Logf("   Metadata Count (With HMAC): %d", metadataCountWithHMAC)

			// HMAC should add minimal overhead to encrypted data (just metadata)
			assert.Equal(t, sizeNoHMAC, sizeWithHMAC, "HMAC should not increase encrypted data size")
			assert.Equal(t, metadataCountWithHMAC, metadataCountNoHMAC+1, "HMAC should add exactly 1 metadata field")

			// Verify decryption works for both
			providerAlias := cfgNoHMAC.Encryption.EncryptionMethodAlias

			decryptedNoHMAC, err := managerNoHMAC.DecryptDataWithMetadata(ctx, encResultNoHMAC.EncryptedData, encResultNoHMAC.EncryptedDEK, encResultNoHMAC.Metadata, objectKey, providerAlias)
			require.NoError(t, err)
			assert.Equal(t, testData, decryptedNoHMAC)

			decryptedWithHMAC, err := managerWithHMAC.DecryptDataWithMetadata(ctx, encResultWithHMAC.EncryptedData, encResultWithHMAC.EncryptedDEK, encResultWithHMAC.Metadata, objectKey, providerAlias)
			require.NoError(t, err)
			assert.Equal(t, testData, decryptedWithHMAC)

			t.Logf("✅ Both encryption modes work correctly")
		})
	}
}

// Helper function to create test config with HMAC setting
func createTestConfigWithHMAC(t *testing.T, integrityVerification bool) *config.Config {
	metadataPrefix := "s3ep-"
	return &config.Config{
		Encryption: config.EncryptionConfig{
			EncryptionMethodAlias: "test-provider",
			MetadataKeyPrefix:     &metadataPrefix,
			IntegrityVerification: integrityVerification,
			Providers: []config.EncryptionProvider{
				{
					Alias: "test-provider",
					Type:  "aes",
					Config: map[string]interface{}{
						"kek": []byte("test-key-32-bytes-long-for-aes!!"), // 32 bytes for AES-256
					},
				},
			},
		},
	}
}
