package encryption

import (
	"context"
	"crypto/rand"
	"fmt"
	"testing"
	"time"

	"github.com/guided-traffic/s3-encryption-proxy/internal/config"
	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption/factory"
	"github.com/stretchr/testify/require"
)

// TestHMACPolicyPerformance tests the performance impact of different HMAC policies
func TestHMACPolicyPerformance(t *testing.T) {
	ctx := context.Background()

	// Test scenarios comparing HMAC policies
	scenarios := map[string]struct {
		Size        int64
		ContentType factory.ContentType
		Description string
		HMACPolicy  string
	}{
		"SmallObject_Auto_Policy": {
			Size:        1024 * 1024, // 1MB
			ContentType: factory.ContentTypeWhole, // AES-GCM
			Description: "1MB AES-GCM with auto policy (should skip HMAC)",
			HMACPolicy:  "auto",
		},
		"SmallObject_Always_Policy": {
			Size:        1024 * 1024, // 1MB
			ContentType: factory.ContentTypeWhole, // AES-GCM
			Description: "1MB AES-GCM with always policy (forced HMAC)",
			HMACPolicy:  "always",
		},
		"LargeObject_Auto_Policy": {
			Size:        50 * 1024 * 1024, // 50MB
			ContentType: factory.ContentTypeMultipart, // AES-CTR
			Description: "50MB AES-CTR with auto policy (should use HMAC)",
			HMACPolicy:  "auto",
		},
		"LargeObject_Never_Policy": {
			Size:        50 * 1024 * 1024, // 50MB
			ContentType: factory.ContentTypeMultipart, // AES-CTR
			Description: "50MB AES-CTR with never policy (no HMAC)",
			HMACPolicy:  "never",
		},
	}

	for name, scenario := range scenarios {
		t.Run(name, func(t *testing.T) {
			t.Logf("🧪 Performance Test: %s", scenario.Description)

			// Create test configuration with specific HMAC policy
			cfg := &config.Config{
				Encryption: config.EncryptionConfig{
					EncryptionMethodAlias: "test-provider",
					MetadataKeyPrefix:     stringPtr("s3ep-"),
					IntegrityVerification: true, // Enable integrity verification
					HMACPolicy:           scenario.HMACPolicy,
					Providers: []config.EncryptionProvider{
						{
							Alias: "test-provider",
							Type:  "aes",
							Config: map[string]interface{}{
								"kek": []byte("test-policy-key-32-bytes-long!!!"),
							},
						},
					},
				},
			}

			manager, err := NewManager(cfg)
			require.NoError(t, err)

			// Generate test data
			testData := make([]byte, scenario.Size)
			_, err = rand.Read(testData)
			require.NoError(t, err)

			objectKey := fmt.Sprintf("policy-test-%s", name)

			// Measure encryption performance
			startTime := time.Now()
			encResult, err := manager.EncryptDataWithContentType(ctx, testData, objectKey, scenario.ContentType)
			encryptDuration := time.Since(startTime)
			require.NoError(t, err)
			require.NotNil(t, encResult)

			// Measure decryption performance
			startTime = time.Now()
			decryptedData, err := manager.DecryptDataWithMetadata(ctx, encResult.EncryptedData, encResult.EncryptedDEK, encResult.Metadata, objectKey, "test-provider")
			decryptDuration := time.Since(startTime)
			require.NoError(t, err)
			require.Equal(t, testData, decryptedData)

			// Calculate performance metrics
			dataSizeMB := float64(scenario.Size) / (1024 * 1024)
			encryptThroughput := dataSizeMB / encryptDuration.Seconds()
			decryptThroughput := dataSizeMB / decryptDuration.Seconds()

			// Check for HMAC presence in metadata
			hasHMAC := false
			for key := range encResult.Metadata {
				if key == "s3ep-hmac" {
					hasHMAC = true
					break
				}
			}

			// Verify expected HMAC behavior based on policy and content type
			expectedHMAC := shouldHaveHMAC(scenario.ContentType, scenario.HMACPolicy)
			require.Equal(t, expectedHMAC, hasHMAC,
				"HMAC presence mismatch for policy %s with content type %s",
				scenario.HMACPolicy, scenario.ContentType)

			// Log detailed performance results
			t.Logf("📊 Performance Results for %s (%.1f MB):", name, dataSizeMB)
			t.Logf("   🔄 Encryption: %.2f MB/s (%.3fs)", encryptThroughput, encryptDuration.Seconds())
			t.Logf("   🔓 Decryption: %.2f MB/s (%.3fs)", decryptThroughput, decryptDuration.Seconds())
			t.Logf("   🔐 HMAC Present: %v (expected: %v)", hasHMAC, expectedHMAC)
			t.Logf("   📏 Data Size: original %d bytes, encrypted %d bytes", len(testData), len(encResult.EncryptedData))
			t.Logf("   🏷️  Metadata Fields: %d", len(encResult.Metadata))

			// Performance assertions for AES-GCM with auto policy (should be fast without HMAC)
			if scenario.ContentType == factory.ContentTypeWhole && scenario.HMACPolicy == "auto" {
				require.False(t, hasHMAC, "Auto policy should skip HMAC for AES-GCM")
				require.Greater(t, encryptThroughput, 500.0, "AES-GCM without HMAC should be > 500 MB/s")
			}

			// Performance assertions for AES-CTR with auto policy (should use HMAC)
			if scenario.ContentType == factory.ContentTypeMultipart && scenario.HMACPolicy == "auto" {
				require.True(t, hasHMAC, "Auto policy should use HMAC for AES-CTR")
			}

			// Performance comparison: always vs auto for AES-GCM should show significant difference
			if scenario.ContentType == factory.ContentTypeWhole {
				if scenario.HMACPolicy == "auto" {
					t.Logf("   ✅ Auto policy optimized: no HMAC overhead for authenticated encryption")
				} else if scenario.HMACPolicy == "always" {
					t.Logf("   ⚠️  Always policy: HMAC adds overhead to authenticated encryption")
				}
			}
		})
	}
}

// shouldHaveHMAC determines expected HMAC behavior based on content type and policy
func shouldHaveHMAC(contentType factory.ContentType, policy string) bool {
	switch policy {
	case "always":
		return true
	case "never":
		return false
	case "auto":
		// Auto policy: skip for AES-GCM (ContentTypeWhole), use for AES-CTR (ContentTypeMultipart)
		return contentType == factory.ContentTypeMultipart
	default:
		return true // Default to always
	}
}

// BenchmarkHMACPolicyComparison benchmarks different HMAC policies
func BenchmarkHMACPolicyComparison(b *testing.B) {
	policies := []string{"auto", "always", "never"}
	dataSize := int64(1024 * 1024) // 1MB for quick benchmark

	for _, policy := range policies {
		b.Run(fmt.Sprintf("Policy_%s", policy), func(b *testing.B) {
			benchmarkHMACPolicy(b, dataSize, policy)
		})
	}
}

func benchmarkHMACPolicy(b *testing.B, dataSize int64, hmacPolicy string) {
	ctx := context.Background()

	// Create test configuration
	cfg := &config.Config{
		Encryption: config.EncryptionConfig{
			EncryptionMethodAlias: "bench-provider",
			MetadataKeyPrefix:     stringPtr("s3ep-"),
			IntegrityVerification: true,
			HMACPolicy:           hmacPolicy,
			Providers: []config.EncryptionProvider{
				{
					Alias: "bench-provider",
					Type:  "aes",
					Config: map[string]interface{}{
						"kek": []byte("benchmark-key-32-bytes-long!!!"),
					},
				},
			},
		},
	}

	manager, err := NewManager(cfg)
	require.NoError(b, err)

	// Generate test data
	testData := make([]byte, dataSize)
	_, err = rand.Read(testData)
	require.NoError(b, err)

	objectKey := "benchmark-object"

	// Reset timer and run benchmark
	b.ResetTimer()
	b.SetBytes(dataSize)

	for i := 0; i < b.N; i++ {
		// Encrypt with AES-GCM (ContentTypeWhole)
		encResult, err := manager.EncryptDataWithContentType(ctx, testData, objectKey, factory.ContentTypeWhole)
		require.NoError(b, err)

		// Decrypt
		_, err = manager.DecryptDataWithMetadata(ctx, encResult.EncryptedData, encResult.EncryptedDEK, encResult.Metadata, objectKey, "bench-provider")
		require.NoError(b, err)
	}
}
