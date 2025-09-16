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

// TestHMACPerformanceSummary demonstrates Phase 6 optimization results
func TestHMACPerformanceSummary(t *testing.T) {
	t.Log("🎯 Phase 6: Performance und Optimierung - Results Summary")
	t.Log("=" + string(make([]byte, 60)))

	ctx := context.Background()

	// Test scenarios: Before vs After optimization
	scenarios := []struct {
		name        string
		size        int64
		contentType factory.ContentType
		hmacPolicy  string
		description string
	}{
		{
			name:        "SmallFile_BeforeOptimization",
			size:        1024 * 1024, // 1MB
			contentType: factory.ContentTypeWhole,
			hmacPolicy:  "always", // Old behavior: always HMAC
			description: "1MB AES-GCM with redundant HMAC (before optimization)",
		},
		{
			name:        "SmallFile_AfterOptimization",
			size:        1024 * 1024, // 1MB
			contentType: factory.ContentTypeWhole,
			hmacPolicy:  "auto", // New behavior: smart HMAC
			description: "1MB AES-GCM with smart HMAC policy (after optimization)",
		},
		{
			name:        "LargeFile_StreamingOptimized",
			size:        100 * 1024 * 1024, // 100MB
			contentType: factory.ContentTypeMultipart,
			hmacPolicy:  "auto", // AES-CTR with justified HMAC
			description: "100MB AES-CTR with streaming HMAC (production scenario)",
		},
		{
			name:        "LargeFile_MaxPerformance",
			size:        100 * 1024 * 1024, // 100MB
			contentType: factory.ContentTypeMultipart,
			hmacPolicy:  "never", // Maximum performance
			description: "100MB AES-CTR without HMAC (maximum performance)",
		},
	}

	results := make(map[string]PerformanceResult)

	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			t.Logf("📊 Testing: %s", scenario.description)

			// Create manager with specific policy
			cfg := &config.Config{
				Encryption: config.EncryptionConfig{
					EncryptionMethodAlias: "perf-provider",
					MetadataKeyPrefix:     stringPtr("s3ep-"),
					IntegrityVerification: true,
					HMACPolicy:           scenario.hmacPolicy,
					Providers: []config.EncryptionProvider{
						{
							Alias: "perf-provider",
							Type:  "aes",
							Config: map[string]interface{}{
								"kek": []byte("performance-optimization-key-32!"),
							},
						},
					},
				},
			}

			manager, err := NewManager(cfg)
			require.NoError(t, err)

			// Generate test data
			testData := make([]byte, scenario.size)
			_, err = rand.Read(testData)
			require.NoError(t, err)

			objectKey := fmt.Sprintf("perf-test-%s", scenario.name)

			// Measure encryption
			startTime := time.Now()
			encResult, err := manager.EncryptDataWithContentType(ctx, testData, objectKey, scenario.contentType)
			encryptDuration := time.Since(startTime)
			require.NoError(t, err)

			// Measure decryption
			startTime = time.Now()
			decryptedData, err := manager.DecryptDataWithMetadata(ctx, encResult.EncryptedData, encResult.EncryptedDEK, encResult.Metadata, objectKey, "perf-provider")
			decryptDuration := time.Since(startTime)
			require.NoError(t, err)
			require.Equal(t, testData, decryptedData)

			// Calculate metrics
			dataSizeMB := float64(scenario.size) / (1024 * 1024)
			encryptThroughput := dataSizeMB / encryptDuration.Seconds()
			decryptThroughput := dataSizeMB / decryptDuration.Seconds()

			// Check HMAC presence
			hasHMAC := false
			for key := range encResult.Metadata {
				if key == "s3ep-hmac" {
					hasHMAC = true
					break
				}
			}

			result := PerformanceResult{
				EncryptThroughput: encryptThroughput,
				DecryptThroughput: decryptThroughput,
				HasHMAC:          hasHMAC,
				MetadataFields:   len(encResult.Metadata),
				DataSizeMB:       dataSizeMB,
			}

			results[scenario.name] = result

			t.Logf("   🔄 Encryption: %.1f MB/s", encryptThroughput)
			t.Logf("   🔓 Decryption: %.1f MB/s", decryptThroughput)
			t.Logf("   🔐 HMAC: %v, Metadata: %d fields", hasHMAC, len(encResult.Metadata))
		})
	}

	// Print summary comparison
	t.Log("")
	t.Log("📈 PERFORMANCE OPTIMIZATION SUMMARY")
	t.Log("=" + string(make([]byte, 40)))

	// Small file comparison (AES-GCM optimization)
	before := results["SmallFile_BeforeOptimization"]
	after := results["SmallFile_AfterOptimization"]

	encryptImprovement := ((after.EncryptThroughput - before.EncryptThroughput) / before.EncryptThroughput) * 100
	decryptImprovement := ((after.DecryptThroughput - before.DecryptThroughput) / before.DecryptThroughput) * 100

	t.Logf("🎯 Small Files (1MB AES-GCM) Optimization:")
	t.Logf("   Encryption: %.1f → %.1f MB/s (%.1f%% improvement)",
		before.EncryptThroughput, after.EncryptThroughput, encryptImprovement)
	t.Logf("   Decryption: %.1f → %.1f MB/s (%.1f%% improvement)",
		before.DecryptThroughput, after.DecryptThroughput, decryptImprovement)
	t.Logf("   HMAC Redundancy: %v → %v (eliminated authenticated encryption overlap)",
		before.HasHMAC, after.HasHMAC)

	// Large file performance
	streaming := results["LargeFile_StreamingOptimized"]
	maxPerf := results["LargeFile_MaxPerformance"]

	t.Logf("")
	t.Logf("🚀 Large Files (100MB AES-CTR) Performance:")
	t.Logf("   With HMAC (integrity): %.1f MB/s encrypt, %.1f MB/s decrypt",
		streaming.EncryptThroughput, streaming.DecryptThroughput)
	t.Logf("   Without HMAC (max perf): %.1f MB/s encrypt, %.1f MB/s decrypt",
		maxPerf.EncryptThroughput, maxPerf.DecryptThroughput)

	hmacOverhead := ((maxPerf.EncryptThroughput - streaming.EncryptThroughput) / streaming.EncryptThroughput) * 100
	t.Logf("   HMAC Overhead: %.1f%% (justified for integrity verification)", hmacOverhead)

	// Validation checks
	t.Log("")
	t.Log("✅ VALIDATION CHECKS:")

	require.False(t, after.HasHMAC, "Auto policy should skip HMAC for AES-GCM")
	require.True(t, streaming.HasHMAC, "Auto policy should use HMAC for AES-CTR")
	require.False(t, maxPerf.HasHMAC, "Never policy should skip HMAC")

	require.Greater(t, after.EncryptThroughput, before.EncryptThroughput, "Optimization should improve encryption performance")
	require.Greater(t, streaming.EncryptThroughput, 1000.0, "AES-CTR should achieve >1 GB/s")

	t.Logf("   ✅ Smart HMAC policy working correctly")
	t.Logf("   ✅ Performance improvements validated")
	t.Logf("   ✅ Large file streaming >1 GB/s achieved")

	t.Log("")
	t.Log("🎉 Phase 6 Performance Optimization: COMPLETED SUCCESSFULLY")
}

type PerformanceResult struct {
	EncryptThroughput float64
	DecryptThroughput float64
	HasHMAC          bool
	MetadataFields   int
	DataSizeMB       float64
}
