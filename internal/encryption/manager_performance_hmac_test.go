package encryption

import (
	"context"
	"crypto/rand"
	"fmt"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/guided-traffic/s3-encryption-proxy/internal/config"
	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption/factory"
)

// Performance benchmark for streaming HMAC operations
func BenchmarkHMACStreamingPerformance(b *testing.B) {
	// Test different data sizes from 1MB to 100MB
	testSizes := []struct {
		name string
		size int64
	}{
		{"1MB", 1024 * 1024},
		{"5MB", 5 * 1024 * 1024},
		{"10MB", 10 * 1024 * 1024},
		{"25MB", 25 * 1024 * 1024},
		{"50MB", 50 * 1024 * 1024},
		{"100MB", 100 * 1024 * 1024},
	}

	for _, testSize := range testSizes {
		b.Run(fmt.Sprintf("WithHMAC_%s", testSize.name), func(b *testing.B) {
			benchmarkEncryptionPerformance(b, testSize.size, true)
		})

		b.Run(fmt.Sprintf("WithoutHMAC_%s", testSize.name), func(b *testing.B) {
			benchmarkEncryptionPerformance(b, testSize.size, false)
		})
	}
}

func benchmarkEncryptionPerformance(b *testing.B, dataSize int64, withHMAC bool) {
	ctx := context.Background()

	// Create test configuration
	cfg := &config.Config{
		Encryption: config.EncryptionConfig{
			EncryptionMethodAlias: "benchmark-provider",
			MetadataKeyPrefix:     stringPtr("s3ep-"),
			IntegrityVerification: withHMAC,
			Providers: []config.EncryptionProvider{
				{
					Alias: "benchmark-provider",
					Type:  "aes",
					Config: map[string]interface{}{
						"kek": []byte("benchmark-test-key-32-bytes!!!"),
					},
				},
			},
		},
	}

	manager, err := NewManager(cfg)
	require.NoError(b, err)

	// Generate test data once
	testData := make([]byte, dataSize)
	_, err = rand.Read(testData)
	require.NoError(b, err)

	objectKey := fmt.Sprintf("benchmark-object-%d", dataSize)

	// Reset timer and run benchmark
	b.ResetTimer()
	b.SetBytes(dataSize)

	// Memory stats for analysis
	var m1, m2 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m1)

	for i := 0; i < b.N; i++ {
		// Determine content type based on size (mimics real-world usage)
		contentType := factory.ContentTypeWhole
		if dataSize > 50*1024*1024 { // > 50MB use streaming
			contentType = factory.ContentTypeMultipart
		}

		// Encrypt data
		encResult, err := manager.EncryptDataWithContentType(ctx, testData, objectKey, contentType)
		require.NoError(b, err)

		// Verify decryption to ensure correctness
		providerAlias := cfg.Encryption.EncryptionMethodAlias
		decryptedData, err := manager.DecryptDataWithMetadata(ctx, encResult.EncryptedData, encResult.EncryptedDEK, encResult.Metadata, objectKey, providerAlias)
		require.NoError(b, err)
		require.Equal(b, len(testData), len(decryptedData))
	}

	// Measure memory usage
	runtime.GC()
	runtime.ReadMemStats(&m2)

	// Report additional metrics
	bytesPerSec := float64(dataSize*int64(b.N)) / b.Elapsed().Seconds()
	mbPerSec := bytesPerSec / (1024 * 1024)

	b.ReportMetric(mbPerSec, "MB/s")
	b.ReportMetric(float64(m2.TotalAlloc-m1.TotalAlloc)/float64(b.N), "alloc-bytes/op")
	b.ReportMetric(float64(m2.Mallocs-m1.Mallocs)/float64(b.N), "allocs/op")
}

// TestHMACPerformanceComparison compares HMAC vs non-HMAC performance
func TestHMACPerformanceComparison(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping performance comparison in short mode")
	}

	ctx := context.Background()

	// Test different scenarios
	testScenarios := []struct {
		name        string
		size        int64
		contentType factory.ContentType
		description string
	}{
		{"SmallObject_AES-GCM", 1024 * 1024, factory.ContentTypeWhole, "1MB object using AES-GCM"},
		{"MediumObject_AES-GCM", 10 * 1024 * 1024, factory.ContentTypeWhole, "10MB object using AES-GCM"},
		{"LargeObject_AES-CTR", 50 * 1024 * 1024, factory.ContentTypeMultipart, "50MB object using AES-CTR streaming"},
		{"VeryLargeObject_AES-CTR", 100 * 1024 * 1024, factory.ContentTypeMultipart, "100MB object using AES-CTR streaming"},
	}

	for _, scenario := range testScenarios {
		t.Run(scenario.name, func(t *testing.T) {
			t.Logf("🧪 Performance Comparison: %s", scenario.description)

			// Generate test data
			testData := make([]byte, scenario.size)
			for i := range testData {
				testData[i] = byte(i % 256)
			}
			objectKey := fmt.Sprintf("perf-test-%s", scenario.name)

			// Test WITHOUT HMAC
			cfgNoHMAC := createPerformanceTestConfig("perf-no-hmac", false)
			managerNoHMAC, err := NewManager(cfgNoHMAC)
			require.NoError(t, err)

			startTime := time.Now()
			var m1, m2 runtime.MemStats
			runtime.GC()
			runtime.ReadMemStats(&m1)

			encResultNoHMAC, err := managerNoHMAC.EncryptDataWithContentType(ctx, testData, objectKey, scenario.contentType)
			require.NoError(t, err)

			encryptTimeNoHMAC := time.Since(startTime)
			runtime.ReadMemStats(&m2)
			memoryNoHMAC := m2.TotalAlloc - m1.TotalAlloc

			// Verify decryption
			startTime = time.Now()
			decryptedNoHMAC, err := managerNoHMAC.DecryptDataWithMetadata(ctx, encResultNoHMAC.EncryptedData, encResultNoHMAC.EncryptedDEK, encResultNoHMAC.Metadata, objectKey, "perf-no-hmac")
			require.NoError(t, err)
			decryptTimeNoHMAC := time.Since(startTime)
			assert.Equal(t, len(testData), len(decryptedNoHMAC))

			// Test WITH HMAC
			cfgWithHMAC := createPerformanceTestConfig("perf-with-hmac", true)
			managerWithHMAC, err := NewManager(cfgWithHMAC)
			require.NoError(t, err)

			startTime = time.Now()
			runtime.GC()
			runtime.ReadMemStats(&m1)

			encResultWithHMAC, err := managerWithHMAC.EncryptDataWithContentType(ctx, testData, objectKey, scenario.contentType)
			require.NoError(t, err)

			encryptTimeWithHMAC := time.Since(startTime)
			runtime.ReadMemStats(&m2)
			memoryWithHMAC := m2.TotalAlloc - m1.TotalAlloc

			// Verify decryption with HMAC
			startTime = time.Now()
			decryptedWithHMAC, err := managerWithHMAC.DecryptDataWithMetadata(ctx, encResultWithHMAC.EncryptedData, encResultWithHMAC.EncryptedDEK, encResultWithHMAC.Metadata, objectKey, "perf-with-hmac")
			require.NoError(t, err)
			decryptTimeWithHMAC := time.Since(startTime)
			assert.Equal(t, len(testData), len(decryptedWithHMAC))

			// Calculate performance metrics
			encryptThroughputNoHMAC := float64(scenario.size) / encryptTimeNoHMAC.Seconds() / (1024 * 1024) // MB/s
			encryptThroughputWithHMAC := float64(scenario.size) / encryptTimeWithHMAC.Seconds() / (1024 * 1024)
			decryptThroughputNoHMAC := float64(scenario.size) / decryptTimeNoHMAC.Seconds() / (1024 * 1024)
			decryptThroughputWithHMAC := float64(scenario.size) / decryptTimeWithHMAC.Seconds() / (1024 * 1024)

			// Calculate overhead
			encryptOverhead := (encryptTimeWithHMAC.Seconds() - encryptTimeNoHMAC.Seconds()) / encryptTimeNoHMAC.Seconds() * 100
			decryptOverhead := (decryptTimeWithHMAC.Seconds() - decryptTimeNoHMAC.Seconds()) / decryptTimeNoHMAC.Seconds() * 100
			memoryOverhead := (float64(memoryWithHMAC) - float64(memoryNoHMAC)) / float64(memoryNoHMAC) * 100

			// Verify HMAC metadata presence
			hmacKey := managerWithHMAC.metadataManager.GetHMACMetadataKey()
			_, hasHMAC := encResultWithHMAC.Metadata[hmacKey]
			assert.True(t, hasHMAC, "HMAC metadata should be present")
			_, noHMAC := encResultNoHMAC.Metadata[hmacKey]
			assert.False(t, noHMAC, "HMAC metadata should not be present when disabled")

			// Log detailed performance results
			t.Logf("📊 Performance Results for %s (%.1f MB):", scenario.name, float64(scenario.size)/(1024*1024))
			t.Logf("   🔄 Encryption Performance:")
			t.Logf("      Without HMAC: %.2f MB/s (%.3fs)", encryptThroughputNoHMAC, encryptTimeNoHMAC.Seconds())
			t.Logf("      With HMAC:    %.2f MB/s (%.3fs)", encryptThroughputWithHMAC, encryptTimeWithHMAC.Seconds())
			t.Logf("      HMAC Overhead: %.2f%%", encryptOverhead)
			t.Logf("   🔓 Decryption Performance:")
			t.Logf("      Without HMAC: %.2f MB/s (%.3fs)", decryptThroughputNoHMAC, decryptTimeNoHMAC.Seconds())
			t.Logf("      With HMAC:    %.2f MB/s (%.3fs)", decryptThroughputWithHMAC, decryptTimeWithHMAC.Seconds())
			t.Logf("      HMAC Overhead: %.2f%%", decryptOverhead)
			t.Logf("   💾 Memory Usage:")
			t.Logf("      Without HMAC: %d bytes", memoryNoHMAC)
			t.Logf("      With HMAC:    %d bytes", memoryWithHMAC)
			t.Logf("      Memory Overhead: %.2f%%", memoryOverhead)
			t.Logf("   📏 Data Sizes:")
			t.Logf("      Original:     %d bytes", scenario.size)
			t.Logf("      Encrypted:    %d bytes (%.3fx)", len(encResultWithHMAC.EncryptedData), float64(len(encResultWithHMAC.EncryptedData))/float64(scenario.size))
			t.Logf("   🔐 Security:")
			t.Logf("      HMAC Enabled: %v", hasHMAC)
			t.Logf("      Metadata Fields: %d", len(encResultWithHMAC.Metadata))

			// Performance assertions (should not have significant overhead)
			assert.Less(t, encryptOverhead, 15.0, "Encryption overhead should be less than 15%")
			assert.Less(t, decryptOverhead, 15.0, "Decryption overhead should be less than 15%")
			assert.Less(t, memoryOverhead, 50.0, "Memory overhead should be less than 50%")

			// Throughput assertions (should maintain good performance)
			assert.Greater(t, encryptThroughputWithHMAC, 10.0, "Encryption with HMAC should be at least 10 MB/s")
			assert.Greater(t, decryptThroughputWithHMAC, 10.0, "Decryption with HMAC should be at least 10 MB/s")
		})
	}
}

// TestStreamingHMACMemoryUsage tests memory efficiency of streaming HMAC
func TestStreamingHMACMemoryUsage(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping memory usage test in short mode")
	}

	ctx := context.Background()

	// Test with very large data to verify streaming behavior
	dataSize := int64(200 * 1024 * 1024) // 200MB
	t.Logf("🧪 Testing memory usage for %d MB streaming HMAC", dataSize/(1024*1024))

	cfg := createPerformanceTestConfig("memory-test", true)
	manager, err := NewManager(cfg)
	require.NoError(t, err)

	// Generate large test data
	testData := make([]byte, dataSize)
	for i := range testData {
		testData[i] = byte(i % 256)
	}

	objectKey := "memory-usage-test"

	// Measure memory before operation
	var m1, m2, m3 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m1)

	// Encrypt with streaming (should use constant memory)
	encResult, err := manager.EncryptDataWithContentType(ctx, testData, objectKey, factory.ContentTypeMultipart)
	require.NoError(t, err)

	runtime.GC()
	runtime.ReadMemStats(&m2)

	// Decrypt (should also use constant memory)
	decryptedData, err := manager.DecryptDataWithMetadata(ctx, encResult.EncryptedData, encResult.EncryptedDEK, encResult.Metadata, objectKey, "memory-test")
	require.NoError(t, err)

	runtime.GC()
	runtime.ReadMemStats(&m3)

	// Verify correctness
	assert.Equal(t, len(testData), len(decryptedData))

	// Calculate memory usage
	encryptMemory := m2.TotalAlloc - m1.TotalAlloc
	decryptMemory := m3.TotalAlloc - m2.TotalAlloc
	totalMemory := m3.TotalAlloc - m1.TotalAlloc

	// Memory efficiency ratios
	encryptRatio := float64(encryptMemory) / float64(dataSize)
	decryptRatio := float64(decryptMemory) / float64(dataSize)
	totalRatio := float64(totalMemory) / float64(dataSize)

	t.Logf("📊 Memory Usage Analysis for %d MB:", dataSize/(1024*1024))
	t.Logf("   Original Data: %d bytes (%.1f MB)", dataSize, float64(dataSize)/(1024*1024))
	t.Logf("   Encrypt Memory: %d bytes (%.2f MB, %.3fx ratio)", encryptMemory, float64(encryptMemory)/(1024*1024), encryptRatio)
	t.Logf("   Decrypt Memory: %d bytes (%.2f MB, %.3fx ratio)", decryptMemory, float64(decryptMemory)/(1024*1024), decryptRatio)
	t.Logf("   Total Memory: %d bytes (%.2f MB, %.3fx ratio)", totalMemory, float64(totalMemory)/(1024*1024), totalRatio)

	// Memory efficiency assertions - streaming should use much less memory than data size
	assert.Less(t, encryptRatio, 2.0, "Encryption memory should be less than 2x data size")
	assert.Less(t, decryptRatio, 2.0, "Decryption memory should be less than 2x data size")
	assert.Less(t, totalRatio, 3.0, "Total memory should be less than 3x data size")

	// For truly streaming operations, memory should be much smaller
	if dataSize > 100*1024*1024 { // For very large files
		assert.Less(t, encryptRatio, 0.1, "Large file encryption should use <10% of data size in memory")
		assert.Less(t, decryptRatio, 0.1, "Large file decryption should use <10% of data size in memory")
	}

	t.Logf("✅ Memory efficiency validated - streaming HMAC uses %.1f%% of data size", totalRatio*100)
}

// Helper function to create performance test configuration
func createPerformanceTestConfig(alias string, integrityVerification bool) *config.Config {
	metadataPrefix := "s3ep-"
	return &config.Config{
		Encryption: config.EncryptionConfig{
			EncryptionMethodAlias: alias,
			MetadataKeyPrefix:     &metadataPrefix,
			IntegrityVerification: integrityVerification,
			Providers: []config.EncryptionProvider{
				{
					Alias: alias,
					Type:  "aes",
					Config: map[string]interface{}{
						"kek": []byte("performance-test-key-32bytes-!!!"),
					},
				},
			},
		},
	}
}
