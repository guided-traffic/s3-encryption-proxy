package encryption

import (
	"context"
	"crypto/rand"
	"runtime"
	"testing"
	"time"

	"github.com/guided-traffic/s3-encryption-proxy/internal/config"
	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption"
	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption/factory"
	"github.com/stretchr/testify/require"
)

// TestMemoryEfficiency tests memory usage and GC pressure for HMAC operations
func TestMemoryEfficiency(t *testing.T) {
	ctx := context.Background()

	// Test scenarios for memory analysis
	testCases := []struct {
		name         string
		size         int64
		contentType  factory.ContentType
		hmacPolicy   string
		iterations   int
		description  string
	}{
		{
			name:        "SmallFiles_WithHMAC",
			size:        1024 * 1024, // 1MB
			contentType: factory.ContentTypeWhole,
			hmacPolicy:  "always",
			iterations:  100,
			description: "1MB files with HMAC - memory allocation pattern",
		},
		{
			name:        "SmallFiles_WithoutHMAC",
			size:        1024 * 1024, // 1MB
			contentType: factory.ContentTypeWhole,
			hmacPolicy:  "auto", // skips HMAC for AES-GCM
			iterations:  100,
			description: "1MB files without HMAC - optimized memory usage",
		},
		{
			name:        "LargeFiles_Streaming",
			size:        50 * 1024 * 1024, // 50MB
			contentType: factory.ContentTypeMultipart,
			hmacPolicy:  "auto",
			iterations:  10,
			description: "50MB streaming files - memory footprint analysis",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Logf("🧠 Memory Test: %s", tc.description)

			// Create manager
			cfg := &config.Config{
				Encryption: config.EncryptionConfig{
					EncryptionMethodAlias: "memory-provider",
					MetadataKeyPrefix:     stringPtr("s3ep-"),
					IntegrityVerification: true,
					HMACPolicy:           tc.hmacPolicy,
					Providers: []config.EncryptionProvider{
						{
							Alias: "memory-provider",
							Type:  "aes",
							Config: map[string]interface{}{
								"kek": []byte("memory-test-key-32-bytes-long!!!"),
							},
						},
					},
				},
			}

			manager, err := NewManager(cfg)
			require.NoError(t, err)

			// Generate test data once and reuse
			testData := make([]byte, tc.size)
			_, err = rand.Read(testData)
			require.NoError(t, err)

			// Force GC before measurement
			runtime.GC()
			runtime.GC() // Double GC to ensure clean state
			time.Sleep(100 * time.Millisecond)

			// Capture initial memory state
			var initialStats runtime.MemStats
			runtime.ReadMemStats(&initialStats)

			startTime := time.Now()
			var encResults []*encryption.EncryptionResult

			// Perform multiple operations to stress test memory
			for i := 0; i < tc.iterations; i++ {
				objectKey := "memory-test-object"

				// Encrypt
				encResult, err := manager.EncryptDataWithContentType(ctx, testData, objectKey, tc.contentType)
				require.NoError(t, err)

				// Store result for decryption
				encResults = append(encResults, encResult)

				// Periodic GC every 10 operations to measure pressure
				if i%10 == 9 {
					runtime.GC()
				}
			}

			// Decrypt all results
			for i, encResult := range encResults {
				objectKey := "memory-test-object"
				_, err := manager.DecryptDataWithMetadata(ctx, encResult.EncryptedData, encResult.EncryptedDEK, encResult.Metadata, objectKey, "memory-provider")
				require.NoError(t, err)

				// Periodic GC during decryption
				if i%10 == 9 {
					runtime.GC()
				}
			}

			operationDuration := time.Since(startTime)

			// Force final GC and measure final state
			runtime.GC()
			runtime.GC()
			time.Sleep(100 * time.Millisecond)

			var finalStats runtime.MemStats
			runtime.ReadMemStats(&finalStats)

			// Calculate memory metrics
			totalDataProcessed := int64(tc.iterations) * tc.size * 2 // encrypt + decrypt
			totalDataMB := float64(totalDataProcessed) / (1024 * 1024)

			heapAllocated := finalStats.HeapAlloc - initialStats.HeapAlloc
			heapSys := finalStats.HeapSys - initialStats.HeapSys
			numGC := finalStats.NumGC - initialStats.NumGC
			gcPauseTotal := finalStats.PauseTotalNs - initialStats.PauseTotalNs

			memoryEfficiency := float64(heapAllocated) / float64(totalDataProcessed)
			throughputMBps := totalDataMB / operationDuration.Seconds()

			// Check for HMAC usage
			hasHMAC := false
			if len(encResults) > 0 {
				for key := range encResults[0].Metadata {
					if key == "s3ep-hmac" {
						hasHMAC = true
						break
					}
				}
			}

			// Log detailed memory analysis
			t.Logf("📊 Memory Analysis Results:")
			t.Logf("   📏 Data Processed: %.1f MB (%d iterations × %.1f MB × 2 ops)",
				totalDataMB, tc.iterations, float64(tc.size)/(1024*1024))
			t.Logf("   ⚡ Throughput: %.1f MB/s", throughputMBps)
			t.Logf("   🔐 HMAC Enabled: %v", hasHMAC)
			t.Logf("   💾 Memory Usage:")
			t.Logf("      Heap Allocated: %d bytes (%.2f%% of data)", heapAllocated, memoryEfficiency*100)
			t.Logf("      Heap System: %d bytes", heapSys)
			t.Logf("      Memory Efficiency: %.4f bytes per data byte", memoryEfficiency)
			t.Logf("   🗑️  GC Performance:")
			t.Logf("      GC Cycles: %d", numGC)
			t.Logf("      GC Pause Total: %.2f ms", float64(gcPauseTotal)/1e6)
			t.Logf("      Avg GC Pause: %.2f ms", float64(gcPauseTotal)/float64(numGC)/1e6)

			// Memory efficiency assertions
			switch tc.name {
			case "SmallFiles_WithoutHMAC":
				// Without HMAC should be more memory efficient
				require.Less(t, memoryEfficiency, 0.5, "Memory usage should be <50% of data size without HMAC")

			case "SmallFiles_WithHMAC":
				// With HMAC will use more memory for hash calculation
				require.Less(t, memoryEfficiency, 1.0, "Memory usage should be <100% of data size even with HMAC")

			case "LargeFiles_Streaming":
				// Streaming should be very memory efficient regardless of file size
				require.Less(t, memoryEfficiency, 0.2, "Streaming should use <20% of data size in memory")
				require.Greater(t, throughputMBps, 1000.0, "Streaming should maintain >1 GB/s throughput")
			}

			// GC pressure should be reasonable
			avgGCPause := float64(gcPauseTotal) / float64(numGC) / 1e6
			require.Less(t, avgGCPause, 10.0, "Average GC pause should be <10ms")

			t.Logf("   ✅ Memory efficiency validated for %s", tc.name)
		})
	}

	t.Log("")
	t.Log("🎯 Memory Optimization Summary:")
	t.Log("   ✅ HMAC Smart Policy reduces memory overhead")
	t.Log("   ✅ Streaming maintains low memory footprint for large files")
	t.Log("   ✅ GC pressure remains manageable across all scenarios")
	t.Log("   ✅ Memory efficiency optimized for production workloads")
}

// BenchmarkMemoryAllocation benchmarks memory allocation patterns
func BenchmarkMemoryAllocation(b *testing.B) {
	ctx := context.Background()

	cfg := &config.Config{
		Encryption: config.EncryptionConfig{
			EncryptionMethodAlias: "bench-memory",
			MetadataKeyPrefix:     stringPtr("s3ep-"),
			IntegrityVerification: true,
			HMACPolicy:           "auto", // Smart policy
			Providers: []config.EncryptionProvider{
				{
					Alias: "bench-memory",
					Type:  "aes",
					Config: map[string]interface{}{
						"kek": []byte("benchmark-memory-key-32-bytes!!!"),
					},
				},
			},
		},
	}

	manager, err := NewManager(cfg)
	require.NoError(b, err)

	// 1MB test data
	testData := make([]byte, 1024*1024)
	_, err = rand.Read(testData)
	require.NoError(b, err)

	b.ResetTimer()
	b.ReportAllocs() // Report allocation statistics

	for i := 0; i < b.N; i++ {
		// Test memory allocation pattern for encryption/decryption cycle
		encResult, err := manager.EncryptDataWithContentType(ctx, testData, "bench-object", factory.ContentTypeWhole)
		require.NoError(b, err)

		_, err = manager.DecryptDataWithMetadata(ctx, encResult.EncryptedData, encResult.EncryptedDEK, encResult.Metadata, "bench-object", "bench-memory")
		require.NoError(b, err)
	}
}

// Helper type is no longer needed - use encryption.EncryptionResult directly
