package encryption

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/guided-traffic/s3-encryption-proxy/internal/config"
)

// Test data generators for comprehensive testing
func generateStreamingTestData(size int) []byte {
	data := make([]byte, size)
	for i := range data {
		data[i] = byte(i % 256)
	}
	return data
}

func generateRandomStreamingTestData(size int) []byte {
	data := make([]byte, size)
	_, err := rand.Read(data)
	if err != nil {
		panic(err)
	}
	return data
}

// Helper to create test config with different providers
func createStreamingTestConfig(providerType string, segmentSize int64) *config.Config {
	cfg := &config.Config{
		Encryption: config.EncryptionConfig{
			EncryptionMethodAlias: "test-provider",
			Providers: []config.EncryptionProvider{
				{
					Alias: "test-provider",
					Type:  providerType,
					Config: map[string]interface{}{
						"key": "test-key-32-bytes-for-aes-256!!",
					},
				},
			},
		},
		Optimizations: config.OptimizationsConfig{
			StreamingSegmentSize: segmentSize,
		},
	}
	return cfg
}

// TestNewStreamingOperations tests StreamingOperations creation and configuration
func TestNewStreamingOperations_Comprehensive(t *testing.T) {
	t.Run("Creation_With_Custom_Config", func(t *testing.T) {
		// Test with custom segment size
		cfg := createStreamingTestConfig("none", 2*1024*1024) // 2MB

		providerManager, err := NewProviderManager(cfg)
		require.NoError(t, err)

		hmacManager := NewHMACManager(cfg)
		metadataManager := NewMetadataManager(cfg, "test-")

		sop := NewStreamingOperations(providerManager, hmacManager, metadataManager, cfg)

		assert.NotNil(t, sop)
		assert.Equal(t, int64(2*1024*1024), sop.GetSegmentSize())
		assert.NotNil(t, sop.bufferPool)
	})

	t.Run("Creation_With_Default_Config", func(t *testing.T) {
		// Test with nil config (should use defaults)
		providerManager, err := NewProviderManager(nil)
		require.NoError(t, err)

		hmacManager := NewHMACManager(nil)
		metadataManager := NewMetadataManager(nil, "")

		sop := NewStreamingOperations(providerManager, hmacManager, metadataManager, nil)

		assert.NotNil(t, sop)
		assert.Equal(t, int64(12*1024*1024), sop.GetSegmentSize()) // Default 12MB
	})

	t.Run("Buffer_Pool_Memory_Management", func(t *testing.T) {
		// Test buffer pool functionality and memory clearing
		cfg := createStreamingTestConfig("none", 1024) // 1KB for fast testing

		providerManager, err := NewProviderManager(cfg)
		require.NoError(t, err)

		hmacManager := NewHMACManager(cfg)
		metadataManager := NewMetadataManager(cfg, "test-")

		sop := NewStreamingOperations(providerManager, hmacManager, metadataManager, cfg)

		// Get buffer and verify size
		buffer1 := sop.getBuffer()
		assert.NotNil(t, buffer1)
		assert.Equal(t, 1024, len(buffer1))

		// Fill buffer with test data
		for i := range buffer1 {
			buffer1[i] = 0xFF
		}

		// Return buffer (should be cleared)
		sop.returnBuffer(buffer1)

		// Get new buffer and verify it's cleared
		buffer2 := sop.getBuffer()
		assert.NotNil(t, buffer2)
		for i := range buffer2 {
			assert.Equal(t, byte(0), buffer2[i], "Buffer should be cleared at index %d", i)
		}
	})
}

// TestStreamWithSegments tests the core streaming functionality
func TestStreamWithSegments_Comprehensive(t *testing.T) {
	t.Run("Small_Data_Single_Segment", func(t *testing.T) {
		cfg := createTestConfig("none", 1024) // 1KB segments

		providerManager, err := NewProviderManager(cfg)
		require.NoError(t, err)

		hmacManager := NewHMACManager(cfg)
		metadataManager := NewMetadataManager(cfg, "test-")

		sop := NewStreamingOperations(providerManager, hmacManager, metadataManager, cfg)

		testData := "Hello, Streaming World!"
		reader := strings.NewReader(testData)

		var receivedData []byte
		segmentCount := 0

		err = sop.StreamWithSegments(context.Background(), reader, func(segment []byte) error {
			segmentCount++
			receivedData = append(receivedData, segment...)
			return nil
		})

		assert.NoError(t, err)
		assert.Equal(t, 1, segmentCount)
		assert.Equal(t, testData, string(receivedData))
	})

	t.Run("Large_Data_Multiple_Segments", func(t *testing.T) {
		cfg := createTestConfig("none", 100) // 100 byte segments for testing

		providerManager, err := NewProviderManager(cfg)
		require.NoError(t, err)

		hmacManager := NewHMACManager(cfg)
		metadataManager := NewMetadataManager(cfg, "test-")

		sop := NewStreamingOperations(providerManager, hmacManager, metadataManager, cfg)

		testData := generateTestData(500) // 500 bytes = 5 segments
		reader := bytes.NewReader(testData)

		var receivedData []byte
		segmentCount := 0

		err = sop.StreamWithSegments(context.Background(), reader, func(segment []byte) error {
			segmentCount++
			receivedData = append(receivedData, segment...)
			return nil
		})

		assert.NoError(t, err)
		assert.Equal(t, 5, segmentCount)
		assert.Equal(t, testData, receivedData)
	})

	t.Run("Context_Cancellation", func(t *testing.T) {
		cfg := createTestConfig("none", 1024)

		providerManager, err := NewProviderManager(cfg)
		require.NoError(t, err)

		hmacManager := NewHMACManager(cfg)
		metadataManager := NewMetadataManager(cfg, "test-")

		sop := NewStreamingOperations(providerManager, hmacManager, metadataManager, cfg)

		// Create large data stream
		testData := generateTestData(10 * 1024) // 10KB
		reader := bytes.NewReader(testData)

		// Create cancelable context
		ctx, cancel := context.WithCancel(context.Background())

		segmentCount := 0
		err = sop.StreamWithSegments(ctx, reader, func(segment []byte) error {
			segmentCount++
			if segmentCount == 2 {
				cancel() // Cancel after second segment
			}
			return nil
		})

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "context canceled")
		assert.Equal(t, 2, segmentCount)
	})

	t.Run("Error_In_Callback", func(t *testing.T) {
		cfg := createTestConfig("none", 1024)

		providerManager, err := NewProviderManager(cfg)
		require.NoError(t, err)

		hmacManager := NewHMACManager(cfg)
		metadataManager := NewMetadataManager(cfg, "test-")

		sop := NewStreamingOperations(providerManager, hmacManager, metadataManager, cfg)

		testData := generateTestData(2048) // 2KB = 2 segments
		reader := bytes.NewReader(testData)

		expectedError := assert.AnError
		segmentCount := 0

		err = sop.StreamWithSegments(context.Background(), reader, func(segment []byte) error {
			segmentCount++
			if segmentCount == 2 {
				return expectedError // Error on second segment
			}
			return nil
		})

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to process segment 2")
		assert.Equal(t, 2, segmentCount)
	})
}

// TestCreateEncryptionReader tests encryption reader creation and functionality
func TestCreateEncryptionReader_Comprehensive(t *testing.T) {
	t.Run("None_Provider_Pass_Through", func(t *testing.T) {
		cfg := createTestConfig("none", 1024)

		providerManager, err := NewProviderManager(cfg)
		require.NoError(t, err)

		hmacManager := NewHMACManager(cfg)
		metadataManager := NewMetadataManager(cfg, "test-")

		sop := NewStreamingOperations(providerManager, hmacManager, metadataManager, cfg)

		testData := "Test data for none provider"
		reader := strings.NewReader(testData)
		objectKey := "test/object"

		encReader, metadata, err := sop.CreateEncryptionReader(context.Background(), reader, objectKey)

		assert.NoError(t, err)
		assert.NotNil(t, encReader)
		assert.NotNil(t, metadata)

		// Read all data through encryption reader
		result, err := io.ReadAll(encReader)
		assert.NoError(t, err)
		assert.Equal(t, testData, string(result))
	})

	t.Run("Encryption_Reader_Interface", func(t *testing.T) {
		cfg := createTestConfig("none", 1024)

		providerManager, err := NewProviderManager(cfg)
		require.NoError(t, err)

		hmacManager := NewHMACManager(cfg)
		metadataManager := NewMetadataManager(cfg, "test-")

		sop := NewStreamingOperations(providerManager, hmacManager, metadataManager, cfg)

		testData := generateTestData(2048) // 2KB test data
		reader := bytes.NewReader(testData)
		objectKey := "test/large-object"

		encReader, _, err := sop.CreateEncryptionReader(context.Background(), reader, objectKey)
		assert.NoError(t, err)

		// Verify it implements io.Reader
		var _ io.Reader = encReader

		// Test incremental reading
		buffer := make([]byte, 512)
		var totalRead []byte

		for {
			n, err := encReader.Read(buffer)
			if n > 0 {
				totalRead = append(totalRead, buffer[:n]...)
			}
			if err == io.EOF {
				break
			}
			assert.NoError(t, err)
		}

		assert.Equal(t, testData, totalRead)
	})
}

// TestCreateDecryptionReader tests decryption reader creation and functionality
func TestCreateDecryptionReader_Comprehensive(t *testing.T) {
	t.Run("None_Provider_Pass_Through", func(t *testing.T) {
		cfg := createTestConfig("none", 1024)

		providerManager, err := NewProviderManager(cfg)
		require.NoError(t, err)

		hmacManager := NewHMACManager(cfg)
		metadataManager := NewMetadataManager(cfg, "test-")

		sop := NewStreamingOperations(providerManager, hmacManager, metadataManager, cfg)

		testData := "Test data for none provider decryption"
		reader := strings.NewReader(testData)

		// Simulate metadata for none provider
		metadata := map[string]string{
			"test-kek-fingerprint": "none-provider-fingerprint",
		}

		decReader, err := sop.CreateDecryptionReader(context.Background(), reader, metadata)

		assert.NoError(t, err)
		assert.NotNil(t, decReader)

		// Read all data through decryption reader
		result, err := io.ReadAll(decReader)
		assert.NoError(t, err)
		assert.Equal(t, testData, string(result))
	})

	t.Run("Invalid_Metadata", func(t *testing.T) {
		cfg := createTestConfig("none", 1024)

		providerManager, err := NewProviderManager(cfg)
		require.NoError(t, err)

		hmacManager := NewHMACManager(cfg)
		metadataManager := NewMetadataManager(cfg, "test-")

		sop := NewStreamingOperations(providerManager, hmacManager, metadataManager, cfg)

		testData := "Test data"
		reader := strings.NewReader(testData)

		// Invalid metadata (missing fingerprint)
		metadata := map[string]string{}

		_, err = sop.CreateDecryptionReader(context.Background(), reader, metadata)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "fingerprint")
	})
}

// TestEncryptDecryptStream tests full encrypt/decrypt workflow
func TestEncryptDecryptStream_Comprehensive(t *testing.T) {
	t.Run("Small_Data_Round_Trip", func(t *testing.T) {
		cfg := createTestConfig("none", 1024)

		providerManager, err := NewProviderManager(cfg)
		require.NoError(t, err)

		hmacManager := NewHMACManager(cfg)
		metadataManager := NewMetadataManager(cfg, "test-")

		sop := NewStreamingOperations(providerManager, hmacManager, metadataManager, cfg)

		originalData := "Hello, streaming encryption world!"
		objectKey := "test/small-file"

		// Encrypt
		reader := strings.NewReader(originalData)
		encryptedData, metadata, err := sop.EncryptStream(context.Background(), reader, objectKey)
		assert.NoError(t, err)
		assert.NotNil(t, encryptedData)
		assert.NotNil(t, metadata)

		// For none provider, data should be unchanged
		assert.Equal(t, originalData, string(encryptedData))

		// Decrypt
		encReader := bytes.NewReader(encryptedData)
		decryptedData, err := sop.DecryptStream(context.Background(), encReader, metadata)
		assert.NoError(t, err)
		assert.Equal(t, originalData, string(decryptedData))
	})

	t.Run("Large_Data_Round_Trip", func(t *testing.T) {
		cfg := createTestConfig("none", 512) // Small segments for testing

		providerManager, err := NewProviderManager(cfg)
		require.NoError(t, err)

		hmacManager := NewHMACManager(cfg)
		metadataManager := NewMetadataManager(cfg, "test-")

		sop := NewStreamingOperations(providerManager, hmacManager, metadataManager, cfg)

		originalData := generateTestData(5120) // 5KB = 10 segments
		objectKey := "test/large-file"

		// Encrypt
		reader := bytes.NewReader(originalData)
		encryptedData, metadata, err := sop.EncryptStream(context.Background(), reader, objectKey)
		assert.NoError(t, err)
		assert.NotNil(t, encryptedData)
		assert.NotNil(t, metadata)

		// Decrypt
		encReader := bytes.NewReader(encryptedData)
		decryptedData, err := sop.DecryptStream(context.Background(), encReader, metadata)
		assert.NoError(t, err)
		assert.Equal(t, originalData, decryptedData)
	})
}

// TestStreamingPerformance includes performance-oriented tests
func TestStreamingPerformance(t *testing.T) {
	t.Run("Memory_Efficiency_Large_File", func(t *testing.T) {
		// Test that streaming doesn't load entire file into memory
		cfg := createTestConfig("none", 1024*1024) // 1MB segments

		providerManager, err := NewProviderManager(cfg)
		require.NoError(t, err)

		hmacManager := NewHMACManager(cfg)
		metadataManager := NewMetadataManager(cfg, "test-")

		sop := NewStreamingOperations(providerManager, hmacManager, metadataManager, cfg)

		// Create 10MB test data
		largeData := generateTestData(10 * 1024 * 1024)
		reader := bytes.NewReader(largeData)

		segmentCount := 0
		totalSize := int64(0)

		start := time.Now()
		err = sop.StreamWithSegments(context.Background(), reader, func(segment []byte) error {
			segmentCount++
			totalSize += int64(len(segment))
			return nil
		})
		duration := time.Since(start)

		assert.NoError(t, err)
		assert.Equal(t, 10, segmentCount) // 10MB / 1MB = 10 segments
		assert.Equal(t, int64(len(largeData)), totalSize)

		// Performance assertion: should complete in reasonable time
		assert.Less(t, duration, 5*time.Second, "Streaming took too long")
	})
}

// Benchmark tests for performance analysis
func BenchmarkStreamingOperations(b *testing.B) {
	cfg := createTestConfig("none", 1024*1024) // 1MB segments

	providerManager, err := NewProviderManager(cfg)
	require.NoError(b, err)

	hmacManager := NewHMACManager(cfg)
	metadataManager := NewMetadataManager(cfg, "test-")

	sop := NewStreamingOperations(providerManager, hmacManager, metadataManager, cfg)

	b.Run("StreamWithSegments_1MB", func(b *testing.B) {
		data := generateTestData(1024 * 1024) // 1MB

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			reader := bytes.NewReader(data)
			err := sop.StreamWithSegments(context.Background(), reader, func(segment []byte) error {
				return nil
			})
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("BufferPool_Get_Return", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			buffer := sop.getBuffer()
			sop.returnBuffer(buffer)
		}
	})
}
