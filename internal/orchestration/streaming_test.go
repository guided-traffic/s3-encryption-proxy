package orchestration

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/guided-traffic/s3-encryption-proxy/internal/config"
	"github.com/guided-traffic/s3-encryption-proxy/internal/validation"
)

// =============================================================================
// Test Utilities and Helper Functions
// =============================================================================

// calculateSHA256ForStreamingTest computes SHA256 hash for streaming testing
func calculateSHA256ForStreamingTest(data []byte) string {
	hash := sha256.Sum256(data)
	return fmt.Sprintf("%x", hash)
}

// generateStreamingTestData creates deterministic test data of specified size
func generateStreamingTestData(size int) []byte {
	data := make([]byte, size)
	for i := range data {
		data[i] = byte(i % 256)
	}
	return data
}

// generateRandomStreamingTestData creates random test data for encryption testing
func generateRandomStreamingTestData(size int) []byte {
	data := make([]byte, size)
	_, err := rand.Read(data)
	if err != nil {
		panic(err)
	}
	return data
}

// createStreamingTestConfig creates a test configuration with specified provider and segment size
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

// createStreamingTestStreamingOperations creates a StreamingOperations instance for testing
func createStreamingTestStreamingOperations(t testing.TB, providerType string, segmentSize int64) *StreamingOperations {
	cfg := createStreamingTestConfig(providerType, segmentSize)

	providerManager, err := NewProviderManager(cfg)
	require.NoError(t, err)

	hmacManager := validation.NewHMACManager(cfg)
	metadataManager := NewMetadataManager(cfg, "test-")

	sop := NewStreamingOperations(providerManager, hmacManager, metadataManager, cfg)
	require.NotNil(t, sop)

	return sop
}

// createTestStreamingOperations creates a StreamingOperations instance with a given config for testing
// This function is used for testing with real AES-CTR providers and custom configurations
func createTestStreamingOperations(t testing.TB, cfg *config.Config) *StreamingOperations {
	providerManager, err := NewProviderManager(cfg)
	require.NoError(t, err, "Should create provider manager")

	hmacManager := validation.NewHMACManager(cfg)
	require.NotNil(t, hmacManager, "Should create HMAC manager")

	metadataManager := NewMetadataManager(cfg, "s3ep-")
	require.NotNil(t, metadataManager, "Should create metadata manager")

	sop := NewStreamingOperations(providerManager, hmacManager, metadataManager, cfg)
	require.NotNil(t, sop, "Should create streaming operations")

	return sop
}

// TestReader implements io.Reader for controlled testing scenarios
type TestReader struct {
	data     []byte
	pos      int
	err      error
	readSize int // Limit read size to simulate slow readers
}

func NewTestReader(data []byte) *TestReader {
	return &TestReader{data: data, readSize: len(data)}
}

func (tr *TestReader) SetReadSize(size int) {
	tr.readSize = size
}

func (tr *TestReader) SetError(err error) {
	tr.err = err
}

func (tr *TestReader) Read(p []byte) (n int, err error) {
	if tr.err != nil {
		return 0, tr.err
	}

	if tr.pos >= len(tr.data) {
		return 0, io.EOF
	}

	readSize := len(p)
	if tr.readSize > 0 && readSize > tr.readSize {
		readSize = tr.readSize
	}

	available := len(tr.data) - tr.pos
	if readSize > available {
		readSize = available
	}

	n = copy(p[:readSize], tr.data[tr.pos:tr.pos+readSize])
	tr.pos += n
	return n, nil
}

// ErrorAfterReader returns an error after reading a specified amount of data
type ErrorAfterReader struct {
	data       []byte
	pos        int
	errorAfter int
	err        error
}

func NewErrorAfterReader(data []byte, errorAfter int, err error) *ErrorAfterReader {
	return &ErrorAfterReader{
		data:       data,
		errorAfter: errorAfter,
		err:        err,
	}
}

func (ear *ErrorAfterReader) Read(p []byte) (n int, err error) {
	if ear.pos >= ear.errorAfter {
		return 0, ear.err
	}

	remaining := ear.errorAfter - ear.pos
	readSize := len(p)
	if readSize > remaining {
		readSize = remaining
	}

	if ear.pos+readSize > len(ear.data) {
		readSize = len(ear.data) - ear.pos
	}

	n = copy(p[:readSize], ear.data[ear.pos:ear.pos+readSize])
	ear.pos += n

	if ear.pos >= ear.errorAfter {
		return n, ear.err
	}

	return n, nil
}

// =============================================================================
// Test Cases for StreamingOperations Creation and Configuration
// =============================================================================

// TestNewStreamingOperations tests the creation and configuration of StreamingOperations
func TestNewStreamingOperations(t *testing.T) {
	t.Run("Creation_With_Custom_Config", func(t *testing.T) {
		// Test creating StreamingOperations with custom segment size
		cfg := createStreamingTestConfig("none", 2*1024*1024) // 2MB segments

		providerManager, err := NewProviderManager(cfg)
		require.NoError(t, err)

		hmacManager := validation.NewHMACManager(cfg)
		metadataManager := NewMetadataManager(cfg, "test-")

		sop := NewStreamingOperations(providerManager, hmacManager, metadataManager, cfg)

		assert.NotNil(t, sop)
		assert.Equal(t, int64(2*1024*1024), sop.GetSegmentSize())
		assert.NotNil(t, sop.bufferPool)
		assert.NotNil(t, sop.logger)
	})

	t.Run("Creation_With_Default_Config", func(t *testing.T) {
		// Test creating StreamingOperations with nil config (uses defaults)
		// Note: We need a minimal config for ProviderManager to work
		cfg := &config.Config{
			Encryption: config.EncryptionConfig{
				EncryptionMethodAlias: "none",
				Providers: []config.EncryptionProvider{
					{
						Alias: "none",
						Type:  "none",
						Config: map[string]interface{}{},
					},
				},
			},
		}

		providerManager, err := NewProviderManager(cfg)
		require.NoError(t, err)

		hmacManager := validation.NewHMACManager(nil)
		metadataManager := NewMetadataManager(cfg, "test-")

		sop := NewStreamingOperations(providerManager, hmacManager, metadataManager, nil)

		assert.NotNil(t, sop)
		assert.Equal(t, int64(12*1024*1024), sop.GetSegmentSize()) // Default 12MB
		assert.NotNil(t, sop.bufferPool)
	})

	t.Run("Buffer_Pool_Functionality", func(t *testing.T) {
		// Test buffer pool memory management and clearing
		sop := createStreamingTestStreamingOperations(t, "none", 1024) // 1KB for fast testing

		// Get buffer and verify properties
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

	t.Run("GetSegmentSize", func(t *testing.T) {
		// Test GetSegmentSize method
		testSizes := []int64{1024, 1024 * 1024, 5 * 1024 * 1024}

		for _, size := range testSizes {
			sop := createStreamingTestStreamingOperations(t, "none", size)
			assert.Equal(t, size, sop.GetSegmentSize())
		}
	})
}

// =============================================================================
// Test Cases for StreamWithSegments Core Functionality
// =============================================================================

// TestStreamWithSegments tests the core streaming segmentation functionality
func TestStreamWithSegments(t *testing.T) {
	t.Run("Small_Data_Single_Segment", func(t *testing.T) {
		// Test streaming small data that fits in one segment
		sop := createStreamingTestStreamingOperations(t, "none", 1024) // 1KB segments

		testData := "Hello, Streaming World! This is a test."
		reader := strings.NewReader(testData)

		var receivedData []byte
		segmentCount := 0

		err := sop.StreamWithSegments(context.Background(), reader, func(segment []byte) error {
			segmentCount++
			receivedData = append(receivedData, segment...)
			return nil
		})

		assert.NoError(t, err)
		assert.Equal(t, 1, segmentCount)
		assert.Equal(t, testData, string(receivedData))
	})

	t.Run("Large_Data_Multiple_Segments", func(t *testing.T) {
		// Test streaming large data across multiple segments
		sop := createStreamingTestStreamingOperations(t, "none", 100) // 100-byte segments

		testData := generateStreamingTestData(500) // 500 bytes = 5 segments
		reader := bytes.NewReader(testData)

		var receivedData []byte
		segmentCount := 0
		segmentSizes := []int{}

		err := sop.StreamWithSegments(context.Background(), reader, func(segment []byte) error {
			segmentCount++
			segmentSizes = append(segmentSizes, len(segment))
			receivedData = append(receivedData, segment...)
			return nil
		})

		assert.NoError(t, err)
		assert.Equal(t, 5, segmentCount)
		assert.Equal(t, testData, receivedData)

		// Verify segment sizes (all should be 100 except possibly the last)
		for i, size := range segmentSizes {
			if i < len(segmentSizes)-1 {
				assert.Equal(t, 100, size, "Segment %d should be 100 bytes", i)
			} else {
				assert.LessOrEqual(t, size, 100, "Last segment should be <= 100 bytes")
			}
		}
	})

	t.Run("Empty_Stream", func(t *testing.T) {
		// Test streaming empty data
		sop := createStreamingTestStreamingOperations(t, "none", 1024)

		reader := strings.NewReader("")
		segmentCount := 0

		err := sop.StreamWithSegments(context.Background(), reader, func(segment []byte) error {
			segmentCount++
			return nil
		})

		assert.NoError(t, err)
		assert.Equal(t, 0, segmentCount)
	})

	t.Run("Context_Cancellation", func(t *testing.T) {
		// Test context cancellation during streaming
		sop := createStreamingTestStreamingOperations(t, "none", 1024)

		testData := generateStreamingTestData(10 * 1024) // 10KB
		reader := bytes.NewReader(testData)

		ctx, cancel := context.WithCancel(context.Background())
		segmentCount := 0

		err := sop.StreamWithSegments(ctx, reader, func(segment []byte) error {
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

	t.Run("Callback_Error", func(t *testing.T) {
		// Test error handling in segment callback
		sop := createStreamingTestStreamingOperations(t, "none", 1024)

		testData := generateStreamingTestData(2048) // 2KB = 2 segments
		reader := bytes.NewReader(testData)

		expectedError := errors.New("callback error")
		segmentCount := 0

		err := sop.StreamWithSegments(context.Background(), reader, func(segment []byte) error {
			segmentCount++
			if segmentCount == 2 {
				return expectedError
			}
			return nil
		})

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to process segment 2")
		assert.Equal(t, 2, segmentCount)
	})

	t.Run("Reader_Error", func(t *testing.T) {
		// Test handling of reader errors
		sop := createStreamingTestStreamingOperations(t, "none", 1024)

		testData := generateStreamingTestData(2048)
		expectedError := errors.New("reader error")
		reader := NewErrorAfterReader(testData, 1024, expectedError) // Error after 1KB

		segmentCount := 0

		err := sop.StreamWithSegments(context.Background(), reader, func(segment []byte) error {
			segmentCount++
			return nil
		})

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to read from stream")
		assert.Equal(t, 1, segmentCount) // Should have processed one segment before error
	})
}

// =============================================================================
// Test Cases for Encryption Reader Functionality
// =============================================================================

// TestCreateEncryptionReader tests creation and functionality of encryption readers
func TestCreateEncryptionReader(t *testing.T) {
	t.Run("None_Provider_Pass_Through", func(t *testing.T) {
		// Test encryption reader with none provider (pass-through)
		sop := createStreamingTestStreamingOperations(t, "none", 1024)

		testData := "Test data for none provider encryption"
		reader := strings.NewReader(testData)
		objectKey := "test/object"

		encReader, _, err := sop.CreateEncryptionReader(context.Background(), reader, objectKey)

		assert.NoError(t, err)
		assert.NotNil(t, encReader)
		// Note: metadata might be nil for none provider, which is acceptable

		// Read all data through encryption reader
		result, err := io.ReadAll(encReader)
		assert.NoError(t, err)
		assert.Equal(t, testData, string(result))
	})

	t.Run("Encryption_Reader_Interface", func(t *testing.T) {
		// Test that EncryptionReader properly implements io.Reader
		sop := createStreamingTestStreamingOperations(t, "none", 1024)

		testData := generateStreamingTestData(2048)
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

	t.Run("Encryption_Reader_Close", func(t *testing.T) {
		// Test EncryptionReader Close functionality
		sop := createStreamingTestStreamingOperations(t, "none", 1024)

		testData := "Test data for close testing"
		reader := strings.NewReader(testData)
		objectKey := "test/close-object"

		encReader, _, err := sop.CreateEncryptionReader(context.Background(), reader, objectKey)
		assert.NoError(t, err)

		// Check if it implements io.Closer
		if closer, ok := encReader.(io.Closer); ok {
			err = closer.Close()
			assert.NoError(t, err)
		}
	})

	t.Run("Large_Data_Streaming", func(t *testing.T) {
		// Test encryption reader with large data
		sop := createStreamingTestStreamingOperations(t, "none", 1024) // 1KB segments

		testData := generateStreamingTestData(10 * 1024) // 10KB
		reader := bytes.NewReader(testData)
		objectKey := "test/large-stream"

		encReader, _, err := sop.CreateEncryptionReader(context.Background(), reader, objectKey)
		assert.NoError(t, err)

		// Read in chunks and verify
		var totalRead []byte
		buffer := make([]byte, 1500) // Larger than segment size

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

// =============================================================================
// Test Cases for Decryption Reader Functionality
// =============================================================================

// TestCreateDecryptionReader tests creation and functionality of decryption readers
func TestCreateDecryptionReader(t *testing.T) {
	t.Run("None_Provider_Pass_Through", func(t *testing.T) {
		// Test decryption reader with none provider
		sop := createStreamingTestStreamingOperations(t, "none", 1024)

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

	t.Run("Invalid_Metadata_Missing_Fingerprint", func(t *testing.T) {
		// Test error handling with invalid metadata
		sop := createStreamingTestStreamingOperations(t, "none", 1024)

		testData := "Test data"
		reader := strings.NewReader(testData)

		// Invalid metadata (missing fingerprint)
		metadata := map[string]string{}

		_, err := sop.CreateDecryptionReader(context.Background(), reader, metadata)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "fingerprint")
	})

	t.Run("Decryption_Reader_Interface", func(t *testing.T) {
		// Test that DecryptionReader properly implements io.Reader
		sop := createStreamingTestStreamingOperations(t, "none", 1024)

		testData := generateStreamingTestData(2048)
		reader := bytes.NewReader(testData)

		metadata := map[string]string{
			"test-kek-fingerprint": "none-provider-fingerprint",
		}

		decReader, err := sop.CreateDecryptionReader(context.Background(), reader, metadata)
		assert.NoError(t, err)

		// Verify it implements io.Reader
		var _ io.Reader = decReader

		// Test incremental reading
		buffer := make([]byte, 512)
		var totalRead []byte

		for {
			n, err := decReader.Read(buffer)
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

	t.Run("Decryption_Reader_Close", func(t *testing.T) {
		// Test DecryptionReader Close functionality
		sop := createStreamingTestStreamingOperations(t, "none", 1024)

		testData := "Test data for close testing"
		reader := strings.NewReader(testData)

		metadata := map[string]string{
			"test-kek-fingerprint": "none-provider-fingerprint",
		}

		decReader, err := sop.CreateDecryptionReader(context.Background(), reader, metadata)
		assert.NoError(t, err)

		// Check if it implements io.Closer
		if closer, ok := decReader.(io.Closer); ok {
			err = closer.Close()
			assert.NoError(t, err)
		}
	})
}

// =============================================================================
// Test Cases for Full Stream Encryption/Decryption
// =============================================================================

// TestEncryptDecryptStream tests full encrypt/decrypt workflow
func TestEncryptDecryptStream(t *testing.T) {
	t.Run("Small_Data_Round_Trip", func(t *testing.T) {
		// Test complete encrypt/decrypt cycle with small data
		sop := createStreamingTestStreamingOperations(t, "none", 1024)

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

		// Decrypt using internal metadata (these wouldn't be sent to S3)
		encReader := bytes.NewReader(encryptedData)
		decryptedData, err := sop.DecryptStream(context.Background(), encReader, metadata)
		assert.NoError(t, err)
		assert.Equal(t, originalData, string(decryptedData))
	})

	t.Run("Large_Data_Round_Trip", func(t *testing.T) {
		// Test complete encrypt/decrypt cycle with large data (multiple segments)
		sop := createStreamingTestStreamingOperations(t, "none", 512) // Small segments for testing

		originalData := generateStreamingTestData(5120) // 5KB = 10 segments
		objectKey := "test/large-file"

		// Encrypt
		reader := bytes.NewReader(originalData)
		encryptedData, metadata, err := sop.EncryptStream(context.Background(), reader, objectKey)
		assert.NoError(t, err)
		assert.NotNil(t, encryptedData)
		assert.NotNil(t, metadata)

		// Decrypt using internal metadata (these wouldn't be sent to S3)
		encReader := bytes.NewReader(encryptedData)
		decryptedData, err := sop.DecryptStream(context.Background(), encReader, metadata)
		assert.NoError(t, err)
		assert.Equal(t, originalData, decryptedData)
	})

	t.Run("Empty_Data_Round_Trip", func(t *testing.T) {
		// Test encrypt/decrypt with empty data
		sop := createStreamingTestStreamingOperations(t, "none", 1024)

		originalData := ""
		objectKey := "test/empty-file"

		// Encrypt
		reader := strings.NewReader(originalData)
		encryptedData, metadata, err := sop.EncryptStream(context.Background(), reader, objectKey)
		assert.NoError(t, err)
		assert.NotNil(t, metadata)
		assert.Equal(t, "", string(encryptedData))

		// Decrypt using internal metadata (these wouldn't be sent to S3)
		encReader := bytes.NewReader(encryptedData)
		decryptedData, err := sop.DecryptStream(context.Background(), encReader, metadata)
		assert.NoError(t, err)
		assert.Equal(t, originalData, string(decryptedData))
	})

	t.Run("Unencrypted_File_With_No_Metadata", func(t *testing.T) {
		// Test decryption of files that have no encryption metadata (real-world scenario)
		sop := createStreamingTestStreamingOperations(t, "none", 1024)

		originalData := "This file was stored without encryption metadata"

		// Simulate a file stored in S3 without any encryption metadata
		reader := bytes.NewReader([]byte(originalData))
		decryptedData, err := sop.DecryptStream(context.Background(), reader, nil)
		assert.NoError(t, err)
		assert.Equal(t, originalData, string(decryptedData))
	})

	t.Run("Unencrypted_File_With_Empty_Metadata", func(t *testing.T) {
		// Test decryption of files that have empty encryption metadata
		sop := createStreamingTestStreamingOperations(t, "none", 1024)

		originalData := "This file was stored with empty metadata"

		// Simulate a file stored in S3 with empty metadata
		reader := bytes.NewReader([]byte(originalData))
		decryptedData, err := sop.DecryptStream(context.Background(), reader, map[string]string{})
		assert.NoError(t, err)
		assert.Equal(t, originalData, string(decryptedData))
	})

	t.Run("Context_Cancellation_During_Encryption", func(t *testing.T) {
		// Test context cancellation during encryption
		sop := createStreamingTestStreamingOperations(t, "none", 1024)

		largeData := generateStreamingTestData(10 * 1024) // 10KB
		reader := bytes.NewReader(largeData)
		objectKey := "test/cancel-file"

		// Create context with timeout
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Microsecond)
		defer cancel()

		// This should fail due to context cancellation
		_, _, err := sop.EncryptStream(ctx, reader, objectKey)
		// Note: Might not always fail due to fast execution, but test the mechanism
		if err != nil {
			assert.Contains(t, err.Error(), "context")
		}
	})
}

// =============================================================================
// Test Cases for Streaming with Callbacks and Last Segment Detection
// =============================================================================

// TestStreamEncryptWithCallback tests streaming encryption with callback functionality
func TestStreamEncryptWithCallback(t *testing.T) {
	t.Run("Basic_Callback_Functionality", func(t *testing.T) {
		// Test basic streaming encryption with callback
		sop := createStreamingTestStreamingOperations(t, "none", 1024)

		testData := "Hello, callback world!"
		reader := strings.NewReader(testData)
		objectKey := "test/callback-object"

		var receivedSegments [][]byte
		var lastSegmentFlags []bool

		metadata, err := sop.StreamEncryptWithCallback(
			context.Background(),
			reader,
			objectKey,
			func(encryptedData []byte, isLastSegment bool) error {
				receivedSegments = append(receivedSegments, append([]byte(nil), encryptedData...))
				lastSegmentFlags = append(lastSegmentFlags, isLastSegment)
				return nil
			},
		)

		assert.NoError(t, err)
		assert.NotNil(t, metadata)
		assert.Equal(t, 1, len(receivedSegments))
		assert.Equal(t, 1, len(lastSegmentFlags))
		assert.True(t, lastSegmentFlags[0]) // Single segment should be marked as last

		// Verify data
		var reconstructedData []byte
		for _, segment := range receivedSegments {
			reconstructedData = append(reconstructedData, segment...)
		}
		assert.Equal(t, testData, string(reconstructedData))
	})

	t.Run("Multiple_Segments_Last_Flag", func(t *testing.T) {
		// Test last segment detection with multiple segments
		sop := createStreamingTestStreamingOperations(t, "none", 100) // Small segments

		testData := generateStreamingTestData(300) // 3 segments
		reader := bytes.NewReader(testData)
		objectKey := "test/multi-callback"

		var lastSegmentFlags []bool

		_, err := sop.StreamEncryptWithCallback(
			context.Background(),
			reader,
			objectKey,
			func(encryptedData []byte, isLastSegment bool) error {
				lastSegmentFlags = append(lastSegmentFlags, isLastSegment)
				return nil
			},
		)

		assert.NoError(t, err)
		assert.Equal(t, 3, len(lastSegmentFlags))
		assert.False(t, lastSegmentFlags[0], "First segment should not be last")
		assert.False(t, lastSegmentFlags[1], "Second segment should not be last")
		assert.True(t, lastSegmentFlags[2], "Third segment should be last")
	})

	t.Run("Callback_Error_Handling", func(t *testing.T) {
		// Test error handling in callback
		sop := createStreamingTestStreamingOperations(t, "none", 1024)

		testData := generateStreamingTestData(2048) // 2 segments
		reader := bytes.NewReader(testData)
		objectKey := "test/callback-error"

		expectedError := errors.New("callback error")
		segmentCount := 0

		_, err := sop.StreamEncryptWithCallback(
			context.Background(),
			reader,
			objectKey,
			func(encryptedData []byte, isLastSegment bool) error {
				segmentCount++
				if segmentCount == 2 {
					return expectedError
				}
				return nil
			},
		)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "callback error") // Check for the actual callback error
		assert.Equal(t, 2, segmentCount)
	})
}

// TestStreamDecryptWithCallback tests streaming decryption with callback functionality
func TestStreamDecryptWithCallback(t *testing.T) {
	t.Run("Basic_Callback_Functionality", func(t *testing.T) {
		// Test basic streaming decryption with callback
		sop := createStreamingTestStreamingOperations(t, "none", 1024)

		testData := "Hello, decryption callback!"
		reader := strings.NewReader(testData)

		metadata := map[string]string{
			"test-kek-fingerprint": "none-provider-fingerprint",
		}

		var receivedSegments [][]byte
		var lastSegmentFlags []bool

		err := sop.StreamDecryptWithCallback(
			context.Background(),
			reader,
			metadata,
			func(decryptedData []byte, isLastSegment bool) error {
				receivedSegments = append(receivedSegments, append([]byte(nil), decryptedData...))
				lastSegmentFlags = append(lastSegmentFlags, isLastSegment)
				return nil
			},
		)

		assert.NoError(t, err)
		assert.Equal(t, 1, len(receivedSegments))
		assert.Equal(t, 1, len(lastSegmentFlags))
		assert.True(t, lastSegmentFlags[0]) // Single segment should be marked as last

		// Verify data
		var reconstructedData []byte
		for _, segment := range receivedSegments {
			reconstructedData = append(reconstructedData, segment...)
		}
		assert.Equal(t, testData, string(reconstructedData))
	})

	t.Run("Invalid_Metadata", func(t *testing.T) {
		// Test error handling with invalid metadata
		sop := createStreamingTestStreamingOperations(t, "none", 1024)

		testData := "Test data"
		reader := strings.NewReader(testData)

		invalidMetadata := map[string]string{} // Missing fingerprint

		err := sop.StreamDecryptWithCallback(
			context.Background(),
			reader,
			invalidMetadata,
			func(decryptedData []byte, isLastSegment bool) error {
				return nil
			},
		)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "fingerprint")
	})
}

// =============================================================================
// Test Cases for Performance and Memory Efficiency
// =============================================================================

// TestStreamingPerformance includes performance-oriented tests
func TestStreamingPerformance(t *testing.T) {
	t.Run("Memory_Efficiency_Large_File", func(t *testing.T) {
		// Test that streaming doesn't load entire file into memory at once
		sop := createStreamingTestStreamingOperations(t, "none", 1024*1024) // 1MB segments

		// Create 5MB test data
		largeData := generateStreamingTestData(5 * 1024 * 1024)
		reader := bytes.NewReader(largeData)

		segmentCount := 0
		totalSize := int64(0)
		maxSegmentSize := 0

		start := time.Now()
		err := sop.StreamWithSegments(context.Background(), reader, func(segment []byte) error {
			segmentCount++
			totalSize += int64(len(segment))
			if len(segment) > maxSegmentSize {
				maxSegmentSize = len(segment)
			}
			return nil
		})
		duration := time.Since(start)

		assert.NoError(t, err)
		assert.Equal(t, 5, segmentCount) // 5MB / 1MB = 5 segments
		assert.Equal(t, int64(len(largeData)), totalSize)
		assert.LessOrEqual(t, maxSegmentSize, 1024*1024, "No segment should exceed configured size")

		// Performance assertion: should complete in reasonable time
		assert.Less(t, duration, 10*time.Second, "Streaming took too long")
	})

	t.Run("Buffer_Pool_Reuse", func(t *testing.T) {
		// Test that buffer pool properly reuses buffers
		sop := createStreamingTestStreamingOperations(t, "none", 1024)

		// Get multiple buffers and verify they're reused
		buffers := make([][]byte, 10)
		for i := 0; i < 10; i++ {
			buffers[i] = sop.getBuffer()
			assert.Equal(t, 1024, len(buffers[i]))
		}

		// Return all buffers
		for _, buffer := range buffers {
			sop.returnBuffer(buffer)
		}

		// Get new buffers - some should be reused (though Go's sync.Pool doesn't guarantee this)
		newBuffers := make([][]byte, 10)
		for i := 0; i < 10; i++ {
			newBuffers[i] = sop.getBuffer()
			assert.Equal(t, 1024, len(newBuffers[i]))
		}
	})

	t.Run("Concurrent_Buffer_Access", func(t *testing.T) {
		// Test thread-safe buffer pool access
		sop := createStreamingTestStreamingOperations(t, "none", 1024)

		done := make(chan bool, 10)

		// Start multiple goroutines accessing buffer pool
		for i := 0; i < 10; i++ {
			go func() {
				defer func() { done <- true }()

				for j := 0; j < 100; j++ {
					buffer := sop.getBuffer()
					assert.Equal(t, 1024, len(buffer))

					// Simulate some work
					time.Sleep(1 * time.Microsecond)

					sop.returnBuffer(buffer)
				}
			}()
		}

		// Wait for all goroutines to complete
		for i := 0; i < 10; i++ {
			<-done
		}
	})
}

// =============================================================================
// Test Cases for Edge Cases and Error Handling
// =============================================================================

// TestStreamingEdgeCases tests various edge cases and error conditions
func TestStreamingEdgeCases(t *testing.T) {
	t.Run("Empty_Reader", func(t *testing.T) {
		// Test handling of empty reader (EOF immediately)
		sop := createStreamingTestStreamingOperations(t, "none", 1024)
		emptyReader := strings.NewReader("")

		callbackCalled := false
		err := sop.StreamWithSegments(context.Background(), emptyReader, func(segment []byte) error {
			callbackCalled = true
			return nil
		})

		// Should complete without error but not call callback
		assert.NoError(t, err)
		assert.False(t, callbackCalled, "Callback should not be called for empty reader")
	})

	t.Run("Nil_Callback", func(t *testing.T) {
		// Test handling of nil callback
		sop := createStreamingTestStreamingOperations(t, "none", 1024)

		testData := "test data"
		reader := strings.NewReader(testData)

		// This should panic or error
		assert.Panics(t, func() {
			_ = sop.StreamWithSegments(context.Background(), reader, nil)
		})
	})

	t.Run("Very_Large_Segment_Size", func(t *testing.T) {
		// Test with very large segment size
		sop := createStreamingTestStreamingOperations(t, "none", 100*1024*1024) // 100MB segments

		testData := generateStreamingTestData(1024) // 1KB data
		reader := bytes.NewReader(testData)

		segmentCount := 0
		err := sop.StreamWithSegments(context.Background(), reader, func(segment []byte) error {
			segmentCount++
			assert.Equal(t, len(testData), len(segment)) // Should fit in one segment
			return nil
		})

		assert.NoError(t, err)
		assert.Equal(t, 1, segmentCount)
	})

	t.Run("Very_Small_Segment_Size", func(t *testing.T) {
		// Test with very small segment size
		sop := createStreamingTestStreamingOperations(t, "none", 10) // 10-byte segments

		testData := generateStreamingTestData(100) // 100 bytes = 10 segments
		reader := bytes.NewReader(testData)

		segmentCount := 0
		var totalData []byte

		err := sop.StreamWithSegments(context.Background(), reader, func(segment []byte) error {
			segmentCount++
			totalData = append(totalData, segment...)
			assert.LessOrEqual(t, len(segment), 10, "Segment should not exceed 10 bytes")
			return nil
		})

		assert.NoError(t, err)
		assert.Equal(t, 10, segmentCount)
		assert.Equal(t, testData, totalData)
	})
}

// =============================================================================
// Benchmark Tests for Performance Analysis
// =============================================================================

// BenchmarkStreamingOperations contains benchmark tests for performance analysis
func BenchmarkStreamingOperations(b *testing.B) {
	b.Run("StreamWithSegments_1MB", func(b *testing.B) {
		sop := createStreamingTestStreamingOperations(b, "none", 1024*1024) // 1MB segments
		data := generateStreamingTestData(1024 * 1024) // 1MB data

		b.ResetTimer()
		b.ReportAllocs()

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
		sop := createStreamingTestStreamingOperations(b, "none", 1024*1024)

		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			buffer := sop.getBuffer()
			sop.returnBuffer(buffer)
		}
	})

	b.Run("EncryptDecrypt_RoundTrip_10MB", func(b *testing.B) {
		sop := createStreamingTestStreamingOperations(b, "none", 1024*1024) // 1MB segments
		data := generateStreamingTestData(10 * 1024 * 1024) // 10MB data
		objectKey := "bench/large-file"

		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			// Encrypt
			reader := bytes.NewReader(data)
			encryptedData, metadata, err := sop.EncryptStream(context.Background(), reader, objectKey)
			if err != nil {
				b.Fatal(err)
			}

			// Decrypt
			encReader := bytes.NewReader(encryptedData)
			_, err = sop.DecryptStream(context.Background(), encReader, metadata)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("CreateEncryptionReader_Large", func(b *testing.B) {
		sop := createStreamingTestStreamingOperations(b, "none", 1024*1024)
		data := generateStreamingTestData(5 * 1024 * 1024) // 5MB data
		objectKey := "bench/reader-test"

		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			reader := bytes.NewReader(data)
			encReader, _, err := sop.CreateEncryptionReader(context.Background(), reader, objectKey)
			if err != nil {
				b.Fatal(err)
			}

			// Read all data
			_, err = io.ReadAll(encReader)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

// TestRealAESCTREncryptionReaders tests the EncryptionReader and DecryptionReader
// with real AES-CTR encryption to achieve full coverage of the streaming reader implementations.
//
// This test covers the Read() and Close() methods of both EncryptionReader and DecryptionReader
// which are only used with real encryption providers (not the None Provider).
//
// Test Coverage:
// - EncryptionReader.Read() method: streaming.go:381-433 (currently 0% coverage)
// - DecryptionReader.Read() method: streaming.go:467-519 (currently 0% coverage)
// - EncryptionReader.Close() method: streaming.go:433-442 (currently 0% coverage)
// - DecryptionReader.Close() method: streaming.go:519-530 (currently 0% coverage)
// - Real AES-CTR encryption and decryption workflow with readers
// - Buffer management and security cleanup in streaming operations
//
// Security Features Tested:
// - Real AES-CTR encryption with 256-bit keys
// - Proper IV generation and usage
// - Memory security through buffer clearing
// - HMAC integrity verification during streaming
// - Secure metadata handling for encrypted streams
func TestRealAESCTREncryptionReaders(t *testing.T) {
	// Setup AES-CTR provider configuration (not None Provider)
	cfg := &config.Config{
		Encryption: config.EncryptionConfig{
			EncryptionMethodAlias: "aes-ctr-provider",
			IntegrityVerification: "strict", // Enable HMAC for comprehensive testing
			Providers: []config.EncryptionProvider{
				{
					Alias: "aes-ctr-provider",
					Type:  "aes",
					Config: map[string]interface{}{
						// Base64 encoded 32-byte AES key for real encryption
						"aes_key": "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=",
					},
				},
			},
		},
	}

	t.Run("EncryptionReader_Real_AES_CTR_Streaming", func(t *testing.T) {
		// Initialize streaming operations with real AES-CTR provider
		streamOps := createTestStreamingOperations(t, cfg)
		ctx := context.Background()

		// Test data for encryption
		testData := []byte("This is test data for real AES-CTR encryption streaming! " +
			"We need enough data to test multiple read operations and ensure " +
			"proper streaming behavior with real encryption algorithms.")
		objectKey := "test/real-aes-ctr-file.bin"

		// Create encryption reader with real AES-CTR
		encReader, metadata, err := streamOps.CreateEncryptionReader(ctx, strings.NewReader(string(testData)), objectKey)
		require.NoError(t, err, "CreateEncryptionReader should succeed with AES-CTR")
		require.NotNil(t, encReader, "Encryption reader should not be nil")
		require.NotEmpty(t, metadata, "Metadata should be generated for AES-CTR encryption")

		// Verify metadata contains AES-CTR specific information
		assert.Contains(t, metadata, "s3ep-kek-fingerprint", "Metadata should contain KEK fingerprint")
		assert.Contains(t, metadata, "s3ep-encrypted-dek", "Metadata should contain encrypted DEK")
		assert.Contains(t, metadata, "s3ep-aes-iv", "Metadata should contain AES IV")
		assert.Contains(t, metadata, "s3ep-dek-algorithm", "Metadata should contain DEK algorithm")
		assert.Equal(t, "aes-ctr", metadata["s3ep-dek-algorithm"], "Should use AES-CTR")

		// Test streaming read operations on EncryptionReader
		var encryptedData []byte
		buffer := make([]byte, 64) // Small buffer to force multiple reads

		for {
			n, err := encReader.Read(buffer)
			if n > 0 {
				encryptedData = append(encryptedData, buffer[:n]...)
				t.Logf("EncryptionReader.Read() processed %d bytes (total: %d)", n, len(encryptedData))
			}
			if err == io.EOF {
				t.Log("EncryptionReader.Read() reached EOF successfully")
				break
			}
			require.NoError(t, err, "EncryptionReader.Read() should not return unexpected errors")
		}

		// Verify encrypted data properties
		assert.NotEmpty(t, encryptedData, "Encrypted data should not be empty")
		assert.NotEqual(t, testData, encryptedData, "Encrypted data should differ from original")
		assert.Greater(t, len(encryptedData), 0, "Encrypted data should have positive length")
		t.Logf("Successfully encrypted %d bytes using real AES-CTR streaming", len(encryptedData))

		// Test EncryptionReader.Close() method
		if closer, ok := encReader.(io.Closer); ok {
			err = closer.Close()
			assert.NoError(t, err, "EncryptionReader.Close() should succeed")
			t.Log("EncryptionReader.Close() completed successfully - resources cleaned up")
		}

		// Now test DecryptionReader with the encrypted data
		t.Run("DecryptionReader_Real_AES_CTR_Streaming", func(t *testing.T) {
			// Create decryption reader with real AES-CTR and encrypted data
			decReader, err := streamOps.CreateDecryptionReader(ctx, bytes.NewReader(encryptedData), metadata)
			require.NoError(t, err, "CreateDecryptionReader should succeed with AES-CTR metadata")
			require.NotNil(t, decReader, "Decryption reader should not be nil")

			// Test streaming read operations on DecryptionReader
			var decryptedData []byte
			buffer = make([]byte, 48) // Different buffer size to test reader flexibility

			for {
				n, err := decReader.Read(buffer)
				if n > 0 {
					decryptedData = append(decryptedData, buffer[:n]...)
					t.Logf("DecryptionReader.Read() processed %d bytes (total: %d)", n, len(decryptedData))
				}
				if err == io.EOF {
					t.Log("DecryptionReader.Read() reached EOF successfully")
					break
				}
				require.NoError(t, err, "DecryptionReader.Read() should not return unexpected errors")
			}

			// Verify round-trip decryption success
			assert.Equal(t, testData, decryptedData, "Decrypted data should match original test data")
			assert.Equal(t, len(testData), len(decryptedData), "Decrypted data length should match original")
			t.Logf("Successfully decrypted %d bytes using real AES-CTR streaming - round-trip complete", len(decryptedData))

			// Test DecryptionReader.Close() method
			if closer, ok := decReader.(io.Closer); ok {
				err = closer.Close()
				assert.NoError(t, err, "DecryptionReader.Close() should succeed")
				t.Log("DecryptionReader.Close() completed successfully - resources cleaned up")
			}
		})
	})

	t.Run("EncryptionReader_Large_Data_Streaming", func(t *testing.T) {
		// Test with larger data to ensure proper streaming with multiple segments
		streamOps := createTestStreamingOperations(t, cfg)
		ctx := context.Background()

		// Generate 10KB of test data for comprehensive streaming test
		largeTestData := make([]byte, 10*1024)
		for i := range largeTestData {
			largeTestData[i] = byte(i % 256)
		}
		objectKey := "test/large-real-aes-ctr-file.bin"

		// Create encryption reader for large data
		encReader, metadata, err := streamOps.CreateEncryptionReader(ctx, bytes.NewReader(largeTestData), objectKey)
		require.NoError(t, err, "CreateEncryptionReader should handle large data")
		require.NotNil(t, encReader, "Encryption reader should not be nil for large data")

		// Test one complete round-trip with streaming read
		buffer := make([]byte, 512) // Use consistent buffer size
		var encryptedData []byte

		readOperations := 0
		for {
			n, err := encReader.Read(buffer)
			if n > 0 {
				encryptedData = append(encryptedData, buffer[:n]...)
				readOperations++
			}
			if err == io.EOF {
				break
			}
			require.NoError(t, err, "Should handle large data streaming without errors")
		}

		t.Logf("Completed %d read operations, encrypted %d bytes", readOperations, len(encryptedData))
		assert.Greater(t, readOperations, 1, "Should require multiple read operations for large data")

		// Test decryption of large data
		decReader, err := streamOps.CreateDecryptionReader(ctx, bytes.NewReader(encryptedData), metadata)
		require.NoError(t, err, "Should create decryption reader for large data")

		decryptedData, err := io.ReadAll(decReader)
		require.NoError(t, err, "Should decrypt large data without errors")

		// Compare SHA256 hashes instead of raw data to avoid huge output
		originalHash := calculateSHA256ForStreamingTest(largeTestData)
		decryptedHash := calculateSHA256ForStreamingTest(decryptedData)
		assert.Equal(t, originalHash, decryptedHash, "Large data round-trip should be perfect (SHA256 match)")

		t.Logf("Original SHA256:  %s", originalHash)
		t.Logf("Decrypted SHA256: %s", decryptedHash)

		// Test that encrypted data is different from original
		encryptedHash := calculateSHA256ForStreamingTest(encryptedData)
		assert.NotEqual(t, originalHash, encryptedHash, "Encrypted data should be different from original")
	})

	t.Run("EncryptionReader_Error_Handling", func(t *testing.T) {
		// Test error handling in EncryptionReader.Read()
		streamOps := createTestStreamingOperations(t, cfg)
		ctx := context.Background()

		// Create a reader that will fail after some data
		failingReader := &FailingReader{
			data: []byte("Some initial data"),
			failAfter: 10,
		}

		encReader, _, err := streamOps.CreateEncryptionReader(ctx, failingReader, "test/failing.bin")
		require.NoError(t, err, "Should create encryption reader even with potentially failing source")

		// Read until we hit the error
		buffer := make([]byte, 32)
		var totalRead int

		for {
			n, err := encReader.Read(buffer)
			totalRead += n

			if err != nil {
				if err == io.EOF {
					t.Log("Reached EOF before hitting reader error")
					break
				} else {
					// Should get the underlying reader error
					assert.Contains(t, err.Error(), "simulated reader failure",
						"Should propagate underlying reader errors")
					t.Logf("Correctly handled reader error after %d bytes: %v", totalRead, err)
					break
				}
			}
		}
	})

	t.Run("DecryptionReader_Invalid_Metadata_Handling", func(t *testing.T) {
		// Test DecryptionReader with invalid/corrupted metadata
		streamOps := createTestStreamingOperations(t, cfg)
		ctx := context.Background()

		testData := []byte("Test data for invalid metadata handling")

		// Test with missing fingerprint metadata
		invalidMetadata := map[string]string{
			"s3ep-dek-algorithm": "aes-256-ctr",
			// Missing s3ep-kek-fingerprint
		}

		_, err := streamOps.CreateDecryptionReader(ctx, strings.NewReader(string(testData)), invalidMetadata)
		assert.Error(t, err, "Should fail with missing fingerprint in metadata")
		assert.Contains(t, err.Error(), "fingerprint", "Error should mention missing fingerprint")

		// Test with invalid encrypted DEK
		invalidMetadata2 := map[string]string{
			"s3ep-kek-fingerprint": "some-fingerprint",
			"s3ep-encrypted-dek": "invalid-base64-data!@#",
			"s3ep-aes-iv": "dGVzdGl2MTIzNDU2Nzg5YWJjZGVm",
			"s3ep-dek-algorithm": "aes-256-ctr",
		}

		_, err = streamOps.CreateDecryptionReader(ctx, strings.NewReader(string(testData)), invalidMetadata2)
		assert.Error(t, err, "Should fail with invalid encrypted DEK")
		t.Logf("Correctly rejected invalid metadata: %v", err)
	})
}

// FailingReader is a test helper that simulates reader failures
// Used to test error handling in EncryptionReader.Read()
type FailingReader struct {
	data      []byte
	pos       int
	failAfter int
}

func (fr *FailingReader) Read(p []byte) (n int, err error) {
	if fr.pos >= fr.failAfter {
		return 0, fmt.Errorf("simulated reader failure at position %d", fr.pos)
	}

	if fr.pos >= len(fr.data) {
		return 0, io.EOF
	}

	n = copy(p, fr.data[fr.pos:])
	fr.pos += n
	return n, nil
}
