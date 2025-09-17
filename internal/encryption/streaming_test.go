package encryption

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/guided-traffic/s3-encryption-proxy/internal/config"
)

// MockProviderManager is a mock implementation of ProviderManager for testing
type MockProviderManager struct {
	mock.Mock
}

func (m *MockProviderManager) IsNoneProvider() bool {
	args := m.Called()
	return args.Bool(0)
}

func (m *MockProviderManager) GetActiveFingerprint() string {
	args := m.Called()
	return args.String(0)
}

func (m *MockProviderManager) GetActiveProviderAlgorithm() string {
	args := m.Called()
	return args.String(0)
}

// MockHMACManager is a mock implementation of HMACManager for testing
type MockHMACManager struct {
	mock.Mock
}

// MockMetadataManager is a mock implementation of MetadataManager for testing
type MockMetadataManager struct {
	mock.Mock
}

func (m *MockMetadataManager) GetFingerprint(metadata map[string]string) (string, error) {
	args := m.Called(metadata)
	return args.String(0), args.Error(1)
}

func (m *MockMetadataManager) BuildMetadataForEncryption(
	dek []byte,
	encryptedDEK []byte,
	iv []byte,
	algorithm string,
	fingerprint string,
	providerAlgorithm string,
	additionalMetadata map[string]string,
) map[string]string {
	args := m.Called(dek, encryptedDEK, iv, algorithm, fingerprint, providerAlgorithm, additionalMetadata)
	return args.Get(0).(map[string]string)
}

// TestReader implements io.Reader for testing purposes
type TestReader struct {
	data   []byte
	pos    int
	closed bool
	err    error
}

func NewTestReader(data []byte) *TestReader {
	return &TestReader{
		data: data,
		pos:  0,
	}
}

func (tr *TestReader) Read(p []byte) (n int, err error) {
	if tr.closed {
		return 0, errors.New("reader closed")
	}
	if tr.err != nil {
		return 0, tr.err
	}
	if tr.pos >= len(tr.data) {
		return 0, io.EOF
	}

	n = copy(p, tr.data[tr.pos:])
	tr.pos += n
	return n, nil
}

func (tr *TestReader) SetError(err error) {
	tr.err = err
}

func (tr *TestReader) Close() {
	tr.closed = true
}

// SlowTestReader simulates a slow reader for testing timeouts and cancellation
type SlowTestReader struct {
	data       []byte
	pos        int
	delay      time.Duration
	chunkSize  int
}

func NewSlowTestReader(data []byte, delay time.Duration, chunkSize int) *SlowTestReader {
	return &SlowTestReader{
		data:      data,
		pos:       0,
		delay:     delay,
		chunkSize: chunkSize,
	}
}

func (str *SlowTestReader) Read(p []byte) (n int, err error) {
	if str.pos >= len(str.data) {
		return 0, io.EOF
	}

	// Simulate slow reading
	time.Sleep(str.delay)

	// Limit chunk size to simulate slow reader
	readSize := len(p)
	if str.chunkSize > 0 && readSize > str.chunkSize {
		readSize = str.chunkSize
	}

	available := len(str.data) - str.pos
	if readSize > available {
		readSize = available
	}

	n = copy(p[:readSize], str.data[str.pos:str.pos+readSize])
	str.pos += n
	return n, nil
}

// ErrorReader always returns an error after reading some data
type ErrorReader struct {
	data      []byte
	pos       int
	errorAfter int
	err       error
}

func NewErrorReader(data []byte, errorAfter int, err error) *ErrorReader {
	return &ErrorReader{
		data:       data,
		pos:        0,
		errorAfter: errorAfter,
		err:        err,
	}
}

func (er *ErrorReader) Read(p []byte) (n int, err error) {
	if er.pos >= er.errorAfter {
		return 0, er.err
	}

	remaining := er.errorAfter - er.pos
	readSize := len(p)
	if readSize > remaining {
		readSize = remaining
	}

	if er.pos+readSize > len(er.data) {
		readSize = len(er.data) - er.pos
	}

	if readSize <= 0 {
		return 0, er.err
	}

	n = copy(p[:readSize], er.data[er.pos:er.pos+readSize])
	er.pos += n

	if er.pos >= er.errorAfter {
		return n, er.err
	}

	return n, nil
}

// Helper function to create a basic streaming operations instance for testing
func createTestStreamingOperations(t *testing.T) (*StreamingOperations, *MockProviderManager, *MockHMACManager, *MockMetadataManager) {
	providerManager := &MockProviderManager{}
	hmacManager := &MockHMACManager{}
	metadataManager := &MockMetadataManager{}

	config := &config.Config{}

	sop := NewStreamingOperations(providerManager, hmacManager, metadataManager, config)
	require.NotNil(t, sop)

	return sop, providerManager, hmacManager, metadataManager
}

// Test NewStreamingOperations
func TestNewStreamingOperations(t *testing.T) {
	t.Run("successful_creation_with_config", func(t *testing.T) {
		providerManager := &MockProviderManager{}
		hmacManager := &MockHMACManager{}
		metadataManager := &MockMetadataManager{}
		config := &config.Config{}

		sop := NewStreamingOperations(providerManager, hmacManager, metadataManager, config)

		assert.NotNil(t, sop)
		assert.Equal(t, providerManager, sop.providerManager)
		assert.Equal(t, hmacManager, sop.hmacManager)
		assert.Equal(t, metadataManager, sop.metadataManager)
		assert.NotNil(t, sop.bufferPool)
		assert.Equal(t, int64(12*1024*1024), sop.segmentSize) // Default 12MB
		assert.Equal(t, config, sop.config)
		assert.NotNil(t, sop.logger)
	})

	t.Run("creation_with_nil_config", func(t *testing.T) {
		providerManager := &MockProviderManager{}
		hmacManager := &MockHMACManager{}
		metadataManager := &MockMetadataManager{}

		sop := NewStreamingOperations(providerManager, hmacManager, metadataManager, nil)

		assert.NotNil(t, sop)
		assert.Equal(t, int64(12*1024*1024), sop.segmentSize) // Default 12MB
		assert.Nil(t, sop.config)
	})

	t.Run("buffer_pool_functionality", func(t *testing.T) {
		sop, _, _, _ := createTestStreamingOperations(t)

		// Test buffer pool
		buffer1 := sop.getBuffer()
		assert.NotNil(t, buffer1)
		assert.Equal(t, sop.segmentSize, int64(len(buffer1)))

		// Modify buffer and return it
		buffer1[0] = 0xFF
		sop.returnBuffer(buffer1)

		// Get a new buffer - should be cleared
		buffer2 := sop.getBuffer()
		assert.NotNil(t, buffer2)
		assert.Equal(t, byte(0), buffer2[0]) // Should be cleared
	})
}

// Test CreateEncryptionReader
func TestCreateEncryptionReader(t *testing.T) {
	t.Run("successful_creation_with_encryption", func(t *testing.T) {
		sop, providerManager, _, _ := createTestStreamingOperations(t)
		providerManager.On("IsNoneProvider").Return(false)

		testData := "Hello, World!"
		reader := strings.NewReader(testData)
		objectKey := "test-object"

		encReader, metadata, err := sop.CreateEncryptionReader(context.Background(), reader, objectKey)

		assert.NoError(t, err)
		assert.NotNil(t, encReader)
		assert.NotNil(t, metadata)

		// Verify it's an EncryptionReader
		_, ok := encReader.(*EncryptionReader)
		assert.True(t, ok)

		providerManager.AssertExpectations(t)
	})

	t.Run("none_provider_passthrough", func(t *testing.T) {
		sop, providerManager, _, _ := createTestStreamingOperations(t)
		providerManager.On("IsNoneProvider").Return(true)

		testData := "Hello, World!"
		reader := strings.NewReader(testData)
		objectKey := "test-object"

		encReader, metadata, err := sop.CreateEncryptionReader(context.Background(), reader, objectKey)

		assert.NoError(t, err)
		assert.Equal(t, reader, encReader) // Should return original reader
		assert.Nil(t, metadata)

		providerManager.AssertExpectations(t)
	})

	t.Run("context_cancellation", func(t *testing.T) {
		sop, providerManager, _, _ := createTestStreamingOperations(t)
		providerManager.On("IsNoneProvider").Return(false)

		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		testData := "Hello, World!"
		reader := strings.NewReader(testData)
		objectKey := "test-object"

		// Should still create reader even with cancelled context
		encReader, metadata, err := sop.CreateEncryptionReader(ctx, reader, objectKey)

		assert.NoError(t, err)
		assert.NotNil(t, encReader)
		assert.NotNil(t, metadata)

		providerManager.AssertExpectations(t)
	})
}

// Test CreateDecryptionReader
func TestCreateDecryptionReader(t *testing.T) {
	t.Run("successful_creation_with_decryption", func(t *testing.T) {
		sop, _, _, metadataManager := createTestStreamingOperations(t)

		metadata := map[string]string{"fingerprint": "test-fingerprint"}
		metadataManager.On("GetFingerprint", metadata).Return("test-fingerprint", nil)

		testData := "encrypted data"
		reader := strings.NewReader(testData)

		decReader, err := sop.CreateDecryptionReader(context.Background(), reader, metadata)

		assert.NoError(t, err)
		assert.NotNil(t, decReader)

		// Verify it's a DecryptionReader
		_, ok := decReader.(*DecryptionReader)
		assert.True(t, ok)

		metadataManager.AssertExpectations(t)
	})

	t.Run("none_provider_passthrough", func(t *testing.T) {
		sop, _, _, metadataManager := createTestStreamingOperations(t)

		metadata := map[string]string{"fingerprint": "none-provider-fingerprint"}
		metadataManager.On("GetFingerprint", metadata).Return("none-provider-fingerprint", nil)

		testData := "plain data"
		reader := strings.NewReader(testData)

		decReader, err := sop.CreateDecryptionReader(context.Background(), reader, metadata)

		assert.NoError(t, err)
		assert.Equal(t, reader, decReader) // Should return original reader

		metadataManager.AssertExpectations(t)
	})

	t.Run("fingerprint_extraction_error", func(t *testing.T) {
		sop, _, _, metadataManager := createTestStreamingOperations(t)

		metadata := map[string]string{}
		expectedError := errors.New("fingerprint not found")
		metadataManager.On("GetFingerprint", metadata).Return("", expectedError)

		testData := "encrypted data"
		reader := strings.NewReader(testData)

		decReader, err := sop.CreateDecryptionReader(context.Background(), reader, metadata)

		assert.Error(t, err)
		assert.Nil(t, decReader)
		assert.Contains(t, err.Error(), "failed to get fingerprint from metadata")

		metadataManager.AssertExpectations(t)
	})
}

// Test StreamWithSegments
func TestStreamWithSegments(t *testing.T) {
	t.Run("successful_segmented_processing", func(t *testing.T) {
		sop, _, _, _ := createTestStreamingOperations(t)

		// Create test data larger than segment size
		testData := make([]byte, sop.segmentSize*2+100)
		for i := range testData {
			testData[i] = byte(i % 256)
		}

		reader := bytes.NewReader(testData)

		var processedSegments [][]byte
		segmentCallback := func(segment []byte) error {
			// Make a copy since the buffer is reused
			segmentCopy := make([]byte, len(segment))
			copy(segmentCopy, segment)
			processedSegments = append(processedSegments, segmentCopy)
			return nil
		}

		err := sop.StreamWithSegments(context.Background(), reader, segmentCallback)

		assert.NoError(t, err)
		assert.Equal(t, 3, len(processedSegments)) // Should have 3 segments

		// Verify all data was processed
		var reassembledData []byte
		for _, segment := range processedSegments {
			reassembledData = append(reassembledData, segment...)
		}
		assert.Equal(t, testData, reassembledData)
	})

	t.Run("empty_stream", func(t *testing.T) {
		sop, _, _, _ := createTestStreamingOperations(t)

		reader := strings.NewReader("")

		segmentCount := 0
		segmentCallback := func(segment []byte) error {
			segmentCount++
			return nil
		}

		err := sop.StreamWithSegments(context.Background(), reader, segmentCallback)

		assert.NoError(t, err)
		assert.Equal(t, 0, segmentCount)
	})

	t.Run("callback_error", func(t *testing.T) {
		sop, _, _, _ := createTestStreamingOperations(t)

		testData := "Hello, World!"
		reader := strings.NewReader(testData)

		expectedError := errors.New("callback error")
		segmentCallback := func(segment []byte) error {
			return expectedError
		}

		err := sop.StreamWithSegments(context.Background(), reader, segmentCallback)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to process segment")
	})

	t.Run("context_cancellation", func(t *testing.T) {
		sop, _, _, _ := createTestStreamingOperations(t)

		// Create a slow reader with delays
		testData := make([]byte, 1000)
		reader := NewSlowTestReader(testData, 100*time.Millisecond, 10)

		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()

		segmentCallback := func(segment []byte) error {
			return nil
		}

		err := sop.StreamWithSegments(ctx, reader, segmentCallback)

		assert.Error(t, err)
		assert.Equal(t, context.DeadlineExceeded, err)
	})

	t.Run("reader_error", func(t *testing.T) {
		sop, _, _, _ := createTestStreamingOperations(t)

		testData := make([]byte, 100)
		expectedError := errors.New("reader error")
		reader := NewErrorReader(testData, 50, expectedError)

		segmentCallback := func(segment []byte) error {
			return nil
		}

		err := sop.StreamWithSegments(context.Background(), reader, segmentCallback)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to read from stream")
	})

	t.Run("exact_segment_size", func(t *testing.T) {
		sop, _, _, _ := createTestStreamingOperations(t)

		// Create test data exactly matching segment size
		testData := make([]byte, sop.segmentSize)
		for i := range testData {
			testData[i] = byte(i % 256)
		}

		reader := bytes.NewReader(testData)

		var processedSegments [][]byte
		segmentCallback := func(segment []byte) error {
			segmentCopy := make([]byte, len(segment))
			copy(segmentCopy, segment)
			processedSegments = append(processedSegments, segmentCopy)
			return nil
		}

		err := sop.StreamWithSegments(context.Background(), reader, segmentCallback)

		assert.NoError(t, err)
		assert.Equal(t, 1, len(processedSegments)) // Should have exactly 1 segment
		assert.Equal(t, testData, processedSegments[0])
	})
}

// Test GetSegmentSize
func TestGetSegmentSize(t *testing.T) {
	t.Run("returns_configured_segment_size", func(t *testing.T) {
		sop, _, _, _ := createTestStreamingOperations(t)

		segmentSize := sop.GetSegmentSize()

		assert.Equal(t, sop.segmentSize, segmentSize)
		assert.Equal(t, int64(12*1024*1024), segmentSize) // Default 12MB
	})
}

// Test buffer pool methods
func TestBufferPool(t *testing.T) {
	t.Run("buffer_reuse", func(t *testing.T) {
		sop, _, _, _ := createTestStreamingOperations(t)

		// Get multiple buffers
		buffer1 := sop.getBuffer()
		buffer2 := sop.getBuffer()

		assert.NotNil(t, buffer1)
		assert.NotNil(t, buffer2)
		assert.Equal(t, int(sop.segmentSize), len(buffer1))
		assert.Equal(t, int(sop.segmentSize), len(buffer2))

		// Modify buffers
		buffer1[0] = 0xAA
		buffer2[0] = 0xBB

		// Return buffers
		sop.returnBuffer(buffer1)
		sop.returnBuffer(buffer2)

		// Get buffers again - they should be cleared
		buffer3 := sop.getBuffer()
		buffer4 := sop.getBuffer()

		assert.Equal(t, byte(0), buffer3[0])
		assert.Equal(t, byte(0), buffer4[0])
	})

	t.Run("buffer_clearing_security", func(t *testing.T) {
		sop, _, _, _ := createTestStreamingOperations(t)

		buffer := sop.getBuffer()

		// Fill buffer with sensitive data
		for i := range buffer {
			buffer[i] = 0xFF
		}

		// Return buffer
		sop.returnBuffer(buffer)

		// Get buffer again and verify it's cleared
		newBuffer := sop.getBuffer()
		for i := range newBuffer {
			assert.Equal(t, byte(0), newBuffer[i], "Buffer should be cleared for security")
		}
	})

	t.Run("concurrent_buffer_access", func(t *testing.T) {
		sop, _, _, _ := createTestStreamingOperations(t)

		const numGoroutines = 10
		const operationsPerGoroutine = 100

		var wg sync.WaitGroup
		wg.Add(numGoroutines)

		for i := 0; i < numGoroutines; i++ {
			go func() {
				defer wg.Done()
				for j := 0; j < operationsPerGoroutine; j++ {
					buffer := sop.getBuffer()
					assert.NotNil(t, buffer)
					assert.Equal(t, int(sop.segmentSize), len(buffer))

					// Simulate some work
					buffer[0] = byte(j)

					sop.returnBuffer(buffer)
				}
			}()
		}

		wg.Wait()
	})
}

// Test EncryptionReader
func TestEncryptionReader(t *testing.T) {
	t.Run("successful_read", func(t *testing.T) {
		testData := "Hello, World! This is a test message for encryption."
		reader := strings.NewReader(testData)

		encReader := &EncryptionReader{
			reader:   reader,
			buffer:   make([]byte, 1024),
			metadata: make(map[string]string),
			logger:   logrus.NewEntry(logrus.StandardLogger()),
		}

		buffer := make([]byte, 20)
		n, err := encReader.Read(buffer)

		assert.NoError(t, err)
		assert.Equal(t, 20, n)
		assert.Equal(t, []byte("Hello, World! This i"), buffer)
		assert.False(t, encReader.finished)
	})

	t.Run("read_until_eof", func(t *testing.T) {
		testData := "Short"
		reader := strings.NewReader(testData)

		encReader := &EncryptionReader{
			reader:   reader,
			buffer:   make([]byte, 1024),
			metadata: make(map[string]string),
			logger:   logrus.NewEntry(logrus.StandardLogger()),
		}

		buffer := make([]byte, 10)
		n, err := encReader.Read(buffer)

		assert.Equal(t, io.EOF, err)
		assert.Equal(t, 5, n)
		assert.Equal(t, []byte("Short"), buffer[:n])
		assert.True(t, encReader.finished)

		// Subsequent reads should return EOF
		n, err = encReader.Read(buffer)
		assert.Equal(t, io.EOF, err)
		assert.Equal(t, 0, n)
	})

	t.Run("reader_error", func(t *testing.T) {
		testData := "Hello"
		expectedError := errors.New("reader error")
		reader := NewErrorReader([]byte(testData), 3, expectedError)

		encReader := &EncryptionReader{
			reader:   reader,
			buffer:   make([]byte, 1024),
			metadata: make(map[string]string),
			logger:   logrus.NewEntry(logrus.StandardLogger()),
		}

		// First read should succeed
		buffer := make([]byte, 10)
		n, err := encReader.Read(buffer)
		assert.NoError(t, err)
		assert.Equal(t, 3, n)

		// Second read should return error
		n, err = encReader.Read(buffer)
		assert.Error(t, err)
		assert.Equal(t, expectedError, err)
	})

	t.Run("multiple_reads", func(t *testing.T) {
		testData := "Hello, World! This is a longer test message."
		reader := strings.NewReader(testData)

		encReader := &EncryptionReader{
			reader:   reader,
			buffer:   make([]byte, 1024),
			metadata: make(map[string]string),
			logger:   logrus.NewEntry(logrus.StandardLogger()),
		}

		var result []byte
		buffer := make([]byte, 10)

		for {
			n, err := encReader.Read(buffer)
			if n > 0 {
				result = append(result, buffer[:n]...)
			}
			if err == io.EOF {
				break
			}
			assert.NoError(t, err)
		}

		assert.Equal(t, testData, string(result))
	})
}

// Test DecryptionReader
func TestDecryptionReader(t *testing.T) {
	t.Run("successful_read", func(t *testing.T) {
		testData := "Encrypted data that should be decrypted."
		reader := strings.NewReader(testData)

		decReader := &DecryptionReader{
			reader: reader,
			buffer: make([]byte, 1024),
			logger: logrus.NewEntry(logrus.StandardLogger()),
		}

		buffer := make([]byte, 20)
		n, err := decReader.Read(buffer)

		assert.NoError(t, err)
		assert.Equal(t, 20, n)
		assert.Equal(t, []byte("Encrypted data that "), buffer)
		assert.False(t, decReader.finished)
	})

	t.Run("read_until_eof", func(t *testing.T) {
		testData := "Short"
		reader := strings.NewReader(testData)

		decReader := &DecryptionReader{
			reader: reader,
			buffer: make([]byte, 1024),
			logger: logrus.NewEntry(logrus.StandardLogger()),
		}

		buffer := make([]byte, 10)
		n, err := decReader.Read(buffer)

		assert.Equal(t, io.EOF, err)
		assert.Equal(t, 5, n)
		assert.Equal(t, []byte("Short"), buffer[:n])
		assert.True(t, decReader.finished)

		// Subsequent reads should return EOF
		n, err = decReader.Read(buffer)
		assert.Equal(t, io.EOF, err)
		assert.Equal(t, 0, n)
	})

	t.Run("reader_error", func(t *testing.T) {
		testData := "Hello"
		expectedError := errors.New("reader error")
		reader := NewErrorReader([]byte(testData), 3, expectedError)

		decReader := &DecryptionReader{
			reader: reader,
			buffer: make([]byte, 1024),
			logger: logrus.NewEntry(logrus.StandardLogger()),
		}

		// First read should succeed
		buffer := make([]byte, 10)
		n, err := decReader.Read(buffer)
		assert.NoError(t, err)
		assert.Equal(t, 3, n)

		// Second read should return error
		n, err = decReader.Read(buffer)
		assert.Error(t, err)
		assert.Equal(t, expectedError, err)
	})
}

// Test EncryptStream
func TestEncryptStream(t *testing.T) {
	t.Run("successful_encryption", func(t *testing.T) {
		sop, providerManager, _, metadataManager := createTestStreamingOperations(t)

		providerManager.On("IsNoneProvider").Return(false)
		providerManager.On("GetActiveFingerprint").Return("test-fingerprint")
		providerManager.On("GetActiveProviderAlgorithm").Return("aes-256-ctr")

		expectedMetadata := map[string]string{
			"algorithm": "aes-ctr",
			"fingerprint": "test-fingerprint",
		}
		metadataManager.On("BuildMetadataForEncryption",
			mock.Anything, mock.Anything, mock.Anything,
			"aes-ctr", "test-fingerprint", "aes-256-ctr", mock.Anything).Return(expectedMetadata)

		testData := "Hello, World! This is test data for encryption."
		reader := strings.NewReader(testData)
		objectKey := "test-object"

		encryptedData, metadata, err := sop.EncryptStream(context.Background(), reader, objectKey)

		assert.NoError(t, err)
		assert.Equal(t, []byte(testData), encryptedData) // Currently passes through
		assert.Equal(t, expectedMetadata, metadata)

		providerManager.AssertExpectations(t)
		metadataManager.AssertExpectations(t)
	})

	t.Run("none_provider_passthrough", func(t *testing.T) {
		sop, providerManager, _, _ := createTestStreamingOperations(t)

		providerManager.On("IsNoneProvider").Return(true)

		testData := "Hello, World!"
		reader := strings.NewReader(testData)
		objectKey := "test-object"

		encryptedData, metadata, err := sop.EncryptStream(context.Background(), reader, objectKey)

		assert.NoError(t, err)
		assert.Equal(t, []byte(testData), encryptedData)
		assert.Nil(t, metadata)

		providerManager.AssertExpectations(t)
	})

	t.Run("reader_error", func(t *testing.T) {
		sop, _, _, _ := createTestStreamingOperations(t)

		expectedError := errors.New("reader error")
		reader := &TestReader{err: expectedError}

		encryptedData, metadata, err := sop.EncryptStream(context.Background(), reader, "test-object")

		assert.Error(t, err)
		assert.Nil(t, encryptedData)
		assert.Nil(t, metadata)
		assert.Contains(t, err.Error(), "failed to read stream")
	})

	t.Run("large_stream", func(t *testing.T) {
		sop, providerManager, _, metadataManager := createTestStreamingOperations(t)

		providerManager.On("IsNoneProvider").Return(false)
		providerManager.On("GetActiveFingerprint").Return("test-fingerprint")
		providerManager.On("GetActiveProviderAlgorithm").Return("aes-256-ctr")

		expectedMetadata := map[string]string{"algorithm": "aes-ctr"}
		metadataManager.On("BuildMetadataForEncryption",
			mock.Anything, mock.Anything, mock.Anything,
			mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(expectedMetadata)

		// Create large test data
		testData := make([]byte, 5*1024*1024) // 5MB
		for i := range testData {
			testData[i] = byte(i % 256)
		}

		reader := bytes.NewReader(testData)
		objectKey := "large-test-object"

		encryptedData, metadata, err := sop.EncryptStream(context.Background(), reader, objectKey)

		assert.NoError(t, err)
		assert.Equal(t, testData, encryptedData)
		assert.Equal(t, expectedMetadata, metadata)

		providerManager.AssertExpectations(t)
		metadataManager.AssertExpectations(t)
	})
}

// Test DecryptStream
func TestDecryptStream(t *testing.T) {
	t.Run("successful_decryption", func(t *testing.T) {
		sop, _, _, metadataManager := createTestStreamingOperations(t)

		metadata := map[string]string{"fingerprint": "test-fingerprint"}
		metadataManager.On("GetFingerprint", metadata).Return("test-fingerprint", nil)

		testData := "Encrypted data to be decrypted"
		reader := strings.NewReader(testData)

		decryptedData, err := sop.DecryptStream(context.Background(), reader, metadata)

		assert.NoError(t, err)
		assert.Equal(t, []byte(testData), decryptedData) // Currently passes through

		metadataManager.AssertExpectations(t)
	})

	t.Run("none_provider_passthrough", func(t *testing.T) {
		sop, _, _, metadataManager := createTestStreamingOperations(t)

		metadata := map[string]string{"fingerprint": "none-provider-fingerprint"}
		metadataManager.On("GetFingerprint", metadata).Return("none-provider-fingerprint", nil)

		testData := "Plain data"
		reader := strings.NewReader(testData)

		decryptedData, err := sop.DecryptStream(context.Background(), reader, metadata)

		assert.NoError(t, err)
		assert.Equal(t, []byte(testData), decryptedData)

		metadataManager.AssertExpectations(t)
	})

	t.Run("fingerprint_extraction_error", func(t *testing.T) {
		sop, _, _, metadataManager := createTestStreamingOperations(t)

		metadata := map[string]string{}
		expectedError := errors.New("fingerprint not found")
		metadataManager.On("GetFingerprint", metadata).Return("", expectedError)

		testData := "Encrypted data"
		reader := strings.NewReader(testData)

		decryptedData, err := sop.DecryptStream(context.Background(), reader, metadata)

		assert.Error(t, err)
		assert.Nil(t, decryptedData)
		assert.Contains(t, err.Error(), "failed to get fingerprint from metadata")

		metadataManager.AssertExpectations(t)
	})

	t.Run("reader_error", func(t *testing.T) {
		sop, _, _, metadataManager := createTestStreamingOperations(t)

		metadata := map[string]string{"fingerprint": "test-fingerprint"}
		metadataManager.On("GetFingerprint", metadata).Return("test-fingerprint", nil)

		expectedError := errors.New("reader error")
		reader := &TestReader{err: expectedError}

		decryptedData, err := sop.DecryptStream(context.Background(), reader, metadata)

		assert.Error(t, err)
		assert.Nil(t, decryptedData)
		assert.Contains(t, err.Error(), "failed to read stream")

		metadataManager.AssertExpectations(t)
	})
}

// Test StreamEncryptWithCallback
func TestStreamEncryptWithCallback(t *testing.T) {
	t.Run("successful_encryption_with_callback", func(t *testing.T) {
		sop, _, _, _ := createTestStreamingOperations(t)

		testData := "Hello, World! This is test data for callback encryption."
		reader := strings.NewReader(testData)
		objectKey := "test-object"

		var receivedSegments [][]byte
		callback := func(encryptedData []byte, isLastSegment bool) error {
			segmentCopy := make([]byte, len(encryptedData))
			copy(segmentCopy, encryptedData)
			receivedSegments = append(receivedSegments, segmentCopy)
			return nil
		}

		metadata, err := sop.StreamEncryptWithCallback(context.Background(), reader, objectKey, callback)

		assert.NoError(t, err)
		assert.NotNil(t, metadata)
		assert.Equal(t, 1, len(receivedSegments))
		assert.Equal(t, []byte(testData), receivedSegments[0])
	})

	t.Run("callback_error", func(t *testing.T) {
		sop, _, _, _ := createTestStreamingOperations(t)

		testData := "Hello, World!"
		reader := strings.NewReader(testData)
		objectKey := "test-object"

		expectedError := errors.New("callback error")
		callback := func(encryptedData []byte, isLastSegment bool) error {
			return expectedError
		}

		metadata, err := sop.StreamEncryptWithCallback(context.Background(), reader, objectKey, callback)

		assert.Error(t, err)
		assert.Nil(t, metadata)
		assert.Contains(t, err.Error(), "failed to process segment")
	})

	t.Run("multiple_segments", func(t *testing.T) {
		sop, _, _, _ := createTestStreamingOperations(t)

		// Create test data larger than segment size
		testData := make([]byte, sop.segmentSize*2+100)
		for i := range testData {
			testData[i] = byte(i % 256)
		}

		reader := bytes.NewReader(testData)
		objectKey := "large-test-object"

		var receivedSegments [][]byte
		callback := func(encryptedData []byte, isLastSegment bool) error {
			segmentCopy := make([]byte, len(encryptedData))
			copy(segmentCopy, encryptedData)
			receivedSegments = append(receivedSegments, segmentCopy)
			return nil
		}

		metadata, err := sop.StreamEncryptWithCallback(context.Background(), reader, objectKey, callback)

		assert.NoError(t, err)
		assert.NotNil(t, metadata)
		assert.Equal(t, 3, len(receivedSegments)) // Should have 3 segments

		// Verify all data was processed
		var reassembledData []byte
		for _, segment := range receivedSegments {
			reassembledData = append(reassembledData, segment...)
		}
		assert.Equal(t, testData, reassembledData)
	})

	t.Run("empty_stream", func(t *testing.T) {
		sop, _, _, _ := createTestStreamingOperations(t)

		reader := strings.NewReader("")
		objectKey := "empty-object"

		callbackCalled := false
		callback := func(encryptedData []byte, isLastSegment bool) error {
			callbackCalled = true
			return nil
		}

		metadata, err := sop.StreamEncryptWithCallback(context.Background(), reader, objectKey, callback)

		assert.NoError(t, err)
		assert.NotNil(t, metadata)
		assert.False(t, callbackCalled)
	})
}

// Test StreamDecryptWithCallback
func TestStreamDecryptWithCallback(t *testing.T) {
	t.Run("successful_decryption_with_callback", func(t *testing.T) {
		sop, _, _, metadataManager := createTestStreamingOperations(t)

		metadata := map[string]string{"fingerprint": "test-fingerprint"}
		metadataManager.On("GetFingerprint", metadata).Return("test-fingerprint", nil)

		testData := "Encrypted data for callback decryption."
		reader := strings.NewReader(testData)

		var receivedSegments [][]byte
		callback := func(decryptedData []byte, isLastSegment bool) error {
			segmentCopy := make([]byte, len(decryptedData))
			copy(segmentCopy, decryptedData)
			receivedSegments = append(receivedSegments, segmentCopy)
			return nil
		}

		err := sop.StreamDecryptWithCallback(context.Background(), reader, metadata, callback)

		assert.NoError(t, err)
		assert.Equal(t, 1, len(receivedSegments))
		assert.Equal(t, []byte(testData), receivedSegments[0])

		metadataManager.AssertExpectations(t)
	})

	t.Run("callback_error", func(t *testing.T) {
		sop, _, _, _ := createTestStreamingOperations(t)

		metadata := map[string]string{}
		testData := "Encrypted data"
		reader := strings.NewReader(testData)

		expectedError := errors.New("callback error")
		callback := func(decryptedData []byte, isLastSegment bool) error {
			return expectedError
		}

		err := sop.StreamDecryptWithCallback(context.Background(), reader, metadata, callback)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to process segment")
	})

	t.Run("multiple_segments", func(t *testing.T) {
		sop, _, _, _ := createTestStreamingOperations(t)

		metadata := map[string]string{}

		// Create test data larger than segment size
		testData := make([]byte, sop.segmentSize*2+100)
		for i := range testData {
			testData[i] = byte(i % 256)
		}

		reader := bytes.NewReader(testData)

		var receivedSegments [][]byte
		callback := func(decryptedData []byte, isLastSegment bool) error {
			segmentCopy := make([]byte, len(decryptedData))
			copy(segmentCopy, decryptedData)
			receivedSegments = append(receivedSegments, segmentCopy)
			return nil
		}

		err := sop.StreamDecryptWithCallback(context.Background(), reader, metadata, callback)

		assert.NoError(t, err)
		assert.Equal(t, 3, len(receivedSegments)) // Should have 3 segments

		// Verify all data was processed
		var reassembledData []byte
		for _, segment := range receivedSegments {
			reassembledData = append(reassembledData, segment...)
		}
		assert.Equal(t, testData, reassembledData)
	})
}

// Integration tests
func TestStreamingOperationsIntegration(t *testing.T) {
	t.Run("encrypt_then_decrypt_roundtrip", func(t *testing.T) {
		sop, providerManager, _, metadataManager := createTestStreamingOperations(t)

		// Setup mocks for encryption
		providerManager.On("IsNoneProvider").Return(false)
		providerManager.On("GetActiveFingerprint").Return("test-fingerprint")
		providerManager.On("GetActiveProviderAlgorithm").Return("aes-256-ctr")

		expectedMetadata := map[string]string{
			"algorithm": "aes-ctr",
			"fingerprint": "test-fingerprint",
		}
		metadataManager.On("BuildMetadataForEncryption",
			mock.Anything, mock.Anything, mock.Anything,
			"aes-ctr", "test-fingerprint", "aes-256-ctr", mock.Anything).Return(expectedMetadata)

		// Setup mocks for decryption
		metadataManager.On("GetFingerprint", expectedMetadata).Return("test-fingerprint", nil)

		originalData := "Hello, World! This is a test message for roundtrip encryption/decryption."

		// Encrypt
		encryptReader := strings.NewReader(originalData)
		encryptedData, metadata, err := sop.EncryptStream(context.Background(), encryptReader, "test-object")
		require.NoError(t, err)
		require.NotNil(t, metadata)

		// Decrypt
		decryptReader := bytes.NewReader(encryptedData)
		decryptedData, err := sop.DecryptStream(context.Background(), decryptReader, metadata)
		require.NoError(t, err)

		assert.Equal(t, originalData, string(decryptedData))

		providerManager.AssertExpectations(t)
		metadataManager.AssertExpectations(t)
	})

	t.Run("streaming_reader_roundtrip", func(t *testing.T) {
		sop, providerManager, _, metadataManager := createTestStreamingOperations(t)

		providerManager.On("IsNoneProvider").Return(false)
		metadataManager.On("GetFingerprint", mock.Anything).Return("test-fingerprint", nil)

		originalData := "This is test data for streaming reader roundtrip."

		// Create encryption reader
		encryptReader := strings.NewReader(originalData)
		streamingEncReader, metadata, err := sop.CreateEncryptionReader(context.Background(), encryptReader, "test-object")
		require.NoError(t, err)

		// Read encrypted data
		var encryptedData []byte
		buffer := make([]byte, 10)
		for {
			n, err := streamingEncReader.Read(buffer)
			if n > 0 {
				encryptedData = append(encryptedData, buffer[:n]...)
			}
			if err == io.EOF {
				break
			}
			require.NoError(t, err)
		}

		// Create decryption reader
		decryptReader := bytes.NewReader(encryptedData)
		streamingDecReader, err := sop.CreateDecryptionReader(context.Background(), decryptReader, metadata)
		require.NoError(t, err)

		// Read decrypted data
		var decryptedData []byte
		for {
			n, err := streamingDecReader.Read(buffer)
			if n > 0 {
				decryptedData = append(decryptedData, buffer[:n]...)
			}
			if err == io.EOF {
				break
			}
			require.NoError(t, err)
		}

		assert.Equal(t, originalData, string(decryptedData))

		providerManager.AssertExpectations(t)
		metadataManager.AssertExpectations(t)
	})
}

// Benchmark tests
func BenchmarkStreamingOperations(b *testing.B) {
	sop, providerManager, _, metadataManager := createTestStreamingOperations(&testing.T{})

	providerManager.On("IsNoneProvider").Return(false)
	providerManager.On("GetActiveFingerprint").Return("test-fingerprint")
	providerManager.On("GetActiveProviderAlgorithm").Return("aes-256-ctr")

	expectedMetadata := map[string]string{"algorithm": "aes-ctr"}
	metadataManager.On("BuildMetadataForEncryption",
		mock.Anything, mock.Anything, mock.Anything,
		mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(expectedMetadata)

	testData := make([]byte, 1024*1024) // 1MB
	for i := range testData {
		testData[i] = byte(i % 256)
	}

	b.Run("EncryptStream", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			reader := bytes.NewReader(testData)
			_, _, err := sop.EncryptStream(context.Background(), reader, "bench-object")
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("StreamWithSegments", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			reader := bytes.NewReader(testData)
			err := sop.StreamWithSegments(context.Background(), reader, func(segment []byte) error {
				// Simulate some processing
				_ = len(segment)
				return nil
			})
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("BufferPoolOperations", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			buffer := sop.getBuffer()
			// Simulate some work
			buffer[0] = byte(i)
			sop.returnBuffer(buffer)
		}
	})
}

// Error handling tests
func TestStreamingOperationsErrorHandling(t *testing.T) {
	t.Run("nil_reader", func(t *testing.T) {
		sop, _, _, _ := createTestStreamingOperations(t)

		err := sop.StreamWithSegments(context.Background(), nil, func(segment []byte) error {
			return nil
		})

		assert.Error(t, err)
	})

	t.Run("nil_callback", func(t *testing.T) {
		sop, _, _, _ := createTestStreamingOperations(t)

		reader := strings.NewReader("test data")

		// This should panic or handle gracefully
		assert.Panics(t, func() {
			_ = sop.StreamWithSegments(context.Background(), reader, nil)
		})
	})

	t.Run("context_timeout_during_processing", func(t *testing.T) {
		sop, _, _, _ := createTestStreamingOperations(t)

		testData := make([]byte, 100)
		reader := bytes.NewReader(testData)

		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
		defer cancel()

		callbackDelay := 10 * time.Millisecond
		callback := func(segment []byte) error {
			time.Sleep(callbackDelay) // Simulate slow processing
			return nil
		}

		err := sop.StreamWithSegments(ctx, reader, callback)

		assert.Error(t, err)
		assert.Equal(t, context.DeadlineExceeded, err)
	})
}

// Concurrent access tests
func TestStreamingOperationsConcurrency(t *testing.T) {
	t.Run("concurrent_stream_processing", func(t *testing.T) {
		sop, _, _, _ := createTestStreamingOperations(t)

		const numGoroutines = 10
		const dataSize = 1024

		var wg sync.WaitGroup
		wg.Add(numGoroutines)

		errors := make(chan error, numGoroutines)

		for i := 0; i < numGoroutines; i++ {
			go func(id int) {
				defer wg.Done()

				testData := make([]byte, dataSize)
				for j := range testData {
					testData[j] = byte((id + j) % 256)
				}

				reader := bytes.NewReader(testData)

				var processedData []byte
				err := sop.StreamWithSegments(context.Background(), reader, func(segment []byte) error {
					processedData = append(processedData, segment...)
					return nil
				})

				if err != nil {
					errors <- err
					return
				}

				if !bytes.Equal(testData, processedData) {
					errors <- errors.New("data mismatch")
				}
			}(i)
		}

		wg.Wait()
		close(errors)

		for err := range errors {
			assert.NoError(t, err)
		}
	})

	t.Run("concurrent_reader_creation", func(t *testing.T) {
		sop, providerManager, _, _ := createTestStreamingOperations(t)

		providerManager.On("IsNoneProvider").Return(false).Maybe()

		const numGoroutines = 10

		var wg sync.WaitGroup
		wg.Add(numGoroutines * 2) // For both encryption and decryption readers

		errors := make(chan error, numGoroutines*2)

		// Test concurrent encryption reader creation
		for i := 0; i < numGoroutines; i++ {
			go func(id int) {
				defer wg.Done()

				reader := strings.NewReader("test data")
				_, _, err := sop.CreateEncryptionReader(context.Background(), reader, "test-object")
				if err != nil {
					errors <- err
				}
			}(i)
		}

		// Test concurrent decryption reader creation
		for i := 0; i < numGoroutines; i++ {
			go func(id int) {
				defer wg.Done()

				reader := strings.NewReader("encrypted data")
				metadata := map[string]string{"fingerprint": "none-provider-fingerprint"}
				_, err := sop.CreateDecryptionReader(context.Background(), reader, metadata)
				if err != nil {
					errors <- err
				}
			}(i)
		}

		wg.Wait()
		close(errors)

		for err := range errors {
			assert.NoError(t, err)
		}

		providerManager.AssertExpectations(t)
	})
}
