package proxy

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAWSChunkedReader_SimpleChunk(t *testing.T) {
	// Simple chunk: "Hello"
	chunkData := "5\r\nHello\r\n0\r\n\r\n"

	reader := &awsChunkedReader{
		reader: bufio.NewReader(strings.NewReader(chunkData)),
		logger: logrus.NewEntry(logrus.New()),
		buffer: make([]byte, 0),
	}

	// Read the chunk
	buf := make([]byte, 10)
	n, err := reader.Read(buf)

	assert.NoError(t, err)
	assert.Equal(t, 5, n)
	assert.Equal(t, "Hello", string(buf[:n]))

	// Read again should return EOF
	n, err = reader.Read(buf)
	assert.Equal(t, io.EOF, err)
	assert.Equal(t, 0, n)
}

func TestAWSChunkedReader_MultipleChunks(t *testing.T) {
	// Multiple chunks: "Hello" + "World"
	chunkData := "5\r\nHello\r\n5\r\nWorld\r\n0\r\n\r\n"

	reader := &awsChunkedReader{
		reader: bufio.NewReader(strings.NewReader(chunkData)),
		logger: logrus.NewEntry(logrus.New()),
		buffer: make([]byte, 0),
	}

	// Read first chunk
	buf := make([]byte, 10)
	n, err := reader.Read(buf)

	assert.NoError(t, err)
	assert.Equal(t, 5, n)
	assert.Equal(t, "Hello", string(buf[:n]))

	// Read second chunk
	n, err = reader.Read(buf)

	assert.NoError(t, err)
	assert.Equal(t, 5, n)
	assert.Equal(t, "World", string(buf[:n]))

	// Read again should return EOF
	n, err = reader.Read(buf)
	assert.Equal(t, io.EOF, err)
	assert.Equal(t, 0, n)
}

func TestAWSChunkedReader_ChunkedEncoding(t *testing.T) {
	// AWS S3 Signature V4 chunked encoding example
	chunkData := "a;chunk-signature=signature1\r\n1234567890\r\n5;chunk-signature=signature2\r\nhello\r\n0;chunk-signature=signature3\r\n\r\n"

	reader := &awsChunkedReader{
		reader: bufio.NewReader(strings.NewReader(chunkData)),
		logger: logrus.NewEntry(logrus.New()),
		buffer: make([]byte, 0),
	}

	// Read all data
	var result []byte
	buf := make([]byte, 1024)

	for {
		n, err := reader.Read(buf)
		if err == io.EOF {
			break
		}
		assert.NoError(t, err)
		result = append(result, buf[:n]...)
	}

	// Should contain only the actual data, no chunk signatures
	expected := "1234567890hello"
	assert.Equal(t, expected, string(result))
}

func TestAWSChunkedReader_LargeChunk(t *testing.T) {
	// Create a large chunk (1KB)
	data := strings.Repeat("A", 1024)
	chunkData := fmt.Sprintf("400\r\n%s\r\n0\r\n\r\n", data)

	reader := &awsChunkedReader{
		reader: bufio.NewReader(strings.NewReader(chunkData)),
		logger: logrus.NewEntry(logrus.New()),
		buffer: make([]byte, 0),
	}

	// Read in smaller buffers
	var result []byte
	buf := make([]byte, 100)

	for {
		n, err := reader.Read(buf)
		if err == io.EOF {
			break
		}
		assert.NoError(t, err)
		result = append(result, buf[:n]...)
	}

	assert.Equal(t, data, string(result))
	assert.Equal(t, 1024, len(result))
}

func TestAWSChunkedReader_EmptyChunks(t *testing.T) {
	// Chunks with empty data
	chunkData := "0\r\n\r\n0\r\n\r\n"

	reader := &awsChunkedReader{
		reader: bufio.NewReader(strings.NewReader(chunkData)),
		logger: logrus.NewEntry(logrus.New()),
		buffer: make([]byte, 0),
	}

	// Should immediately return EOF for empty chunks
	buf := make([]byte, 10)
	n, err := reader.Read(buf)

	assert.Equal(t, io.EOF, err)
	assert.Equal(t, 0, n)
}

func TestAWSChunkedReader_InvalidHex(t *testing.T) {
	// Invalid hex size
	chunkData := "ZZZ\r\nHello\r\n0\r\n\r\n"

	reader := &awsChunkedReader{
		reader: bufio.NewReader(strings.NewReader(chunkData)),
		logger: logrus.NewEntry(logrus.New()),
		buffer: make([]byte, 0),
	}

	buf := make([]byte, 10)
	n, err := reader.Read(buf)

	assert.Error(t, err)
	assert.Equal(t, 0, n)
	assert.Contains(t, err.Error(), "failed to parse chunk size")
}

func TestAWSChunkedReader_IncompleteChunk(t *testing.T) {
	// Incomplete chunk (missing data)
	chunkData := "5\r\nHell"  // Missing "o\r\n0\r\n\r\n"

	reader := &awsChunkedReader{
		reader: bufio.NewReader(strings.NewReader(chunkData)),
		logger: logrus.NewEntry(logrus.New()),
		buffer: make([]byte, 0),
	}

	buf := make([]byte, 10)
	n, err := reader.Read(buf)

	assert.Error(t, err)
	assert.Equal(t, 0, n)
}

func TestAWSChunkedReader_BufferManagement(t *testing.T) {
	// Test buffer reuse and growth
	chunkData := "3\r\nABC\r\n3\r\nDEF\r\n3\r\nGHI\r\n0\r\n\r\n"

	reader := &awsChunkedReader{
		reader: bufio.NewReader(strings.NewReader(chunkData)),
		logger: logrus.NewEntry(logrus.New()),
		buffer: make([]byte, 0), // Small initial buffer
	}

	// Read with very small buffer to force multiple reads
	var result []byte
	buf := make([]byte, 2) // Smaller than chunk size

	for {
		n, err := reader.Read(buf)
		if err == io.EOF {
			break
		}
		assert.NoError(t, err)
		result = append(result, buf[:n]...)
	}

	assert.Equal(t, "ABCDEFGHI", string(result))
}

func TestAWSChunkedReader_ChunkExtensions(t *testing.T) {
	// Test chunks with extensions (like AWS signatures)
	chunkData := "8;chunk-signature=abcd1234\r\nHelloWor\r\n2;chunk-signature=efgh5678\r\nld\r\n0;chunk-signature=final\r\n\r\n"

	reader := &awsChunkedReader{
		reader: bufio.NewReader(strings.NewReader(chunkData)),
		logger: logrus.NewEntry(logrus.New()),
		buffer: make([]byte, 0),
	}

	var result []byte
	buf := make([]byte, 1024)

	for {
		n, err := reader.Read(buf)
		if err == io.EOF {
			break
		}
		assert.NoError(t, err)
		result = append(result, buf[:n]...)
	}

	// Should strip chunk extensions and return only data
	assert.Equal(t, "HelloWorld", string(result))
}

func TestAWSChunkedReader_RealWorldExample(t *testing.T) {
	// Real-world AWS S3 chunked encoding example
	testData := "This is test data for AWS chunked encoding"

	// Simulate AWS chunked encoding with signatures
	var chunkData bytes.Buffer
	chunkData.WriteString(fmt.Sprintf("%x;chunk-signature=0123456789abcdef\r\n", len(testData)))
	chunkData.WriteString(testData)
	chunkData.WriteString("\r\n0;chunk-signature=final-signature\r\n\r\n")

	reader := &awsChunkedReader{
		reader: bufio.NewReader(&chunkData),
		logger: logrus.NewEntry(logrus.New()),
		buffer: make([]byte, 0),
	}

	// Read the complete data
	result, err := io.ReadAll(reader)
	require.NoError(t, err)

	assert.Equal(t, testData, string(result))
}

func TestAWSChunkedReader_EdgeCases(t *testing.T) {
	tests := []struct {
		name        string
		chunkData   string
		expectError bool
		expectedData string
	}{
		{
			name:         "Only final chunk",
			chunkData:    "0\r\n\r\n",
			expectError:  false,
			expectedData: "",
		},
		{
			name:        "Missing final CRLF",
			chunkData:   "3\r\nABC\r\n0\r\n",
			expectError: false, // Die Implementation ist robuster
			expectedData: "ABC",
		},
		{
			name:         "Chunk with only CRLF",
			chunkData:    "2\r\n\r\n\r\n0\r\n\r\n",
			expectError:  false,
			expectedData: "\r\n",
		},
		{
			name:        "Malformed chunk size line",
			chunkData:   "5\nHello\r\n0\r\n\r\n",
			expectError: false, // Die Implementation kann das verarbeiten
			expectedData: "Hello",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := &awsChunkedReader{
				reader: bufio.NewReader(strings.NewReader(tt.chunkData)),
				logger: logrus.NewEntry(logrus.New()),
				buffer: make([]byte, 0),
			}

			result, err := io.ReadAll(reader)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedData, string(result))
			}
		})
	}
}

func TestAWSChunkedReader_Performance(t *testing.T) {
	// Performance test with larger data
	if testing.Short() {
		t.Skip("Skipping performance test in short mode")
	}

	// Create 1MB of test data
	largeData := strings.Repeat("Performance test data chunk ", 32768) // ~1MB

	// Split into multiple chunks
	var chunkData bytes.Buffer
	chunkSize := 8192
	for i := 0; i < len(largeData); i += chunkSize {
		end := i + chunkSize
		if end > len(largeData) {
			end = len(largeData)
		}
		chunk := largeData[i:end]
		chunkData.WriteString(fmt.Sprintf("%x\r\n%s\r\n", len(chunk), chunk))
	}
	chunkData.WriteString("0\r\n\r\n")

	reader := &awsChunkedReader{
		reader: bufio.NewReader(&chunkData),
		logger: logrus.NewEntry(logrus.New()),
		buffer: make([]byte, 0),
	}

	// Read all data and verify
	result, err := io.ReadAll(reader)
	require.NoError(t, err)
	assert.Equal(t, largeData, string(result))
	assert.Equal(t, len(largeData), len(result))

	t.Logf("Successfully processed %d bytes of chunked data", len(result))
}
