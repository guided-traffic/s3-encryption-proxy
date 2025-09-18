package request

import (
	"net/http"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestChunkedEncodingDetector_RequiresChunkedDecoding(t *testing.T) {
	logger := logrus.NewEntry(logrus.New())
	detector := NewChunkedEncodingDetector(logger)

	tests := []struct {
		name     string
		headers  map[string]string
		expected bool
	}{
		{
			name: "Standard chunked transfer encoding",
			headers: map[string]string{
				"Transfer-Encoding": "chunked",
			},
			expected: true,
		},
		{
			name: "AWS Signature V4 streaming",
			headers: map[string]string{
				"X-Amz-Content-Sha256": "STREAMING-AWS4-HMAC-SHA256-PAYLOAD",
			},
			expected: true,
		},
		{
			name: "AWS chunked in Content-Encoding",
			headers: map[string]string{
				"Content-Encoding": "aws-chunked",
			},
			expected: true,
		},
		{
			name:     "No chunked encoding",
			headers:  map[string]string{},
			expected: false,
		},
		{
			name: "Regular content encoding",
			headers: map[string]string{
				"Content-Encoding": "gzip",
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest("PUT", "/test", nil)
			require.NoError(t, err)

			// Set headers
			for key, value := range tt.headers {
				req.Header.Set(key, value)
			}

			// Handle special case for Transfer-Encoding
			if value, exists := tt.headers["Transfer-Encoding"]; exists {
				req.TransferEncoding = []string{value}
			}

			result := detector.RequiresChunkedDecoding(req)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestChunkedEncodingDetector_AnalyzeFirstLine(t *testing.T) {
	logger := logrus.NewEntry(logrus.New())
	detector := NewChunkedEncodingDetector(logger)

	tests := []struct {
		name     string
		data     []byte
		expected bool
	}{
		{
			name:     "AWS chunked format",
			data:     []byte("a;chunk-signature=abc123\r\nhello world\r\n"),
			expected: true,
		},
		{
			name:     "Standard HTTP chunked format",
			data:     []byte("5\r\nhello\r\n"),
			expected: true,
		},
		{
			name:     "Hex chunk size",
			data:     []byte("10\r\nsome data here\r\n"),
			expected: true,
		},
		{
			name:     "Not chunked format",
			data:     []byte("Hello world, this is regular data"),
			expected: false,
		},
		{
			name:     "Empty data",
			data:     []byte{},
			expected: false,
		},
		{
			name:     "Invalid hex",
			data:     []byte("xyz\r\ndata\r\n"),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := detector.AnalyzeFirstLine(tt.data)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestChunkedEncodingDetector_ProcessChunkedData(t *testing.T) {
	logger := logrus.NewEntry(logrus.New())
	detector := NewChunkedEncodingDetector(logger)

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Simple AWS chunked data",
			input:    "5;chunk-signature=abc\r\nhello\r\n0;chunk-signature=final\r\n\r\n",
			expected: "hello",
		},
		{
			name:     "Multiple chunks",
			input:    "5;chunk-signature=abc\r\nhello\r\n5;chunk-signature=def\r\nworld\r\n0;chunk-signature=final\r\n\r\n",
			expected: "helloworld",
		},
		{
			name:     "Empty data",
			input:    "",
			expected: "",
		},
		{
			name:     "Non-chunked data returns original",
			input:    "Hello world",
			expected: "Hello world",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := detector.ProcessChunkedData([]byte(tt.input))
			require.NoError(t, err)
			assert.Equal(t, tt.expected, string(result))
		})
	}
}

func TestChunkedEncodingDetector_CreateOptimalReader(t *testing.T) {
	logger := logrus.NewEntry(logrus.New())
	detector := NewChunkedEncodingDetector(logger)

	t.Run("Creates AWS chunked reader for chunked requests", func(t *testing.T) {
		req, err := http.NewRequest("PUT", "/test", strings.NewReader("test data"))
		require.NoError(t, err)
		req.Header.Set("X-Amz-Content-Sha256", "STREAMING-AWS4-HMAC-SHA256-PAYLOAD")

		reader := detector.CreateOptimalReader(req)
		assert.IsType(t, &AWSChunkedReader{}, reader)
	})

	t.Run("Uses standard reader for non-chunked requests", func(t *testing.T) {
		req, err := http.NewRequest("PUT", "/test", strings.NewReader("test data"))
		require.NoError(t, err)

		reader := detector.CreateOptimalReader(req)
		assert.Equal(t, req.Body, reader)
	})
}

func TestParser_Integration(t *testing.T) {
	logger := logrus.NewEntry(logrus.New())
	parser := NewParser(logger, "s3ep-")

	t.Run("Processes chunked request body", func(t *testing.T) {
		chunkedData := "5;chunk-signature=abc\r\nhello\r\n0;chunk-signature=final\r\n\r\n"
		req, err := http.NewRequest("PUT", "/test", strings.NewReader(chunkedData))
		require.NoError(t, err)
		req.Header.Set("X-Amz-Content-Sha256", "STREAMING-AWS4-HMAC-SHA256-PAYLOAD")

		body, err := parser.ReadBody(req)
		require.NoError(t, err)
		assert.Equal(t, "hello", string(body))
	})

	t.Run("Processes regular request body", func(t *testing.T) {
		regularData := "hello world"
		req, err := http.NewRequest("PUT", "/test", strings.NewReader(regularData))
		require.NoError(t, err)

		body, err := parser.ReadBody(req)
		require.NoError(t, err)
		assert.Equal(t, "hello world", string(body))
	})

	t.Run("Handles empty body", func(t *testing.T) {
		req, err := http.NewRequest("PUT", "/test", nil)
		require.NoError(t, err)

		body, err := parser.ReadBody(req)
		require.NoError(t, err)
		assert.Nil(t, body)
	})
}
