package validation

import (
	"bufio"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewHMACCalculator(t *testing.T) {
	tests := []struct {
		name        string
		hmacKey     []byte
		expectError bool
		errorMsg    string
	}{
		{
			name:        "valid key",
			hmacKey:     []byte("test-hmac-key"),
			expectError: false,
		},
		{
			name:        "valid 32-byte key",
			hmacKey:     make([]byte, 32),
			expectError: false,
		},
		{
			name:        "empty key",
			hmacKey:     []byte{},
			expectError: true,
			errorMsg:    "HMAC key is empty",
		},
		{
			name:        "nil key",
			hmacKey:     nil,
			expectError: true,
			errorMsg:    "HMAC key is empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			calculator, err := NewHMACCalculator(tt.hmacKey)

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
				assert.Nil(t, calculator)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, calculator)
				assert.NotNil(t, calculator.calculator)
				assert.Equal(t, tt.hmacKey, calculator.hmacKey)
			}
		})
	}
}

func TestHMACCalculator_Add(t *testing.T) {
	hmacKey := []byte("test-hmac-key")
	calculator, err := NewHMACCalculator(hmacKey)
	require.NoError(t, err)

	tests := []struct {
		name     string
		data     []byte
		expected int
	}{
		{
			name:     "add simple data",
			data:     []byte("hello world"),
			expected: 11,
		},
		{
			name:     "add empty data",
			data:     []byte{},
			expected: 0,
		},
		{
			name:     "add binary data",
			data:     []byte{0x00, 0x01, 0x02, 0x03, 0xFF},
			expected: 5,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n, err := calculator.Add(tt.data)
			assert.NoError(t, err)
			assert.Equal(t, tt.expected, n)
		})
	}
}

func TestHMACCalculator_Add_WithNilCalculator(t *testing.T) {
	calculator := &HMACCalculator{
		hmacKey:    []byte("test"),
		calculator: nil,
	}

	n, err := calculator.Add([]byte("test"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "HMAC calculator not initialized")
	assert.Equal(t, 0, n)
}

func TestHMACCalculator_AddFromStream(t *testing.T) {
	hmacKey := []byte("test-hmac-key")

	tests := []struct {
		name         string
		data         string
		expectedSize int64
		expectError  bool
		errorMsg     string
	}{
		{
			name:         "simple text stream",
			data:         "hello world",
			expectedSize: 11,
			expectError:  false,
		},
		{
			name:         "empty stream",
			data:         "",
			expectedSize: 0,
			expectError:  false,
		},
		{
			name:         "large stream",
			data:         strings.Repeat("abcdefghijklmnopqrstuvwxyz", 1000), // 26KB
			expectedSize: 26000,
			expectError:  false,
		},
		{
			name:         "larger than buffer stream",
			data:         strings.Repeat("x", 64*1024), // 64KB - larger than the 32KB buffer
			expectedSize: 64 * 1024,
			expectError:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset calculator for each test
			calc, err := NewHMACCalculator(hmacKey)
			require.NoError(t, err)

			reader := bufio.NewReader(strings.NewReader(tt.data))
			size, err := calc.AddFromStream(reader)

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedSize, size)
			}
		})
	}
}

func TestHMACCalculator_AddFromStream_WithNilReader(t *testing.T) {
	hmacKey := []byte("test-hmac-key")
	calculator, err := NewHMACCalculator(hmacKey)
	require.NoError(t, err)

	size, err := calculator.AddFromStream(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "reader is nil")
	assert.Equal(t, int64(0), size)
}

func TestHMACCalculator_AddFromStream_WithNilCalculator(t *testing.T) {
	calculator := &HMACCalculator{
		hmacKey:    []byte("test"),
		calculator: nil,
	}

	reader := bufio.NewReader(strings.NewReader("test"))
	size, err := calculator.AddFromStream(reader)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "HMAC calculator not initialized")
	assert.Equal(t, int64(0), size)
}

func TestHMACCalculator_AddFromStream_WithReadError(t *testing.T) {
	hmacKey := []byte("test-hmac-key")
	calculator, err := NewHMACCalculator(hmacKey)
	require.NoError(t, err)

	// Create a reader that will return an error
	errorReader := &errorReader{data: []byte("partial"), returnError: true}
	reader := bufio.NewReader(errorReader)

	size, err := calculator.AddFromStream(reader)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "error reading from stream")
	// Should still return the bytes read before the error
	assert.Equal(t, int64(7), size) // "partial" is 7 bytes
}

func TestHMACCalculator_GetCurrentHash(t *testing.T) {
	hmacKey := []byte("test-hmac-key")
	calculator, err := NewHMACCalculator(hmacKey)
	require.NoError(t, err)

	// Test hash without any data
	hash1 := calculator.GetCurrentHash()
	assert.NotNil(t, hash1)
	assert.Len(t, hash1, 32) // SHA256 produces 32-byte hash

	// Add some data and test hash
	_, err = calculator.Add([]byte("hello"))
	require.NoError(t, err)

	hash2 := calculator.GetCurrentHash()
	assert.NotNil(t, hash2)
	assert.Len(t, hash2, 32)
	assert.NotEqual(t, hash1, hash2) // Hash should be different after adding data

	// Add more data and test hash again
	_, err = calculator.Add([]byte(" world"))
	require.NoError(t, err)

	hash3 := calculator.GetCurrentHash()
	assert.NotNil(t, hash3)
	assert.Len(t, hash3, 32)
	assert.NotEqual(t, hash2, hash3) // Hash should be different after adding more data

	// Verify that the hash matches what we expect from standard HMAC
	expectedHMAC := hmac.New(sha256.New, hmacKey)
	expectedHMAC.Write([]byte("hello world"))
	expectedHash := expectedHMAC.Sum(nil)
	assert.Equal(t, expectedHash, hash3)
}

func TestHMACCalculator_GetCurrentHash_WithNilCalculator(t *testing.T) {
	calculator := &HMACCalculator{
		hmacKey:    []byte("test"),
		calculator: nil,
	}

	hash := calculator.GetCurrentHash()
	assert.Nil(t, hash)
}

func TestHMACCalculator_Cleanup(t *testing.T) {
	hmacKey := []byte("test-hmac-key")
	calculator, err := NewHMACCalculator(hmacKey)
	require.NoError(t, err)

	// Verify calculator is initialized
	assert.NotNil(t, calculator.hmacKey)
	assert.NotNil(t, calculator.calculator)

	// Add some data to ensure calculator works
	_, err = calculator.Add([]byte("test"))
	assert.NoError(t, err)

	// Cleanup
	calculator.Cleanup()

	// Verify that key is zeroed and calculator is nil
	assert.Nil(t, calculator.hmacKey)
	assert.Nil(t, calculator.calculator)
}

func TestHMACCalculator_Cleanup_WithAlreadyNilFields(t *testing.T) {
	calculator := &HMACCalculator{
		hmacKey:    nil,
		calculator: nil,
	}

	// Should not panic
	assert.NotPanics(t, func() {
		calculator.Cleanup()
	})
}

func TestHMACCalculator_MemoryClearing(t *testing.T) {
	originalKey := []byte("sensitive-hmac-key")
	keyCopy := make([]byte, len(originalKey))
	copy(keyCopy, originalKey)

	calculator, err := NewHMACCalculator(keyCopy)
	require.NoError(t, err)

	// Verify key is stored
	assert.Equal(t, originalKey, calculator.hmacKey)

	// Cleanup
	calculator.Cleanup()

	// The original keyCopy should be zeroed out since calculator stores a reference
	allZero := true
	for _, b := range keyCopy {
		if b != 0 {
			allZero = false
			break
		}
	}
	assert.True(t, allZero, "HMAC key should be zeroed out in memory after cleanup")
}

func TestHMACCalculator_EndToEndWorkflow(t *testing.T) {
	hmacKey := make([]byte, 32)
	_, err := rand.Read(hmacKey)
	require.NoError(t, err)

	calculator, err := NewHMACCalculator(hmacKey)
	require.NoError(t, err)

	// Test complete workflow with various data additions
	testData := [][]byte{
		[]byte("first chunk"),
		[]byte("second chunk"),
		[]byte("third chunk"),
	}

	var allData []byte
	for _, data := range testData {
		n, err := calculator.Add(data)
		require.NoError(t, err)
		assert.Equal(t, len(data), n)
		allData = append(allData, data...)
	}

	// Add data from stream
	streamData := "stream data content"
	reader := bufio.NewReader(strings.NewReader(streamData))
	size, err := calculator.AddFromStream(reader)
	require.NoError(t, err)
	assert.Equal(t, int64(len(streamData)), size)
	allData = append(allData, []byte(streamData)...)

	// Get final hash
	finalHash := calculator.GetCurrentHash()
	assert.Len(t, finalHash, 32)

	// Verify against expected HMAC
	expectedHMAC := hmac.New(sha256.New, hmacKey)
	expectedHMAC.Write(allData)
	expectedHash := expectedHMAC.Sum(nil)
	assert.Equal(t, expectedHash, finalHash)

	// Cleanup
	calculator.Cleanup()
	assert.Nil(t, calculator.hmacKey)
	assert.Nil(t, calculator.calculator)
}

func TestHMACCalculator_ConsistentHashWithMultipleCalls(t *testing.T) {
	hmacKey := []byte("test-key")
	calculator, err := NewHMACCalculator(hmacKey)
	require.NoError(t, err)

	// Add data
	_, err = calculator.Add([]byte("test data"))
	require.NoError(t, err)

	// GetCurrentHash should return the same result when called multiple times
	hash1 := calculator.GetCurrentHash()
	hash2 := calculator.GetCurrentHash()
	hash3 := calculator.GetCurrentHash()

	assert.Equal(t, hash1, hash2)
	assert.Equal(t, hash2, hash3)
}

// errorReader is a helper type for testing read errors
type errorReader struct {
	data        []byte
	pos         int
	returnError bool
}

func (r *errorReader) Read(p []byte) (n int, err error) {
	if r.pos >= len(r.data) {
		if r.returnError {
			return 0, io.ErrUnexpectedEOF
		}
		return 0, io.EOF
	}

	n = copy(p, r.data[r.pos:])
	r.pos += n

	if r.pos >= len(r.data) && r.returnError {
		return n, io.ErrUnexpectedEOF
	}

	return n, nil
}
