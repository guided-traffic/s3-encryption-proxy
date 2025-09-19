package validation

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"hash"
	"io"
)

// HMACCalculator provides a simplified interface for HMAC operations.
// It holds an HMAC key in memory and provides methods to process data streams
// and calculate the final HMAC hash.
type HMACCalculator struct {
	hmacKey    []byte    // HMAC key stored in memory
	calculator hash.Hash // HMAC calculator instance
}

// NewHMACCalculator creates a new HMAC calculator with the provided HMAC key.
// The key is stored in memory for the lifetime of the calculator.
func NewHMACCalculator(hmacKey []byte) (*HMACCalculator, error) {
	if len(hmacKey) == 0 {
		return nil, fmt.Errorf("HMAC key is empty")
	}

	// Create HMAC calculator with the provided key
	calculator := hmac.New(sha256.New, hmacKey)

	return &HMACCalculator{
		hmacKey:    hmacKey,
		calculator: calculator,
	}, nil
}

// Add processes data through the HMAC calculator.
// This method can be called multiple times to feed data incrementally.
func (hc *HMACCalculator) Add(data []byte) (int, error) {
	if hc.calculator == nil {
		return 0, fmt.Errorf("HMAC calculator not initialized")
	}

	return hc.calculator.Write(data)
}

// AddFromStream processes data from a bufio.Reader through the HMAC calculator.
// This method efficiently streams data in chunks without loading everything into memory.
// Returns the total number of bytes processed.
func (hc *HMACCalculator) AddFromStream(reader *bufio.Reader) (int64, error) {
	if hc.calculator == nil {
		return 0, fmt.Errorf("HMAC calculator not initialized")
	}

	if reader == nil {
		return 0, fmt.Errorf("reader is nil")
	}

	const bufferSize = 32 * 1024 // 32KB buffer for efficient streaming
	buffer := make([]byte, bufferSize)
	var totalBytes int64

	for {
		n, err := reader.Read(buffer)
		if n > 0 {
			hc.calculator.Write(buffer[:n])
			totalBytes += int64(n)
		}

		if err == io.EOF {
			break
		}
		if err != nil {
			return totalBytes, fmt.Errorf("error reading from stream: %w", err)
		}
	}

	return totalBytes, nil
}

// GetCurrentHash returns the current HMAC hash value.
// This can be called multiple times and will always return the current state.
func (hc *HMACCalculator) GetCurrentHash() []byte {
	if hc.calculator == nil {
		return nil
	}

	return hc.calculator.Sum(nil)
}

// Cleanup clears the stored HMAC key from memory for security.
// After calling Cleanup, the calculator should not be used anymore.
func (hc *HMACCalculator) Cleanup() {
	if hc.hmacKey != nil {
		// Zero out the key in memory
		for i := range hc.hmacKey {
			hc.hmacKey[i] = 0
		}
		hc.hmacKey = nil
	}
	hc.calculator = nil
}
