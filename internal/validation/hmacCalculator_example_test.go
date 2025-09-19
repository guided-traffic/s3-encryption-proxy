package validation

import (
	"bufio"
	"fmt"
	"strings"
)

// Example demonstrates the basic usage of HMACCalculator
func ExampleHMACCalculator() {
	// 1. Create a DEK (Data Encryption Key)
	dek := []byte("example-key-32-bytes-for-testing")

	// 2. Create a new HMAC calculator with the derived key
	calc, err := NewHMACCalculator(dek)
	if err != nil {
		fmt.Printf("Error creating HMAC calculator: %v\n", err)
		return
	}
	defer calc.Cleanup() // Always cleanup to clear sensitive data from memory

	// 3. Method 1: Write data directly
	data := []byte("Hello, World!")
	calc.Write(data)

	// 4. Get the final HMAC hash
	hash := calc.Sum()
	fmt.Printf("HMAC hash length: %d bytes\n", len(hash))

	// 5. Reset and try with streaming
	calc.Reset()

	// 6. Method 2: Write from a stream
	streamData := "This is streaming data for HMAC calculation!"
	reader := bufio.NewReader(strings.NewReader(streamData))
	bytesProcessed, err := calc.WriteFromStream(reader)
	if err != nil {
		fmt.Printf("Error streaming data: %v\n", err)
		return
	}

	fmt.Printf("Bytes processed from stream: %d\n", bytesProcessed)

	// 7. Get the final hash for streaming data
	streamHash := calc.Sum()
	fmt.Printf("Stream HMAC hash length: %d bytes\n", len(streamHash))

	// Output:
	// HMAC hash length: 32 bytes
	// Bytes processed from stream: 44
	// Stream HMAC hash length: 32 bytes
}

// ExampleHMACCalculator_multipleWrites demonstrates incremental data processing
func ExampleHMACCalculator_multipleWrites() {
	dek := []byte("example-key-32-bytes-for-testing")

	calc, err := NewHMACCalculator(dek)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	defer calc.Cleanup()

	// Write data in multiple chunks
	chunks := [][]byte{
		[]byte("First chunk of data, "),
		[]byte("second chunk of data, "),
		[]byte("and the final chunk."),
	}

	for i, chunk := range chunks {
		calc.Write(chunk)
		fmt.Printf("Processed chunk %d: %d bytes\n", i+1, len(chunk))
	}

	hash := calc.Sum()
	fmt.Printf("Final HMAC length: %d bytes\n", len(hash))

	// Output:
	// Processed chunk 1: 21 bytes
	// Processed chunk 2: 22 bytes
	// Processed chunk 3: 20 bytes
	// Final HMAC length: 32 bytes
}

// ExampleHMACCalculator_consistency demonstrates that the same DEK produces the same result
func ExampleHMACCalculator_consistency() {
	dek := []byte("consistent-key-32-bytes-for-test")
	testData := []byte("Consistent test data")

	// First calculator
	calc1, _ := NewHMACCalculator(dek)
	defer calc1.Cleanup()
	calc1.Write(testData)
	hash1 := calc1.Sum()

	// Second calculator with same DEK
	calc2, _ := NewHMACCalculator(dek)
	defer calc2.Cleanup()
	calc2.Write(testData)
	hash2 := calc2.Sum()

	// Compare results
	fmt.Printf("Hash 1 length: %d\n", len(hash1))
	fmt.Printf("Hash 2 length: %d\n", len(hash2))
	fmt.Printf("Hashes are equal: %t\n", string(hash1) == string(hash2))

	// Output:
	// Hash 1 length: 32
	// Hash 2 length: 32
	// Hashes are equal: true
}
