package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"fmt"
	"log"

	"github.com/guided-traffic/s3-encryption-proxy/internal/config"
	"github.com/guided-traffic/s3-encryption-proxy/internal/encryption"
)

// calculateSHA256 calculates SHA256 hash of data for comparison purposes
func calculateSHA256(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}

// compareSHA256 compares two byte slices using SHA256 hashes
func compareSHA256(a, b []byte) bool {
	hashA := calculateSHA256(a)
	hashB := calculateSHA256(b)
	return bytes.Equal(hashA, hashB)
}

func main() {
	fmt.Println("Testing HMAC streaming with SHA256 comparison...")

	// Create HMAC manager
	manager := encryption.NewHMACManager(&config.Config{
		Encryption: config.EncryptionConfig{
			IntegrityVerification: config.HMACVerificationStrict,
		},
	})

	testDEK := []byte("test-dek-32-bytes-for-testing!!")
	testData := []byte("Hello, World! This is test data for SHA256 comparison.")

	// Test 1: Calculate HMAC twice and compare with SHA256
	reader1 := bufio.NewReader(bytes.NewReader(testData))
	hmacValue1, err := manager.CalculateHMACFromStream(reader1, testDEK)
	if err != nil {
		log.Fatalf("Failed to calculate first HMAC: %v", err)
	}

	reader2 := bufio.NewReader(bytes.NewReader(testData))
	hmacValue2, err := manager.CalculateHMACFromStream(reader2, testDEK)
	if err != nil {
		log.Fatalf("Failed to calculate second HMAC: %v", err)
	}

	// Compare using SHA256 hashes
	if !compareSHA256(hmacValue1, hmacValue2) {
		log.Fatalf("HMAC values should be identical")
	}
	fmt.Printf("✓ HMAC values are identical using SHA256 comparison\n")

	// Test 2: Verify different data produces different HMACs
	differentData := []byte("Different test data")
	reader3 := bufio.NewReader(bytes.NewReader(differentData))
	hmacValue3, err := manager.CalculateHMACFromStream(reader3, testDEK)
	if err != nil {
		log.Fatalf("Failed to calculate third HMAC: %v", err)
	}

	if compareSHA256(hmacValue1, hmacValue3) {
		log.Fatalf("Different data should produce different HMACs")
	}
	fmt.Printf("✓ Different data produces different HMACs (verified with SHA256)\n")

	// Test 3: Large data streaming test with SHA256 comparison
	largeData := make([]byte, 1024*1024) // 1MB
	for i := range largeData {
		largeData[i] = byte(i % 256)
	}

	// Single-pass
	readerLarge1 := bufio.NewReader(bytes.NewReader(largeData))
	largeHMAC1, err := manager.CalculateHMACFromStream(readerLarge1, testDEK)
	if err != nil {
		log.Fatalf("Failed to calculate large data HMAC: %v", err)
	}

	// Multi-part streaming
	calculator, err := manager.CreateCalculator(testDEK)
	if err != nil {
		log.Fatalf("Failed to create calculator: %v", err)
	}

	// Process in 4 parts
	partSize := len(largeData) / 4
	for i := 0; i < 4; i++ {
		start := i * partSize
		end := start + partSize
		if i == 3 {
			end = len(largeData) // Include remainder
		}
		part := largeData[start:end]
		err := manager.UpdateCalculatorSequential(calculator, part, i+1)
		if err != nil {
			log.Fatalf("Failed to update calculator: %v", err)
		}
	}

	largeHMAC2 := manager.FinalizeCalculator(calculator)

	if !compareSHA256(largeHMAC1, largeHMAC2) {
		log.Fatalf("Large data streaming HMAC should match single-pass HMAC")
	}
	fmt.Printf("✓ Large data streaming HMAC matches single-pass (SHA256 verified)\n")

	fmt.Printf("\nSHA256 hashes:\n")
	fmt.Printf("  Single-pass: %x\n", calculateSHA256(largeHMAC1)[:8])
	fmt.Printf("  Streaming:   %x\n", calculateSHA256(largeHMAC2)[:8])

	fmt.Println("\nAll HMAC streaming tests with SHA256 comparison passed! ✓")
}
