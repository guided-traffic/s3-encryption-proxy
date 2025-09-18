package main

import (
	"bufio"
	"bytes"
	"fmt"
	"log"

	"github.com/guided-traffic/s3-encryption-proxy/internal/config"
	"github.com/guided-traffic/s3-encryption-proxy/internal/encryption"
)

func main() {
	fmt.Println("Testing HMAC streaming implementation...")

	// Create HMAC manager
	manager := encryption.NewHMACManager(&config.Config{
		Encryption: config.EncryptionConfig{
			IntegrityVerification: config.HMACVerificationStrict,
		},
	})

	testDEK := []byte("test-dek-32-bytes-for-testing!!")
	testData := []byte("Hello, World! This is test data.")

	// Test 1: Calculate HMAC from stream
	reader := bufio.NewReader(bytes.NewReader(testData))
	hmacValue, err := manager.CalculateHMACFromStream(reader, testDEK)
	if err != nil {
		log.Fatalf("Failed to calculate HMAC: %v", err)
	}
	fmt.Printf("✓ HMAC calculated successfully: %d bytes\n", len(hmacValue))

	// Test 2: Add HMAC to metadata
	metadata := make(map[string]string)
	reader2 := bufio.NewReader(bytes.NewReader(testData))
	err = manager.AddHMACToMetadataFromStream(metadata, reader2, testDEK, "s3ep-")
	if err != nil {
		log.Fatalf("Failed to add HMAC to metadata: %v", err)
	}
	fmt.Printf("✓ HMAC added to metadata: %s\n", metadata["s3ep-hmac"][:20]+"...")

	// Test 3: Verify HMAC from metadata
	reader3 := bufio.NewReader(bytes.NewReader(testData))
	err = manager.VerifyHMACFromMetadataStream(metadata, reader3, testDEK, "s3ep-")
	if err != nil {
		log.Fatalf("Failed to verify HMAC: %v", err)
	}
	fmt.Printf("✓ HMAC verification successful\n")

	// Test 4: Test with corrupted data (should fail)
	corruptedData := make([]byte, len(testData))
	copy(corruptedData, testData)
	corruptedData[0] ^= 0xFF // Flip bits

	reader4 := bufio.NewReader(bytes.NewReader(corruptedData))
	err = manager.VerifyHMACFromMetadataStream(metadata, reader4, testDEK, "s3ep-")
	if err == nil {
		log.Fatalf("HMAC verification should have failed with corrupted data")
	}
	fmt.Printf("✓ HMAC verification correctly failed with corrupted data\n")

	fmt.Println("\nAll HMAC streaming tests passed! ✓")
}
