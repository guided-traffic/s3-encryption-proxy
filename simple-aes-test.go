package main

import (
	"context"
	"fmt"
	"log"

	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption/dataencryption"
)

const testData = "This is a test file for debugging AES-CTR encryption and decryption."

func main() {
	ctx := context.Background()

	// Test AES-CTR provider behavior
	fmt.Println("=== Testing AES-CTR Provider Behavior ===")

	provider := dataencryption.NewAESCTRDataEncryptor()

	// Generate DEK
	dek, err := provider.GenerateDEK(ctx)
	if err != nil {
		log.Printf("Failed to generate DEK: %v", err)
		return
	}

	fmt.Printf("Original data: %q (%d bytes)\n", testData, len(testData))
	fmt.Printf("DEK: %x\n", dek)

	// Encrypt the data
	encrypted, err := provider.Encrypt(ctx, []byte(testData), dek)
	if err != nil {
		log.Printf("Failed to encrypt: %v", err)
		return
	}
	fmt.Printf("Encrypted: %x\n", encrypted)

	// Decrypt the data
	decrypted, err := provider.Decrypt(ctx, encrypted, dek)
	if err != nil {
		log.Printf("Failed to decrypt: %v", err)
		return
	}
	fmt.Printf("Decrypted: %q (%d bytes)\n", string(decrypted), len(decrypted))

	if string(decrypted) == testData {
		fmt.Println("✓ AES-CTR Provider works correctly!")
	} else {
		fmt.Println("✗ AES-CTR Provider has issues!")
		fmt.Printf("Expected: %q\n", testData)
		fmt.Printf("Got:      %q\n", string(decrypted))
	}
}
