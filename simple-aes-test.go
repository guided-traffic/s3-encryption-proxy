package main

import (
	"context"
	"fmt"
	"log"

	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption/providers"
)

const testData = "This is a test file for debugging AES-CTR encryption and decryption."

func main() {
	ctx := context.Background()

	// Test AES-CTR provider behavior
	fmt.Println("=== Testing AES-CTR Provider Behavior ===")

	provider, err := providers.NewAESCTRProviderFromBase64("Zm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyZm9v")
	if err != nil {
		log.Printf("Failed to create provider: %v", err)
		return
	}

	// Create IV and DEK
	iv, dek, err := provider.GenerateDataKey(ctx)
	if err != nil {
		log.Printf("Failed to generate data key: %v", err)
		return
	}

	fmt.Printf("Original data: %q (%d bytes)\n", testData, len(testData))
	fmt.Printf("DEK: %x\n", dek)
	fmt.Printf("IV: %x\n", iv)

	// Encrypt with counter 0
	encrypted, err := provider.EncryptStream(ctx, []byte(testData), dek, iv, 0)
	if err != nil {
		log.Printf("Failed to encrypt: %v", err)
		return
	}
	fmt.Printf("Encrypted (counter=0): %x\n", encrypted)

	// Decrypt with counter 0
	decrypted, err := provider.DecryptStream(ctx, encrypted, dek, iv, 0)
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
