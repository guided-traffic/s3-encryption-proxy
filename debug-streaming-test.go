package main

import (
	"context"
	"fmt"
	"log"

	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption/providers"
)

func main() {
	// Test data
	originalData := []byte("This is a test file for debugging AES-CTR encryption and decryption.")
	fmt.Printf("Original data: %q (%d bytes)\n", string(originalData), len(originalData))

	// Create AES-CTR provider with same key as config
	provider, err := providers.NewAESCTRProviderFromBase64("XZmcGLpObUuGV8CFOmfLKs7rggrX2TwIk5/Lbt9Azl4=")
	if err != nil {
		log.Fatalf("Failed to create AES-CTR provider: %v", err)
	}

	ctx := context.Background()

	// Test 1: Regular Encrypt/Decrypt
	fmt.Println("\n=== Testing Regular Encrypt/Decrypt ===")
	result, err := provider.Encrypt(ctx, originalData, []byte("debug-test-object.txt"))
	if err != nil {
		log.Fatalf("Failed to encrypt: %v", err)
	}

	fmt.Printf("Encrypted data size: %d bytes\n", len(result.EncryptedData))
	fmt.Printf("DEK size: %d bytes\n", len(result.EncryptedDEK))

	decrypted, err := provider.Decrypt(ctx, result.EncryptedData, result.EncryptedDEK, []byte("debug-test-object.txt"))
	if err != nil {
		log.Fatalf("Failed to decrypt: %v", err)
	}

	fmt.Printf("Decrypted data: %q (%d bytes)\n", string(decrypted), len(decrypted))
	if string(decrypted) == string(originalData) {
		fmt.Println("✓ Regular encrypt/decrypt works correctly!")
	} else {
		fmt.Printf("✗ Regular encrypt/decrypt failed! Expected: %q, Got: %q\n", string(originalData), string(decrypted))
	}

	// Test 2: Streaming Encrypt/Decrypt
	fmt.Println("\n=== Testing Streaming Encrypt/Decrypt ===")

	// Generate DEK and IV manually
	dataKey, encryptedDEK, err := provider.GenerateDataKey(ctx)
	if err != nil {
		log.Fatalf("Failed to generate data key: %v", err)
	}

	fmt.Printf("Generated DEK: %x\n", dataKey)
	fmt.Printf("Encrypted DEK size: %d bytes\n", len(encryptedDEK))

	// Use the first 16 bytes of encrypted data from regular encryption as IV
	// (this simulates how the streaming encryption gets the IV)
	iv := result.EncryptedData[:16]
	fmt.Printf("IV from encrypted data: %x\n", iv)

	// Test streaming encryption
	streamEncrypted, err := provider.EncryptStream(ctx, originalData, dataKey, iv, 0)
	if err != nil {
		log.Fatalf("Failed to encrypt stream: %v", err)
	}

	fmt.Printf("Stream encrypted data: %x\n", streamEncrypted)
	fmt.Printf("Stream encrypted size: %d bytes\n", len(streamEncrypted))

	// Test streaming decryption
	streamDecrypted, err := provider.DecryptStream(ctx, streamEncrypted, dataKey, iv, 0)
	if err != nil {
		log.Fatalf("Failed to decrypt stream: %v", err)
	}

	fmt.Printf("Stream decrypted data: %q (%d bytes)\n", string(streamDecrypted), len(streamDecrypted))
	if string(streamDecrypted) == string(originalData) {
		fmt.Println("✓ Streaming encrypt/decrypt works correctly!")
	} else {
		fmt.Printf("✗ Streaming encrypt/decrypt failed! Expected: %q, Got: %q\n", string(originalData), string(streamDecrypted))
	}
}
