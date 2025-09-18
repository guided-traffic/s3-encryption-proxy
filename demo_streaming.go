package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"log"

	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption/dataencryption"
	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption/envelope"
	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption/keyencryption"
)

func main() {
	fmt.Println("🚀 Streaming Encryption Demo")

	ctx := context.Background()

	// Test data
	originalData := []byte("Hello, World! This demonstrates unified streaming encryption with both AES-GCM and AES-CTR!")
	fmt.Printf("📄 Original data: %s\n", string(originalData))

	// 1. Test AES-GCM Streaming
	fmt.Println("\n🔐 Testing AES-GCM Streaming:")
	testAESGCMStreaming(ctx, originalData)

	// 2. Test AES-CTR Streaming
	fmt.Println("\n🔐 Testing AES-CTR Streaming:")
	testAESCTRStreaming(ctx, originalData)

	// 3. Test Envelope Encryption with both
	fmt.Println("\n📦 Testing Envelope Encryption:")
	testEnvelopeEncryption(ctx, originalData)

	fmt.Println("\n✅ All streaming tests completed successfully!")
}

func testAESGCMStreaming(ctx context.Context, data []byte) {
	// Create AES-GCM encryptor
	encryptor := dataencryption.NewAESGCMDataEncryptor()

	// Generate DEK
	dek, err := encryptor.GenerateDEK(ctx)
	if err != nil {
		log.Fatalf("Failed to generate DEK: %v", err)
	}

	// Encrypt using streaming
	dataReader := bufio.NewReader(bytes.NewReader(data))
	encryptedReader, err := encryptor.EncryptStream(ctx, dataReader, dek, []byte("test-key"))
	if err != nil {
		log.Fatalf("Failed to encrypt: %v", err)
	}

	// Read encrypted data
	encryptedData, err := io.ReadAll(encryptedReader)
	if err != nil {
		log.Fatalf("Failed to read encrypted data: %v", err)
	}

	fmt.Printf("   ✓ Encrypted %d bytes -> %d bytes\n", len(data), len(encryptedData))

	// Decrypt using streaming (AES-GCM extracts nonce from data)
	encryptedDataReader := bufio.NewReader(bytes.NewReader(encryptedData))
	decryptedReader, err := encryptor.DecryptStream(ctx, encryptedDataReader, dek, nil, []byte("test-key"))
	if err != nil {
		log.Fatalf("Failed to decrypt: %v", err)
	}

	// Read decrypted data
	decryptedData, err := io.ReadAll(decryptedReader)
	if err != nil {
		log.Fatalf("Failed to read decrypted data: %v", err)
	}

	fmt.Printf("   ✓ Decrypted %d bytes -> %d bytes\n", len(encryptedData), len(decryptedData))

	if !bytes.Equal(data, decryptedData) {
		log.Fatalf("Data mismatch! Original: %s, Decrypted: %s", string(data), string(decryptedData))
	}

	fmt.Printf("   ✅ AES-GCM streaming works! Algorithm: %s\n", encryptor.Algorithm())
}

func testAESCTRStreaming(ctx context.Context, data []byte) {
	// Create AES-CTR encryptor
	encryptor := dataencryption.NewAESCTRDataEncryptor()

	// Generate DEK
	dek, err := encryptor.GenerateDEK(ctx)
	if err != nil {
		log.Fatalf("Failed to generate DEK: %v", err)
	}

	// Encrypt using streaming
	dataReader := bufio.NewReader(bytes.NewReader(data))
	encryptedReader, err := encryptor.EncryptStream(ctx, dataReader, dek, []byte("test-key"))
	if err != nil {
		log.Fatalf("Failed to encrypt: %v", err)
	}

	// Read encrypted data
	encryptedData, err := io.ReadAll(encryptedReader)
	if err != nil {
		log.Fatalf("Failed to read encrypted data: %v", err)
	}

	fmt.Printf("   ✓ Encrypted %d bytes -> %d bytes\n", len(data), len(encryptedData))

	// Get IV from encryptor for decryption
	ivProvider := encryptor.(interface{ GetLastIV() []byte })
	iv := ivProvider.GetLastIV()

	// Decrypt using streaming with IV
	encryptedDataReader := bufio.NewReader(bytes.NewReader(encryptedData))
	decryptedReader, err := encryptor.DecryptStream(ctx, encryptedDataReader, dek, iv, []byte("test-key"))
	if err != nil {
		log.Fatalf("Failed to decrypt: %v", err)
	}

	// Read decrypted data
	decryptedData, err := io.ReadAll(decryptedReader)
	if err != nil {
		log.Fatalf("Failed to read decrypted data: %v", err)
	}

	fmt.Printf("   ✓ Decrypted %d bytes -> %d bytes\n", len(encryptedData), len(decryptedData))

	if !bytes.Equal(data, decryptedData) {
		log.Fatalf("Data mismatch! Original: %s, Decrypted: %s", string(data), string(decryptedData))
	}

	fmt.Printf("   ✅ AES-CTR streaming works! Algorithm: %s\n", encryptor.Algorithm())
}

func testEnvelopeEncryption(ctx context.Context, data []byte) {
	// Create AES key encryptor with a test key
	testKEK := make([]byte, 32) // 256-bit key
	for i := range testKEK {
		testKEK[i] = byte(i % 256)
	}

	keyEncryptor, err := keyencryption.NewAESKeyEncryptor(testKEK)
	if err != nil {
		log.Fatalf("Failed to create key encryptor: %v", err)
	}

	// Test with AES-GCM data encryptor
	dataEncryptor := dataencryption.NewAESGCMDataEncryptor()
	envelopeEncryptor := envelope.NewEnvelopeEncryptor(keyEncryptor, dataEncryptor)

	// Encrypt using convenience method (internally uses streaming)
	encryptedData, encryptedDEK, metadata, err := envelopeEncryptor.EncryptData(ctx, data, []byte("test-associated-data"))
	if err != nil {
		log.Fatalf("Failed to encrypt with envelope: %v", err)
	}

	fmt.Printf("   ✓ Envelope encrypted %d bytes -> %d bytes\n", len(data), len(encryptedData))
	fmt.Printf("   ✓ Encrypted DEK size: %d bytes\n", len(encryptedDEK))
	fmt.Printf("   ✓ Metadata keys: %v\n", getKeys(metadata))

	// Decrypt using convenience method (internally uses streaming)
	decryptedData, err := envelopeEncryptor.DecryptData(ctx, encryptedData, encryptedDEK, []byte("test-associated-data"))
	if err != nil {
		log.Fatalf("Failed to decrypt with envelope: %v", err)
	}

	if !bytes.Equal(data, decryptedData) {
		log.Fatalf("Envelope data mismatch! Original: %s, Decrypted: %s", string(data), string(decryptedData))
	}

	fmt.Printf("   ✅ Envelope encryption works! Fingerprint: %s\n", envelopeEncryptor.Fingerprint())
}

func getKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
