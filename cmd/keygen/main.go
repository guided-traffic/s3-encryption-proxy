package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
)

func main() {
	// Generate a new AES-256 key (32 bytes)
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		fmt.Fprintf(os.Stderr, "Error generating key: %v\n", err)
		os.Exit(1)
	}

	// Encode to base64
	keyBase64 := base64.StdEncoding.EncodeToString(key)

	fmt.Printf("Generated AES-256 key (base64 encoded):\n%s\n", keyBase64)
	fmt.Printf("\nYou can use this key in your configuration:\n")
	fmt.Printf("aes_key: \"%s\"\n", keyBase64)
	fmt.Printf("\nOr set it as an environment variable:\n")
	fmt.Printf("export AES_ENCRYPTION_KEY=\"%s\"\n", keyBase64)
}
