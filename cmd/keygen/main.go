package main

import (
	"encoding/base64"
	"fmt"
	"os"

	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption"
)

func main() {
	// Generate a new AES-256 key
	key, err := encryption.GenerateAESGCMKey()
	if err != nil {
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
