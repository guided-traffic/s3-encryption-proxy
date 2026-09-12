package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"os"
)

func main() {
	if err := printKey(os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "Error generating key: %v\n", err)
		os.Exit(1)
	}
}

// printKey writes a fresh AES-256 key and the two ways to use it.
//
// The layout is a contract: the key is on the SECOND line, because the
// documented way to capture it is `s3ep-keygen | sed -n 2p`. Anything added
// above it breaks every script that follows the documentation.
func printKey(w io.Writer) error {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return err
	}
	encoded := base64.StdEncoding.EncodeToString(key)

	// Only mechanisms the proxy actually has: a literal in the configuration, or
	// a ${VAR} reference written into it. There is no environment variable that
	// overrides a configuration key (ADR 0013).
	_, err := fmt.Fprintf(w, "Generated AES-256 key (base64 encoded):\n%s\n"+
		"\nUse it in your configuration:\n"+
		"aes_key: \"%s\"\n"+
		"\nOr keep it out of the file and reference it:\n"+
		"aes_key: \"${S3EP_AES_KEY}\"   with S3EP_AES_KEY=%s in the environment\n",
		encoded, encoded, encoded)
	return err
}
