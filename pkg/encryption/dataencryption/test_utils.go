package dataencryption

import (
	"crypto/sha256"
	"fmt"
	"io"
)

// calculateStreamingSHA256 computes SHA256 hash from a reader without loading all data into memory
func calculateStreamingSHA256(reader io.Reader) (string, error) {
	hasher := sha256.New()
	_, err := io.Copy(hasher, reader)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", hasher.Sum(nil)), nil
}
