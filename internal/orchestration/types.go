package orchestration

import "io"

// EncryptionResult represents the result of an encryption operation
type EncryptionResult struct {
	EncryptedData  io.Reader         // Streaming encrypted data
	Metadata       map[string]string // Encryption metadata
	Algorithm      string            // Encryption algorithm used
	KeyFingerprint string            // Key fingerprint for decryption
}
