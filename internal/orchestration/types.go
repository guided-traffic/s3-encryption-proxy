package orchestration

import "bufio"

// EncryptionResult represents the result of an encryption operation
type EncryptionResult struct {
	EncryptedData  *bufio.Reader     // Streaming encrypted data
	Metadata       map[string]string // Encryption metadata
	Algorithm      string            // Encryption algorithm used
	KeyFingerprint string            // Key fingerprint for decryption
}
