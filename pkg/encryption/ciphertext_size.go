package encryption

// GCMOverhead is the number of extra bytes AES-GCM adds to the plaintext:
// 12-byte nonce prefix + 16-byte authentication tag.
const GCMOverhead = int64(28)

// ComputeCiphertextSize returns the ciphertext size for a plaintext of the given
// size encrypted with the named algorithm. Returns -1 for unknown algorithms.
// Algorithm overhead:
//   - aes-gcm: 28 bytes (12-byte nonce prefix + 16-byte auth tag)
//   - aes-ctr: 0 bytes
//   - none:    0 bytes
func ComputeCiphertextSize(plaintextSize int64, algorithm string) int64 {
	switch algorithm {
	case "aes-gcm":
		return plaintextSize + GCMOverhead
	case "aes-ctr", "none":
		return plaintextSize
	default:
		return -1
	}
}

// ComputePlaintextSize is the inverse of ComputeCiphertextSize: it returns the
// plaintext size for a stored object of the given size. Returns -1 for unknown
// algorithms or for a ciphertext too small to be valid.
//
// Needed for ranged reads: the client's Range header addresses plaintext bytes,
// while the object in the backend is ciphertext.
func ComputePlaintextSize(ciphertextSize int64, algorithm string) int64 {
	switch algorithm {
	case "aes-gcm":
		if ciphertextSize < GCMOverhead {
			return -1
		}
		return ciphertextSize - GCMOverhead
	case "aes-ctr", "none", "":
		return ciphertextSize
	default:
		return -1
	}
}
