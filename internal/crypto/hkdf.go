package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"

	"golang.org/x/crypto/hkdf"
)

// HKDF constants for integrity verification
const (
	// HKDFIntegrityInfo is the context information for HKDF when deriving integrity verification keys
	HKDFIntegrityInfo = "s3-encryption-proxy-integrity-verification"

	// DefaultHMACKeySize is the default size for HMAC keys in bytes
	DefaultHMACKeySize = 32 // 256 bits for HMAC-SHA256

	// DefaultHKDFSaltLength is the default length for HKDF salt in bytes
	DefaultHKDFSaltLength = 32 // 256 bits

	// MinHMACKeySize is the minimum allowed HMAC key size in bytes
	MinHMACKeySize = 16 // 128 bits

	// MaxHMACKeySize is the maximum allowed HMAC key size in bytes
	MaxHMACKeySize = 64 // 512 bits

	// MinHKDFSaltLength is the minimum allowed HKDF salt length in bytes
	MinHKDFSaltLength = 16 // 128 bits

	// MaxHKDFSaltLength is the maximum allowed HKDF salt length in bytes
	MaxHKDFSaltLength = 64 // 512 bits
)

// HKDFConfig holds configuration for HKDF key derivation
type HKDFConfig struct {
	// HashAlgorithm specifies the hash function to use ("sha256" or "sha512")
	HashAlgorithm string

	// HMACKeySize specifies the size of the derived HMAC key in bytes
	HMACKeySize int

	// HKDFSaltLength specifies the length of the HKDF salt in bytes
	HKDFSaltLength int
}

// HKDFResult holds the result of HKDF key derivation
type HKDFResult struct {
	// DerivedKey is the derived HMAC key
	DerivedKey []byte

	// Salt is the salt used for derivation
	Salt []byte
}

// NewHKDFConfig creates a new HKDF configuration with defaults
func NewHKDFConfig() *HKDFConfig {
	return &HKDFConfig{
		HashAlgorithm:  "sha256",
		HMACKeySize:    DefaultHMACKeySize,
		HKDFSaltLength: DefaultHKDFSaltLength,
	}
}

// Validate validates the HKDF configuration
func (c *HKDFConfig) Validate() error {
	// Validate hash algorithm
	switch c.HashAlgorithm {
	case "sha256", "sha512":
		// Valid algorithms
	case "":
		return fmt.Errorf("hash algorithm is required")
	default:
		return fmt.Errorf("unsupported hash algorithm '%s' (supported: sha256, sha512)", c.HashAlgorithm)
	}

	// Validate HMAC key size
	if c.HMACKeySize < MinHMACKeySize {
		return fmt.Errorf("HMAC key size must be at least %d bytes, got %d", MinHMACKeySize, c.HMACKeySize)
	}
	if c.HMACKeySize > MaxHMACKeySize {
		return fmt.Errorf("HMAC key size must be at most %d bytes, got %d", MaxHMACKeySize, c.HMACKeySize)
	}

	// Validate HKDF salt length
	if c.HKDFSaltLength < MinHKDFSaltLength {
		return fmt.Errorf("HKDF salt length must be at least %d bytes, got %d", MinHKDFSaltLength, c.HKDFSaltLength)
	}
	if c.HKDFSaltLength > MaxHKDFSaltLength {
		return fmt.Errorf("HKDF salt length must be at most %d bytes, got %d", MaxHKDFSaltLength, c.HKDFSaltLength)
	}

	return nil
}

// getHashFunction returns the hash function for the configured algorithm
func (c *HKDFConfig) getHashFunction() func() hash.Hash {
	switch c.HashAlgorithm {
	case "sha256":
		return sha256.New
	case "sha512":
		return sha512.New
	default:
		// This should never happen if Validate() was called
		return sha256.New
	}
}

// DeriveIntegrityKey derives an HMAC key for integrity verification using HKDF
//
// Parameters:
//   - masterKey: The master encryption key used as Input Key Material (IKM)
//   - salt: Optional salt for HKDF. If nil, a random salt will be generated
//
// Returns:
//   - HKDFResult containing the derived key and salt used
//   - error if derivation fails
func (c *HKDFConfig) DeriveIntegrityKey(masterKey []byte, salt []byte) (*HKDFResult, error) {
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("invalid HKDF config: %w", err)
	}

	if len(masterKey) == 0 {
		return nil, fmt.Errorf("master key cannot be empty")
	}

	// Generate salt if not provided
	if salt == nil {
		salt = make([]byte, c.HKDFSaltLength)
		if _, err := rand.Read(salt); err != nil {
			return nil, fmt.Errorf("failed to generate salt: %w", err)
		}
	}

	// Validate salt length
	if len(salt) != c.HKDFSaltLength {
		return nil, fmt.Errorf("salt length must be %d bytes, got %d", c.HKDFSaltLength, len(salt))
	}

	// Create HKDF reader
	hashFunc := c.getHashFunction()
	hkdfReader := hkdf.New(hashFunc, masterKey, salt, []byte(HKDFIntegrityInfo))

	// Derive the HMAC key
	derivedKey := make([]byte, c.HMACKeySize)
	if _, err := hkdfReader.Read(derivedKey); err != nil {
		return nil, fmt.Errorf("failed to derive HMAC key: %w", err)
	}

	return &HKDFResult{
		DerivedKey: derivedKey,
		Salt:       salt,
	}, nil
}

// DeriveIntegrityKeyWithRandomSalt is a convenience method that derives an HMAC key with a randomly generated salt
func (c *HKDFConfig) DeriveIntegrityKeyWithRandomSalt(masterKey []byte) (*HKDFResult, error) {
	return c.DeriveIntegrityKey(masterKey, nil)
}

// DeriveIntegrityKeyWithSalt is a convenience method that derives an HMAC key with a provided salt
func (c *HKDFConfig) DeriveIntegrityKeyWithSalt(masterKey []byte, salt []byte) (*HKDFResult, error) {
	if salt == nil {
		return nil, fmt.Errorf("salt cannot be nil")
	}
	return c.DeriveIntegrityKey(masterKey, salt)
}

// GenerateRandomSalt generates a random salt with the configured length
func (c *HKDFConfig) GenerateRandomSalt() ([]byte, error) {
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("invalid HKDF config: %w", err)
	}

	salt := make([]byte, c.HKDFSaltLength)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}

	return salt, nil
}

// DeriveIntegrityKey is a convenience function that derives HMAC key from DEK using fixed constants
// This function uses the same HKDF constants as specified in the integrity verification feature
func DeriveIntegrityKey(dek []byte) ([]byte, error) {
	if len(dek) == 0 {
		return nil, fmt.Errorf("DEK cannot be empty")
	}

	// Use HKDF-SHA256 with fixed salt and info as per specification
	// Constants match metadata.go: integritySalt="s3-proxy-integrity-v1", integrityInfo="file-hmac-key"
	hkdfReader := hkdf.New(sha256.New, dek, []byte("s3-proxy-integrity-v1"), []byte("file-hmac-key"))

	// Generate 32-byte HMAC key (for HMAC-SHA256)
	hmacKey := make([]byte, 32)
	n, err := hkdfReader.Read(hmacKey)
	if err != nil {
		return nil, fmt.Errorf("HKDF key derivation failed: %w", err)
	}
	if n != 32 {
		return nil, fmt.Errorf("HKDF key derivation returned %d bytes instead of 32", n)
	}

	return hmacKey, nil
}
