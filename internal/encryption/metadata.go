package encryption

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/hkdf"
)

const (
	// HKDF constants for integrity verification according to specification
	integritySalt = "s3-proxy-integrity-v1"
	integrityInfo = "file-hmac-key"
)

// MetadataManager handles HMAC metadata operations for integrity verification
type MetadataManager struct {
	prefix string
}

// NewMetadataManager creates a new metadata manager with the given prefix
func NewMetadataManager(prefix string) *MetadataManager {
	return &MetadataManager{
		prefix: prefix,
	}
}

// AddHMACToMetadata calculates and adds HMAC to the metadata map
// This function takes the raw (unencrypted) data and the DEK to calculate HMAC
func (m *MetadataManager) AddHMACToMetadata(metadata map[string]string, rawData []byte, dek []byte, enabled bool) error {
	// Skip if integrity verification is disabled
	if !enabled {
		return nil
	}

	// Validate inputs
	if metadata == nil {
		return fmt.Errorf("metadata map is nil")
	}
	if len(rawData) == 0 {
		return fmt.Errorf("raw data is empty")
	}
	if len(dek) == 0 {
		return fmt.Errorf("DEK is empty")
	}

	// Derive HMAC key from DEK using HKDF with fixed constants
	hmacKey, err := m.deriveHMACKey(dek)
	if err != nil {
		return fmt.Errorf("failed to derive HMAC key: %w", err)
	}
	defer func() {
		// Clear HMAC key from memory
		for i := range hmacKey {
			hmacKey[i] = 0
		}
	}()

	// Calculate HMAC-SHA256 of raw data
	mac := hmac.New(sha256.New, hmacKey)
	mac.Write(rawData)
	hmacValue := mac.Sum(nil)

	// Store HMAC in metadata as base64
	metadata[m.prefix+"hmac"] = base64.StdEncoding.EncodeToString(hmacValue)

	return nil
}

// VerifyHMACFromMetadata verifies HMAC integrity of the data
// Returns true if HMAC verification succeeds or if HMAC is not present (backward compatibility)
func (m *MetadataManager) VerifyHMACFromMetadata(metadata map[string]string, rawData []byte, dek []byte, enabled bool) (bool, error) {
	// Skip verification if integrity verification is disabled
	if !enabled {
		return true, nil
	}

	// Check if HMAC exists in metadata (backward compatibility)
	hmacBase64, exists := metadata[m.prefix+"hmac"]
	if !exists {
		// No HMAC found - treat as valid for backward compatibility
		return true, nil
	}

	// Validate inputs
	if len(rawData) == 0 {
		return false, fmt.Errorf("raw data is empty")
	}
	if len(dek) == 0 {
		return false, fmt.Errorf("DEK is empty")
	}

	// Decode stored HMAC
	storedHMAC, err := base64.StdEncoding.DecodeString(hmacBase64)
	if err != nil {
		return false, fmt.Errorf("failed to decode stored HMAC: %w", err)
	}

	// Derive HMAC key from DEK using HKDF with fixed constants
	hmacKey, err := m.deriveHMACKey(dek)
	if err != nil {
		return false, fmt.Errorf("failed to derive HMAC key: %w", err)
	}
	defer func() {
		// Clear HMAC key from memory
		for i := range hmacKey {
			hmacKey[i] = 0
		}
	}()

	// Calculate HMAC-SHA256 of raw data
	mac := hmac.New(sha256.New, hmacKey)
	mac.Write(rawData)
	calculatedHMAC := mac.Sum(nil)

	// Compare HMACs using constant-time comparison
	if !hmac.Equal(storedHMAC, calculatedHMAC) {
		return false, fmt.Errorf("HMAC verification failed: data integrity compromised")
	}

	return true, nil
}

// deriveHMACKey derives HMAC key from DEK using HKDF with fixed constants
func (m *MetadataManager) deriveHMACKey(dek []byte) ([]byte, error) {
	// Use HKDF-SHA256 with fixed salt and info as per specification
	hkdfReader := hkdf.New(sha256.New, dek, []byte(integritySalt), []byte(integrityInfo))

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

// ExtractHMACFromMetadata extracts HMAC value from metadata if present
func (m *MetadataManager) ExtractHMACFromMetadata(metadata map[string]string) ([]byte, bool, error) {
	hmacBase64, exists := metadata[m.prefix+"hmac"]
	if !exists {
		return nil, false, nil
	}

	hmacBytes, err := base64.StdEncoding.DecodeString(hmacBase64)
	if err != nil {
		return nil, true, fmt.Errorf("failed to decode HMAC from metadata: %w", err)
	}

	return hmacBytes, true, nil
}

// IsHMACMetadata checks if a metadata key is HMAC-related
func (m *MetadataManager) IsHMACMetadata(key string) bool {
	return key == m.prefix+"hmac"
}

// FilterHMACMetadata removes HMAC metadata from a map (for client responses)
func (m *MetadataManager) FilterHMACMetadata(metadata map[string]string) map[string]string {
	if metadata == nil {
		return nil
	}

	filtered := make(map[string]string)
	for key, value := range metadata {
		if !m.IsHMACMetadata(key) {
			filtered[key] = value
		}
	}

	return filtered
}

// GetHMACMetadataKey returns the full HMAC metadata key with prefix
func (m *MetadataManager) GetHMACMetadataKey() string {
	return m.prefix + "hmac"
}
