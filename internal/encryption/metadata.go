package encryption

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/hkdf"

	"github.com/guided-traffic/s3-encryption-proxy/internal/config"
)

const (
	// HKDF constants for integrity verification according to specification
	integritySalt = "s3-proxy-integrity-v1"
	integrityInfo = "file-hmac-key"
)

// MetadataManagerV2 handles all encryption metadata operations with comprehensive functionality
type MetadataManagerV2 struct {
	// Core configuration
	config *config.Config
	logger *logrus.Entry

	// Metadata configuration
	prefix string
}

// NewMetadataManagerV2 creates a new comprehensive metadata manager
func NewMetadataManagerV2(cfg *config.Config, prefix string) *MetadataManagerV2 {
	if prefix == "" {
		if cfg.Encryption.MetadataKeyPrefix != nil {
			prefix = *cfg.Encryption.MetadataKeyPrefix
		} else {
			prefix = "s3ep-" // default prefix
		}
	}

	return &MetadataManagerV2{
		config: cfg,
		logger: logrus.WithField("component", "metadata_manager_v2"),
		prefix: prefix,
	}
}

// BuildMetadataForEncryption builds complete metadata map for encryption results
func (mm *MetadataManagerV2) BuildMetadataForEncryption(dek, encryptedDEK, iv []byte, algorithm, fingerprint string, originalMetadata map[string]string) map[string]string {
	metadata := make(map[string]string)

	// Copy original metadata if provided
	if originalMetadata != nil {
		for key, value := range originalMetadata {
			metadata[key] = value
		}
	}

	// Add encryption metadata with prefix
	metadata[mm.prefix+"encrypted-dek"] = base64.StdEncoding.EncodeToString(encryptedDEK)
	metadata[mm.prefix+"dek-algorithm"] = algorithm
	metadata[mm.prefix+"kek-fingerprint"] = fingerprint

	// Add IV if provided
	if len(iv) > 0 {
		metadata[mm.prefix+"aes-iv"] = base64.StdEncoding.EncodeToString(iv)
	}

	mm.logger.WithFields(logrus.Fields{
		"algorithm":          algorithm,
		"fingerprint":        fingerprint,
		"metadata_keys":      len(metadata),
		"encryption_keys":    mm.countEncryptionKeys(metadata),
	}).Debug("Built encryption metadata")

	return metadata
}

// ExtractEncryptionMetadata extracts encryption-specific metadata from object metadata
func (mm *MetadataManagerV2) ExtractEncryptionMetadata(metadata map[string]string) (map[string]string, error) {
	encryptionMetadata := make(map[string]string)

	for key, value := range metadata {
		if strings.HasPrefix(key, mm.prefix) {
			// Remove prefix from key for internal use
			cleanKey := strings.TrimPrefix(key, mm.prefix)
			encryptionMetadata[cleanKey] = value
		}
	}

	mm.logger.WithFields(logrus.Fields{
		"total_metadata":     len(metadata),
		"encryption_metadata": len(encryptionMetadata),
	}).Debug("Extracted encryption metadata")

	return encryptionMetadata, nil
}

// FilterMetadataForClient removes encryption metadata from client responses
func (mm *MetadataManagerV2) FilterMetadataForClient(metadata map[string]string) map[string]string {
	filtered := make(map[string]string)
	encryptionKeysCount := 0

	for key, value := range metadata {
		if strings.HasPrefix(key, mm.prefix) {
			encryptionKeysCount++
			// Skip encryption metadata keys
			continue
		}
		filtered[key] = value
	}

	mm.logger.WithFields(logrus.Fields{
		"total_keys":       len(metadata),
		"filtered_keys":    len(filtered),
		"encryption_keys":  encryptionKeysCount,
	}).Debug("Filtered metadata for client")

	return filtered
}

// GetEncryptedDEK extracts and decodes the encrypted DEK from metadata
func (mm *MetadataManagerV2) GetEncryptedDEK(metadata map[string]string) ([]byte, error) {
	encryptedDEKStr, exists := metadata[mm.prefix+"encrypted-dek"]
	if !exists {
		return nil, fmt.Errorf("encrypted DEK not found in metadata")
	}

	encryptedDEK, err := base64.StdEncoding.DecodeString(encryptedDEKStr)
	if err != nil {
		mm.logger.WithFields(logrus.Fields{
			"metadata_key": mm.prefix + "encrypted-dek",
			"error":        err,
		}).Error("Failed to decode encrypted DEK from metadata")
		return nil, fmt.Errorf("failed to decode encrypted DEK: %w", err)
	}

	mm.logger.WithFields(logrus.Fields{
		"dek_size": len(encryptedDEK),
	}).Debug("Successfully extracted encrypted DEK")

	return encryptedDEK, nil
}

// GetAlgorithm extracts the algorithm from metadata
func (mm *MetadataManagerV2) GetAlgorithm(metadata map[string]string) (string, error) {
	algorithm, exists := metadata[mm.prefix+"dek-algorithm"]
	if !exists {
		return "", fmt.Errorf("algorithm not found in metadata")
	}

	mm.logger.WithField("algorithm", algorithm).Debug("Retrieved algorithm from metadata")
	return algorithm, nil
}

// GetFingerprint extracts the KEK fingerprint from metadata
func (mm *MetadataManagerV2) GetFingerprint(metadata map[string]string) (string, error) {
	fingerprint, exists := metadata[mm.prefix+"kek-fingerprint"]
	if !exists {
		return "", fmt.Errorf("KEK fingerprint not found in metadata")
	}

	mm.logger.WithField("fingerprint", fingerprint).Debug("Retrieved fingerprint from metadata")
	return fingerprint, nil
}

// GetIV extracts and decodes the IV from metadata
func (mm *MetadataManagerV2) GetIV(metadata map[string]string) ([]byte, error) {
	ivStr, exists := metadata[mm.prefix+"aes-iv"]
	if !exists {
		return nil, fmt.Errorf("IV not found in metadata")
	}

	iv, err := base64.StdEncoding.DecodeString(ivStr)
	if err != nil {
		mm.logger.WithFields(logrus.Fields{
			"metadata_key": mm.prefix + "aes-iv",
			"error":        err,
		}).Error("Failed to decode IV from metadata")
		return nil, fmt.Errorf("failed to decode IV: %w", err)
	}

	mm.logger.WithField("iv_size", len(iv)).Debug("Successfully extracted IV")
	return iv, nil
}

// GetHMAC extracts and decodes the HMAC from metadata
func (mm *MetadataManagerV2) GetHMAC(metadata map[string]string) ([]byte, error) {
	hmacStr, exists := metadata[mm.prefix+"hmac"]
	if !exists {
		return nil, fmt.Errorf("HMAC not found in metadata")
	}

	hmacBytes, err := base64.StdEncoding.DecodeString(hmacStr)
	if err != nil {
		mm.logger.WithFields(logrus.Fields{
			"metadata_key": mm.prefix + "hmac",
			"error":        err,
		}).Error("Failed to decode HMAC from metadata")
		return nil, fmt.Errorf("failed to decode HMAC: %w", err)
	}

	mm.logger.WithField("hmac_size", len(hmacBytes)).Debug("Successfully extracted HMAC")
	return hmacBytes, nil
}

// SetHMAC adds HMAC to metadata
func (mm *MetadataManagerV2) SetHMAC(metadata map[string]string, hmacBytes []byte) {
	metadata[mm.prefix+"hmac"] = base64.StdEncoding.EncodeToString(hmacBytes)

	mm.logger.WithField("hmac_size", len(hmacBytes)).Debug("Set HMAC in metadata")
}

// HasHMAC checks if HMAC exists in metadata
func (mm *MetadataManagerV2) HasHMAC(metadata map[string]string) bool {
	_, exists := metadata[mm.prefix+"hmac"]
	return exists
}

// ValidateEncryptionMetadata validates that all required encryption metadata is present
func (mm *MetadataManagerV2) ValidateEncryptionMetadata(metadata map[string]string) error {
	requiredKeys := []string{"encrypted-dek", "dek-algorithm", "kek-fingerprint"}

	for _, key := range requiredKeys {
		if _, exists := metadata[mm.prefix+key]; !exists {
			mm.logger.WithField("missing_key", mm.prefix+key).Error("Required encryption metadata missing")
			return fmt.Errorf("required encryption metadata '%s' is missing", mm.prefix+key)
		}
	}

	mm.logger.Debug("Encryption metadata validation passed")
	return nil
}

// GetMetadataPrefix returns the configured metadata prefix
func (mm *MetadataManagerV2) GetMetadataPrefix() string {
	return mm.prefix
}

// countEncryptionKeys counts how many encryption-related keys are in metadata
func (mm *MetadataManagerV2) countEncryptionKeys(metadata map[string]string) int {
	count := 0
	for key := range metadata {
		if strings.HasPrefix(key, mm.prefix) {
			count++
		}
	}
	return count
}

// Legacy MetadataManager for backward compatibility
type MetadataManager struct {
	prefix string
}

// NewMetadataManager creates a new metadata manager with the given prefix
func NewMetadataManager(prefix string) *MetadataManager {
	return &MetadataManager{
		prefix: prefix,
	}
}

// GetHMACMetadataKey returns the HMAC metadata key with prefix
func (m *MetadataManager) GetHMACMetadataKey() string {
	return m.prefix + "hmac"
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

// addMetadataPrefix adds the configured prefix to a metadata key
func (m *MetadataManagerV2) addMetadataPrefix(key string) string {
	if m.prefix == "" {
		return key
	}
	return m.prefix + key
}

// BuildMetadataKey creates a metadata key with the configured prefix
func (m *MetadataManagerV2) BuildMetadataKey(key string) string {
	return m.addMetadataPrefix(key)
}

// ExtractMetadataKey removes the prefix from a metadata key
func (m *MetadataManagerV2) ExtractMetadataKey(fullKey string) string {
	if m.prefix == "" {
		return fullKey
	}
	return strings.TrimPrefix(fullKey, m.prefix)
}

// IsEncryptionMetadata checks if a metadata key is encryption-related
func (m *MetadataManagerV2) IsEncryptionMetadata(key string) bool {
	// Standard encryption metadata keys
	encryptionKeys := []string{
		"dek-algorithm",
		"encrypted-dek",
		"aes-iv",
		"kek-algorithm",
		"kek-fingerprint",
		"hmac",
		"encryption-mode",
		"content-type",
		"algorithm",
	}

	// Check if key matches any encryption metadata (with or without prefix)
	baseKey := m.ExtractMetadataKey(key)
	for _, encKey := range encryptionKeys {
		if baseKey == encKey {
			return true
		}
	}

	return false
}

// FilterEncryptionMetadata removes all encryption metadata from a map (for client responses)
func (m *MetadataManagerV2) FilterEncryptionMetadata(metadata map[string]string) map[string]string {
	if metadata == nil {
		return nil
	}

	filtered := make(map[string]string)
	for key, value := range metadata {
		if !m.IsEncryptionMetadata(key) {
			filtered[key] = value
		}
	}

	return filtered
}

// ExtractRequiredFingerprint extracts the required KEK fingerprint from metadata
func (m *MetadataManagerV2) ExtractRequiredFingerprint(metadata map[string]string) string {
	if metadata == nil {
		return ""
	}

	// Try various metadata keys where the fingerprint might be stored
	fingerprintKeys := []string{
		m.BuildMetadataKey("kek-fingerprint"),
		m.BuildMetadataKey("key-id"),
		"kek-fingerprint",   // fallback without prefix
		"s3ep-kek-fingerprint", // legacy support
		"s3ep-key-id",      // legacy support
		"encryption-kek-fingerprint", // alternative format
	}

	for _, key := range fingerprintKeys {
		if fingerprint, exists := metadata[key]; exists && fingerprint != "" {
			m.logger.WithFields(logrus.Fields{
				"metadata_key": key,
				"fingerprint": fingerprint,
			}).Debug("Found KEK fingerprint in metadata")
			return fingerprint
		}
	}

	m.logger.Debug("No KEK fingerprint found in metadata")
	return ""
}

// ValidateMetadata validates encryption metadata for completeness
func (m *MetadataManagerV2) ValidateMetadata(metadata map[string]string) error {
	if metadata == nil {
		return fmt.Errorf("metadata cannot be nil")
	}

	// Check for required encryption metadata
	requiredKeys := []string{
		"encrypted-dek",
		"kek-fingerprint",
	}

	var missingKeys []string
	for _, key := range requiredKeys {
		fullKey := m.BuildMetadataKey(key)
		if _, exists := metadata[fullKey]; !exists {
			missingKeys = append(missingKeys, fullKey)
		}
	}

	if len(missingKeys) > 0 {
		return fmt.Errorf("missing required metadata keys: %v", missingKeys)
	}

	return nil
}

// AddStandardMetadata adds standard encryption metadata fields
func (m *MetadataManagerV2) AddStandardMetadata(metadata map[string]string, fingerprint string, algorithm string) {
	if metadata == nil {
		return
	}

	metadata[m.BuildMetadataKey("kek-fingerprint")] = fingerprint
	if algorithm != "" {
		metadata[m.BuildMetadataKey("algorithm")] = algorithm
	}
}

// GetAlgorithmFromMetadata extracts the encryption algorithm from metadata
func (m *MetadataManagerV2) GetAlgorithmFromMetadata(metadata map[string]string) string {
	if metadata == nil {
		return ""
	}

	// Try different algorithm keys
	algorithmKeys := []string{
		m.BuildMetadataKey("dek-algorithm"),
		m.BuildMetadataKey("algorithm"),
		"dek-algorithm", // fallback without prefix
		"algorithm",     // fallback without prefix
	}

	for _, key := range algorithmKeys {
		if algorithm, exists := metadata[key]; exists && algorithm != "" {
			return algorithm
		}
	}

	return ""
}

// CreateMissingKEKError creates a detailed error message when the required KEK is not available
func (m *MetadataManagerV2) CreateMissingKEKError(objectKey, requiredFingerprint string, metadata map[string]string) error {
	// Determine the KEK type from metadata or fingerprint pattern
	kekType := "unknown"

	if metadata != nil {
		if kekAlg, exists := metadata[m.BuildMetadataKey("kek-algorithm")]; exists {
			kekType = kekAlg
		}
	}

	m.logger.WithFields(logrus.Fields{
		"object_key": objectKey,
		"required_fingerprint": requiredFingerprint,
		"kek_type": kekType,
	}).Error("Missing required KEK for decryption")

	return fmt.Errorf("❌ KEK_MISSING: Object '%s' requires KEK fingerprint '%s' (type: %s) - provider not available",
		objectKey, requiredFingerprint, kekType)
}

// ValidateConfiguration validates the metadata manager configuration
func (m *MetadataManagerV2) ValidateConfiguration() error {
	if m.config == nil {
		return fmt.Errorf("configuration cannot be nil")
	}

	// Validate prefix configuration
	if m.config.Encryption.MetadataKeyPrefix != nil {
		prefix := *m.config.Encryption.MetadataKeyPrefix
		// Empty string is valid (means no prefix)
		// Check for invalid characters that might cause issues
		if strings.Contains(prefix, " ") || strings.Contains(prefix, "\t") || strings.Contains(prefix, "\n") {
			return fmt.Errorf("metadata prefix cannot contain whitespace characters")
		}
	}

	return nil
}
