package s3client

import (
	"encoding/base64"
	"strings"
)

// MetadataHelper provides utility functions for encryption metadata handling
type MetadataHelper struct {
	metadataPrefix string
}

// NewMetadataHelper creates a new metadata helper with the specified prefix
func NewMetadataHelper(metadataPrefix string) *MetadataHelper {
	return &MetadataHelper{
		metadataPrefix: metadataPrefix,
	}
}

// ExtractEncryptionMetadata extracts encryption-related metadata from S3 object metadata
func (m *MetadataHelper) ExtractEncryptionMetadata(metadata map[string]string) (encryptedDEK string, isEncrypted bool, isStreaming bool) {
	// Check for legacy format first (s3ep-dek)
	if encryptedDEKB64, exists := metadata[m.metadataPrefix+"dek"]; exists {
		return encryptedDEKB64, true, false
	}

	// Check for new prefixed format (s3ep-encrypted-dek)
	if encryptedDEKB64, exists := metadata[m.metadataPrefix+"encrypted-dek"]; exists {
		// Check if this is a multipart encrypted object (uses streaming decryption)
		// Only AES-CTR indicates streaming encryption, AES-GCM is handled differently
		if dekAlgorithm, streamingExists := metadata[m.metadataPrefix+"dek-algorithm"]; streamingExists {
			return encryptedDEKB64, true, dekAlgorithm == "aes-256-ctr"
		}
		return encryptedDEKB64, true, false
	}

	// Check for legacy unprefixed metadata
	if encryptedDEKB64, exists := metadata["encrypted-dek"]; exists {
		if dekAlgorithm, streamingExists := metadata["dek-algorithm"]; streamingExists {
			return encryptedDEKB64, true, dekAlgorithm == "aes-256-ctr"
		}
		return encryptedDEKB64, true, false
	}

	return "", false, false
}

// DecodeEncryptedDEK decodes the base64-encoded encrypted DEK
func (m *MetadataHelper) DecodeEncryptedDEK(encryptedDEKB64 string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(encryptedDEKB64)
}

// CleanMetadata removes encryption-specific metadata from client response
func (m *MetadataHelper) CleanMetadata(metadata map[string]string) map[string]string {
	cleanMetadata := make(map[string]string)
	for k, v := range metadata {
		// Filter out prefixed encryption metadata
		if strings.HasPrefix(k, m.metadataPrefix) {
			continue
		}
		// Filter out legacy unprefixed encryption metadata
		if k == "dek-algorithm" || k == "kek-algorithm" || k == "kek-fingerprint" ||
			k == "upload-id" || k == "encrypted-dek" || k == "aes-iv" ||
			strings.HasPrefix(k, "encryption-") {
			continue
		}
		cleanMetadata[k] = v
	}
	return cleanMetadata
}

// PrepareEncryptionMetadata prepares metadata for storage with encryption info
func (m *MetadataHelper) PrepareEncryptionMetadata(userMetadata, encryptionMetadata map[string]string) map[string]string {
	if encryptionMetadata == nil && userMetadata == nil {
		return nil
	}

	// Start with user metadata
	metadata := make(map[string]string)
	for k, v := range userMetadata {
		metadata[k] = v
	}

	// Add encryption metadata if provided
	for k, v := range encryptionMetadata {
		metadata[k] = v
	}

	return metadata
}
