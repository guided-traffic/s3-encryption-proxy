package s3client

import (
	"strings"
)

// MetadataHandler manages encryption metadata
type MetadataHandler struct {
	prefix string
}

// NewMetadataHandler creates a new metadata handler with the given prefix
func NewMetadataHandler(prefix string) *MetadataHandler {
	return &MetadataHandler{prefix: prefix}
}

// IsEncryptionMetadata checks if a metadata key is encryption-related
func (m *MetadataHandler) IsEncryptionMetadata(key string) bool {
	lowerKey := strings.ToLower(key)
	return strings.HasPrefix(lowerKey, m.prefix) ||
		strings.HasPrefix(lowerKey, "s3ep-") // Legacy support
}

// CleanMetadata removes encryption metadata from a metadata map
func (m *MetadataHandler) CleanMetadata(metadata map[string]string) map[string]string {
	if metadata == nil {
		return nil
	}

	clean := make(map[string]string)
	for k, v := range metadata {
		if !m.IsEncryptionMetadata(k) {
			clean[k] = v
		}
	}
	return clean
}

// ExtractEncryptedDEK extracts the encrypted DEK from metadata
func (m *MetadataHandler) ExtractEncryptedDEK(metadata map[string]string) (string, bool) {
	if metadata == nil {
		return "", false
	}

	// Check new format first
	if dek, ok := metadata[m.prefix+"encrypted-dek"]; ok {
		return dek, true
	}

	// Fallback to legacy format
	if dek, ok := metadata["s3ep-dek"]; ok {
		return dek, true
	}

	return "", false
}

// IsStreamingEncryption checks if object uses streaming encryption
func (m *MetadataHandler) IsStreamingEncryption(metadata map[string]string) bool {
	if metadata == nil {
		return false
	}

	_, hasNew := metadata[m.prefix+"content-type"]
	_, hasLegacy := metadata["s3ep-content-type"]
	return hasNew || hasLegacy
}

// GetContentType extracts content type metadata
func (m *MetadataHandler) GetContentType(metadata map[string]string) (string, bool) {
	if metadata == nil {
		return "", false
	}

	// Check new format first
	if ct, ok := metadata[m.prefix+"content-type"]; ok {
		return ct, true
	}

	// Fallback to legacy format
	if ct, ok := metadata["s3ep-content-type"]; ok {
		return ct, true
	}

	return "", false
}
