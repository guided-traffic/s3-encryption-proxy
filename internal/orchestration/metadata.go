package orchestration

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/guided-traffic/s3-encryption-proxy/internal/config"
	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption/dataencryption"
)

// MetadataManager handles all encryption metadata operations with comprehensive functionality
type MetadataManager struct {
	// Core configuration
	config *config.Config
	logger *logrus.Entry

	// Metadata configuration
	prefix string
}

// NewMetadataManager creates a new comprehensive metadata manager
func NewMetadataManager(cfg *config.Config, prefix string) *MetadataManager {
	if prefix == "" {
		if cfg.Encryption.MetadataKeyPrefix != nil {
			prefix = *cfg.Encryption.MetadataKeyPrefix
		} else {
			prefix = "s3ep-" // default prefix
		}
	}

	return &MetadataManager{
		config: cfg,
		logger: logrus.WithField("component", "metadata_manager"),
		prefix: prefix,
	}
}

func (mm *MetadataManager) GetEncryptedDEK(metadata map[string]string) ([]byte, error) {
	// Only the prefixed key. The unprefixed name lies outside the proxy's
	// namespace, so a client can set it through x-amz-meta-* (ADR 0009 D1).
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
func (mm *MetadataManager) GetAlgorithm(metadata map[string]string) (string, error) {
	if algorithm, exists := metadata[mm.prefix+"dek-algorithm"]; exists {
		mm.logger.WithField("algorithm", algorithm).Debug("Retrieved algorithm from metadata")
		return algorithm, nil
	}

	return "", fmt.Errorf("algorithm not found in metadata")
}

// GetFingerprint extracts the KEK fingerprint from metadata
func (mm *MetadataManager) GetFingerprint(metadata map[string]string) (string, error) {
	if fingerprint, exists := metadata[mm.prefix+"kek-fingerprint"]; exists {
		mm.logger.WithField("fingerprint", fingerprint).Debug("Retrieved fingerprint from metadata")
		return fingerprint, nil
	}

	return "", fmt.Errorf("KEK fingerprint not found in metadata")
}

func (mm *MetadataManager) GetMetadataPrefix() string {
	return mm.prefix
}

func (mm *MetadataManager) BuildSegmentedMetadata(
	encryptedDEK []byte, fingerprint, kekAlgorithm string, userMetadata map[string]string,
) map[string]string {
	metadata := make(map[string]string, len(userMetadata)+4)
	for key, value := range userMetadata {
		// The prefix is the proxy's namespace in both directions (ADR 0009 D6).
		// A client header inside it is already refused where user metadata is
		// collected; dropping it here as well means no future caller can put a
		// key in this namespace that a read would then find beside the four
		// this function writes.
		if mm.prefix != "" && strings.HasPrefix(strings.ToLower(key), mm.prefix) {
			continue
		}
		metadata[key] = value
	}

	metadata[mm.prefix+"encrypted-dek"] = base64.StdEncoding.EncodeToString(encryptedDEK)
	metadata[mm.prefix+"dek-algorithm"] = dataencryption.FormatID
	metadata[mm.prefix+"kek-fingerprint"] = fingerprint
	metadata[mm.prefix+"kek-algorithm"] = kekAlgorithm

	return metadata
}
