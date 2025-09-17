package encryption

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"sync"

	"github.com/sirupsen/logrus"

	"github.com/guided-traffic/s3-encryption-proxy/internal/config"
	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption/dataencryption"
	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption/factory"
)

// SinglePartOperations handles encryption and decryption of single-part objects
// with clear separation between GCM and CTR algorithms
type SinglePartOperations struct {
	providerManager *ProviderManager
	metadataManager *MetadataManagerV2
	hmacManager     *HMACManager
	bufferPool      *sync.Pool
	config          *config.Config
	logger          *logrus.Entry
}

// EncryptionResult represents the result of an encryption operation
type EncryptionResult struct {
	EncryptedData []byte
	Metadata      map[string]string
	Algorithm     string
	KeyFingerprint string
}

// NewSinglePartOperations creates a new single part operations handler
func NewSinglePartOperations(
	providerManager *ProviderManager,
	metadataManager *MetadataManagerV2,
	hmacManager *HMACManager,
	config *config.Config,
) *SinglePartOperations {
	logger := logrus.WithField("component", "single_part_operations")

	// Create buffer pool for performance optimization
	bufferPool := &sync.Pool{
		New: func() interface{} {
			return make([]byte, 0, 64*1024) // 64KB initial capacity
		},
	}

	spo := &SinglePartOperations{
		providerManager: providerManager,
		metadataManager: metadataManager,
		hmacManager:     hmacManager,
		bufferPool:      bufferPool,
		config:          config,
		logger:          logger,
	}

	logger.Info("Initialized single part operations")
	return spo
}

// ShouldUseGCM returns true if the data size is below the streaming threshold
func (spo *SinglePartOperations) ShouldUseGCM(dataSize int64) bool {
	return dataSize < spo.GetThreshold()
}

// GetThreshold returns the threshold size for choosing between GCM and CTR encryption
func (spo *SinglePartOperations) GetThreshold() int64 {
	if spo.config != nil {
		return spo.config.GetStreamingSegmentSize()
	}
	return 5 * 1024 * 1024 // Default 5MB threshold
}

// EncryptGCM encrypts data using AES-GCM for small objects
func (s *SinglePartOperations) EncryptGCM(ctx context.Context, data []byte, objectKey string) (*EncryptionResult, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("data is empty")
	}

	logger := s.logger.WithFields(logrus.Fields{
		"operation":  "encrypt-gcm",
		"object_key": objectKey,
		"data_size":  len(data),
	})

	// Get active provider alias for logging
	activeProviderAlias := s.providerManager.GetActiveProviderAlias()
	logger = logger.WithField("active_provider", activeProviderAlias)

	// Create envelope encryptor for GCM using provider manager
	metadataPrefix := s.getMetadataPrefix()
	envelopeEncryptor, err := s.providerManager.CreateEnvelopeEncryptor(
		factory.ContentTypeWhole,
		metadataPrefix,
	)
	if err != nil {
		logger.WithError(err).Error("Failed to create GCM envelope encryptor")
		return nil, fmt.Errorf("failed to create GCM envelope encryptor: %w", err)
	}

	// Use object key as associated data for additional security
	associatedData := []byte(objectKey)

	// Encrypt data
	var encryptedData []byte
	var metadata map[string]string

	if s.hmacManager.IsEnabled() {
		logger.Debug("Using HMAC-enabled GCM encryption")
		encryptedData, _, metadata, err = envelopeEncryptor.EncryptDataWithHMAC(ctx, data, associatedData)
		if err != nil {
			logger.WithError(err).Error("Failed to encrypt data with HMAC")
			return nil, fmt.Errorf("failed to encrypt data with HMAC: %w", err)
		}
	} else {
		logger.Debug("Using standard GCM encryption")
		encryptedData, _, metadata, err = envelopeEncryptor.EncryptData(ctx, data, associatedData)
		if err != nil {
			logger.WithError(err).Error("Failed to encrypt data")
			return nil, fmt.Errorf("failed to encrypt data: %w", err)
		}
	}

	// Build final metadata result
	// For GCM, we don't have access to the raw DEK or IV here since they're handled by the envelope encryptor
	// The metadata from the encryptor should already contain what we need
	finalMetadata := metadata

	logger.WithFields(logrus.Fields{
		"encrypted_size": len(encryptedData),
		"metadata_count": len(finalMetadata),
	}).Debug("GCM encryption completed successfully")

	return &EncryptionResult{
		EncryptedData: encryptedData,
		Metadata:      finalMetadata,
	}, nil
}

// EncryptCTR encrypts data using AES-CTR for large objects or streaming
func (s *SinglePartOperations) EncryptCTR(ctx context.Context, data []byte, objectKey string) (*EncryptionResult, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("data is empty")
	}

	logger := s.logger.WithFields(logrus.Fields{
		"operation":  "encrypt-ctr",
		"object_key": objectKey,
		"data_size":  len(data),
	})

	// Generate 32-byte DEK for AES-256
	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		logger.WithError(err).Error("Failed to generate DEK")
		return nil, fmt.Errorf("failed to generate DEK: %w", err)
	}

	// Generate 16-byte IV for AES-CTR
	iv := make([]byte, 16)
	if _, err := rand.Read(iv); err != nil {
		logger.WithError(err).Error("Failed to generate IV")
		return nil, fmt.Errorf("failed to generate IV: %w", err)
	}

	// Get active provider alias
	activeProviderAlias := s.providerManager.GetActiveProviderAlias()
	logger = logger.WithField("active_provider", activeProviderAlias)

	encryptedDEK, err := s.providerManager.EncryptDEK(dek, objectKey)
	if err != nil {
		logger.WithError(err).Error("Failed to encrypt DEK")
		return nil, fmt.Errorf("failed to encrypt DEK: %w", err)
	}

	// Create AES-CTR encryptor
	ctrEncryptor, err := dataencryption.NewAESCTRStreamingDataEncryptorWithIV(dek, iv, 0)
	if err != nil {
		logger.WithError(err).Error("Failed to create AES-CTR encryptor")
		return nil, fmt.Errorf("failed to create AES-CTR encryptor: %w", err)
	}

	// Encrypt data
	encryptedData, err := ctrEncryptor.EncryptPart(data)
	if err != nil {
		logger.WithError(err).Error("Failed to encrypt data with AES-CTR")
		return nil, fmt.Errorf("failed to encrypt data with AES-CTR: %w", err)
	}

	// Build metadata
	metadataPrefix := s.getMetadataPrefix()
	metadata := map[string]string{
		metadataPrefix + "dek-algorithm":   "aes-256-ctr",
		metadataPrefix + "aes-iv":          base64.StdEncoding.EncodeToString(iv),
		metadataPrefix + "kek-algorithm":   s.providerManager.GetActiveProviderAlgorithm(),
		metadataPrefix + "kek-fingerprint": s.providerManager.GetActiveFingerprint(),
		metadataPrefix + "encrypted-dek":   base64.StdEncoding.EncodeToString(encryptedDEK),
	}

	// Add HMAC if enabled
	if s.hmacManager.IsEnabled() {
		err = s.hmacManager.AddHMACToMetadata(metadata, data, dek, metadataPrefix)
		if err != nil {
			logger.WithError(err).Error("Failed to add HMAC to metadata")
			return nil, fmt.Errorf("failed to add HMAC to metadata: %w", err)
		}
	}

	// Clear sensitive data
	for i := range dek {
		dek[i] = 0
	}

	logger.WithFields(logrus.Fields{
		"encrypted_size": len(encryptedData),
		"metadata_count": len(metadata),
		"iv_size":        len(iv),
	}).Debug("CTR encryption completed successfully")

	return &EncryptionResult{
		EncryptedData:  encryptedData,
		Metadata:       metadata,
		Algorithm:      "aes-ctr",
		KeyFingerprint: s.providerManager.GetActiveFingerprint(),
	}, nil
}

// DecryptData decrypts data using metadata to determine the correct algorithm
func (s *SinglePartOperations) DecryptData(ctx context.Context, encryptedData []byte, metadata map[string]string, objectKey string) ([]byte, error) {
	if len(encryptedData) == 0 {
		return nil, fmt.Errorf("encrypted data is empty")
	}

	logger := s.logger.WithFields(logrus.Fields{
		"operation":        "decrypt",
		"object_key":       objectKey,
		"encrypted_size":   len(encryptedData),
		"metadata_count":   len(metadata),
	})

	// Determine algorithm from metadata
	algorithm := s.getAlgorithmFromMetadata(metadata)
	logger = logger.WithField("algorithm", algorithm)

	switch algorithm {
	case "aes-gcm":
		logger.Debug("Using GCM decryption")
		return s.DecryptGCM(ctx, encryptedData, metadata, objectKey)
	case "aes-256-ctr":
		logger.Debug("Using CTR decryption")
		return s.DecryptCTR(ctx, encryptedData, metadata, objectKey)
	default:
		logger.Error("Unknown algorithm for decryption")
		return nil, fmt.Errorf("unknown algorithm: %s", algorithm)
	}
}

// DecryptGCM decrypts data that was encrypted with AES-GCM
func (s *SinglePartOperations) DecryptGCM(ctx context.Context, encryptedData []byte, metadata map[string]string, objectKey string) ([]byte, error) {
	logger := s.logger.WithFields(logrus.Fields{
		"operation":      "decrypt-gcm",
		"object_key":     objectKey,
		"encrypted_size": len(encryptedData),
	})

	// Validate input
	if len(encryptedData) == 0 {
		logger.Error("Encrypted data is empty")
		return nil, fmt.Errorf("encrypted data is empty")
	}

	// Get the required key encryptor fingerprint
	fingerprint := s.getRequiredFingerprint(metadata)
	if fingerprint == "" {
		logger.Error("Missing fingerprint in metadata")
		return nil, fmt.Errorf("missing key encryptor fingerprint in metadata")
	}

	// Get the encrypted DEK from metadata
	encryptedDEK, err := s.getEncryptedDEKFromMetadata(metadata)
	if err != nil {
		logger.WithError(err).Error("Failed to get encrypted DEK from metadata")
		return nil, fmt.Errorf("failed to get encrypted DEK: %w", err)
	}

	// Decrypt the DEK
	dek, err := s.providerManager.DecryptDEK(encryptedDEK, fingerprint, objectKey)
	if err != nil {
		logger.WithError(err).Error("Failed to decrypt DEK")
		return nil, fmt.Errorf("failed to decrypt DEK: %w", err)
	}
	defer func() {
		// Clear DEK from memory
		for i := range dek {
			dek[i] = 0
		}
	}()

	// Create factory and get envelope encryptor
	factoryInstance := s.providerManager.GetFactory()

	// Use object key as associated data
	associatedData := []byte(objectKey)

	// For GCM, we need to use the envelope decryption
	metadataPrefix := s.getMetadataPrefix()
	envelopeEncryptor, err := factoryInstance.CreateEnvelopeEncryptorWithPrefix(
		factory.ContentTypeWhole,
		fingerprint,
		metadataPrefix,
	)
	if err != nil {
		logger.WithError(err).Error("Failed to create GCM envelope encryptor for decryption")
		return nil, fmt.Errorf("failed to create GCM envelope encryptor: %w", err)
	}

	// Decrypt data
	decryptedData, err := envelopeEncryptor.DecryptData(ctx, encryptedData, encryptedDEK, associatedData)
	if err != nil {
		logger.WithError(err).Error("Failed to decrypt GCM data")
		return nil, fmt.Errorf("failed to decrypt GCM data: %w", err)
	}

	// Verify HMAC if enabled
	err = s.hmacManager.VerifyHMACFromMetadata(metadata, decryptedData, dek, metadataPrefix)
	if err != nil {
		logger.WithError(err).Error("HMAC verification failed")
		return nil, fmt.Errorf("HMAC verification failed: %w", err)
	}

	logger.WithField("decrypted_size", len(decryptedData)).Debug("GCM decryption completed successfully")
	return decryptedData, nil
}

// DecryptCTR decrypts data that was encrypted with AES-CTR
func (s *SinglePartOperations) DecryptCTR(ctx context.Context, encryptedData []byte, metadata map[string]string, objectKey string) ([]byte, error) {
	logger := s.logger.WithFields(logrus.Fields{
		"operation":      "decrypt-ctr",
		"object_key":     objectKey,
		"encrypted_size": len(encryptedData),
	})

	// Validate input
	if len(encryptedData) == 0 {
		logger.Error("Encrypted data is empty")
		return nil, fmt.Errorf("encrypted data is empty")
	}

	// Get the required key encryptor fingerprint
	fingerprint := s.getRequiredFingerprint(metadata)
	if fingerprint == "" {
		logger.Error("Missing fingerprint in metadata")
		return nil, fmt.Errorf("missing key encryptor fingerprint in metadata")
	}

	// Get the encrypted DEK from metadata
	encryptedDEK, err := s.getEncryptedDEKFromMetadata(metadata)
	if err != nil {
		logger.WithError(err).Error("Failed to get encrypted DEK from metadata")
		return nil, fmt.Errorf("failed to get encrypted DEK: %w", err)
	}

	// Decrypt the DEK
	dek, err := s.providerManager.DecryptDEK(encryptedDEK, fingerprint, objectKey)
	if err != nil {
		logger.WithError(err).Error("Failed to decrypt DEK")
		return nil, fmt.Errorf("failed to decrypt DEK: %w", err)
	}
	defer func() {
		// Clear DEK from memory
		for i := range dek {
			dek[i] = 0
		}
	}()

	// Get IV from metadata
	iv, err := s.getIVFromMetadata(metadata)
	if err != nil {
		logger.WithError(err).Error("Failed to get IV from metadata")
		return nil, fmt.Errorf("failed to get IV from metadata: %w", err)
	}

	// Create AES-CTR decryptor
	ctrDecryptor, err := dataencryption.NewAESCTRStreamingDataEncryptorWithIV(dek, iv, 0)
	if err != nil {
		logger.WithError(err).Error("Failed to create AES-CTR decryptor")
		return nil, fmt.Errorf("failed to create AES-CTR decryptor: %w", err)
	}

	// Decrypt data (AES-CTR decryption is the same operation as encryption)
	decryptedData, err := ctrDecryptor.EncryptPart(encryptedData)
	if err != nil {
		logger.WithError(err).Error("Failed to decrypt CTR data")
		return nil, fmt.Errorf("failed to decrypt CTR data: %w", err)
	}

	// Verify HMAC if enabled
	metadataPrefix := s.getMetadataPrefix()
	err = s.hmacManager.VerifyHMACFromMetadata(metadata, decryptedData, dek, metadataPrefix)
	if err != nil {
		logger.WithError(err).Error("HMAC verification failed")
		return nil, fmt.Errorf("HMAC verification failed: %w", err)
	}

	logger.WithField("decrypted_size", len(decryptedData)).Debug("CTR decryption completed successfully")
	return decryptedData, nil
}

// shouldUseGCM determines if GCM should be used based on data size
func (s *SinglePartOperations) shouldUseGCM(dataSize int) bool {
	// Default streaming threshold is 5MB
	threshold := int64(5 * 1024 * 1024)

	if s.config != nil && s.config.Optimizations.StreamingThreshold > 0 {
		threshold = s.config.Optimizations.StreamingThreshold
	}

	return int64(dataSize) < threshold
}

// getMetadataPrefix returns the configured metadata prefix
func (s *SinglePartOperations) getMetadataPrefix() string {
	if s.config == nil || s.config.Encryption.MetadataKeyPrefix == nil {
		return "s3ep-" // default
	}
	return *s.config.Encryption.MetadataKeyPrefix
}

// getAlgorithmFromMetadata extracts the encryption algorithm from metadata
func (s *SinglePartOperations) getAlgorithmFromMetadata(metadata map[string]string) string {
	metadataPrefix := s.getMetadataPrefix()

	// Try with prefix first
	if algorithm, exists := metadata[metadataPrefix+"dek-algorithm"]; exists {
		return algorithm
	}

	// Fallback to no prefix for backward compatibility
	if algorithm, exists := metadata["dek-algorithm"]; exists {
		return algorithm
	}

	// Default to GCM if not specified
	return "aes-gcm"
}

// getRequiredFingerprint extracts the required key fingerprint from metadata
func (s *SinglePartOperations) getRequiredFingerprint(metadata map[string]string) string {
	metadataPrefix := s.getMetadataPrefix()

	// Try with prefix first
	if fingerprint, exists := metadata[metadataPrefix+"kek-fingerprint"]; exists {
		return fingerprint
	}

	// Fallback to no prefix for backward compatibility
	if fingerprint, exists := metadata["kek-fingerprint"]; exists {
		return fingerprint
	}

	return ""
}

// getEncryptedDEKFromMetadata extracts the encrypted DEK from metadata
func (s *SinglePartOperations) getEncryptedDEKFromMetadata(metadata map[string]string) ([]byte, error) {
	metadataPrefix := s.getMetadataPrefix()

	var encryptedDEKBase64 string
	var exists bool

	// Try with prefix first
	if encryptedDEKBase64, exists = metadata[metadataPrefix+"encrypted-dek"]; !exists {
		// Fallback to no prefix for backward compatibility
		if encryptedDEKBase64, exists = metadata["encrypted-dek"]; !exists {
			return nil, fmt.Errorf("encrypted DEK not found in metadata")
		}
	}

	encryptedDEK, err := base64.StdEncoding.DecodeString(encryptedDEKBase64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode encrypted DEK: %w", err)
	}

	return encryptedDEK, nil
}

// getIVFromMetadata extracts the IV from metadata
func (s *SinglePartOperations) getIVFromMetadata(metadata map[string]string) ([]byte, error) {
	metadataPrefix := s.getMetadataPrefix()

	var ivBase64 string
	var exists bool

	// Try with prefix first
	if ivBase64, exists = metadata[metadataPrefix+"aes-iv"]; !exists {
		// Fallback to no prefix for backward compatibility
		if ivBase64, exists = metadata["aes-iv"]; !exists {
			return nil, fmt.Errorf("IV not found in metadata")
		}
	}

	iv, err := base64.StdEncoding.DecodeString(ivBase64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode IV: %w", err)
	}

	return iv, nil
}
