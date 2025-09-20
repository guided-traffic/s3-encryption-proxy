package orchestration

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"sync"

	"github.com/sirupsen/logrus"

	"github.com/guided-traffic/s3-encryption-proxy/internal/config"
	"github.com/guided-traffic/s3-encryption-proxy/internal/validation"
	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption"
	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption/dataencryption"
	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption/factory"
)

// hmacWriter implements io.Writer to calculate HMAC during streaming
type hmacWriter struct {
	calculator *validation.HMACCalculator
}

func (hw *hmacWriter) Write(p []byte) (n int, err error) {
	return hw.calculator.Add(p)
}

// SinglePartOperations handles encryption and decryption of single-part objects
// with clear separation between GCM and CTR algorithms
type SinglePartOperations struct {
	providerManager *ProviderManager
	metadataManager *MetadataManager
	hmacManager     *validation.HMACManager
	bufferPool      *sync.Pool
	config          *config.Config
	logger          *logrus.Entry
}

// EncryptionResult represents the result of an encryption operation
type EncryptionResult struct {
	EncryptedData  *bufio.Reader     // Streaming encrypted data
	Metadata       map[string]string // Encryption metadata
	Algorithm      string            // Encryption algorithm used
	KeyFingerprint string            // Key fingerprint for decryption
}

// NewSinglePartOperations creates a new single part operations handler
func NewSinglePartOperations(
	providerManager *ProviderManager,
	metadataManager *MetadataManager,
	hmacManager *validation.HMACManager,
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
func (s *SinglePartOperations) EncryptGCM(ctx context.Context, dataReader *bufio.Reader, objectKey string) (*EncryptionResult, error) {
	logger := s.logger.WithFields(logrus.Fields{
		"operation":  "encrypt-gcm",
		"object_key": objectKey,
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

	// Encrypt data using streaming interface
	logger.Debug("Using GCM encryption with streaming")
	encryptedReader, _, metadata, err := envelopeEncryptor.EncryptDataStream(ctx, dataReader, associatedData)
	if err != nil {
		logger.WithError(err).Error("Failed to encrypt data")
		return nil, fmt.Errorf("failed to encrypt data: %w", err)
	}

	// Add HMAC if enabled (post-encryption)
	if s.hmacManager.IsEnabled() {

		logger.Info("Skipping HMAC for GCM encryption (GCM provides built-in authentication)")

		// // We need to read the encrypted data to compute HMAC, then create a new reader
		// encryptedData, err := io.ReadAll(encryptedReader)
		// if err != nil {
		// 	logger.WithError(err).Error("Failed to read encrypted data for HMAC")
		// 	return nil, fmt.Errorf("failed to read encrypted data for HMAC: %w", err)
		// }

		// // Decrypt DEK to compute HMAC on original data
		// dek, err := s.providerManager.DecryptDEK(encryptedDEK, s.providerManager.GetActiveFingerprint(), objectKey)
		// if err != nil {
		// 	logger.WithError(err).Error("Failed to decrypt DEK for HMAC")
		// 	return nil, fmt.Errorf("failed to decrypt DEK for HMAC: %w", err)
		// }
		// defer func() {
		// 	for i := range dek {
		// 		dek[i] = 0
		// 	}
		// }()

		// // Decrypt data to get original for HMAC
		// decryptedReader, err := envelopeEncryptor.DecryptDataStream(ctx, bufio.NewReader(bytes.NewReader(encryptedData)), encryptedDEK, nil, associatedData)
		// if err != nil {
		// 	logger.WithError(err).Error("Failed to decrypt for HMAC calculation")
		// 	return nil, fmt.Errorf("failed to decrypt for HMAC calculation: %w", err)
		// }

		// originalData, err := io.ReadAll(decryptedReader)
		// if err != nil {
		// 	logger.WithError(err).Error("Failed to read decrypted data for HMAC")
		// 	return nil, fmt.Errorf("failed to read decrypted data for HMAC: %w", err)
		// }

		// // Add HMAC to metadata using new HMACManager
		// hmacCalculator, err := s.hmacManager.CreateCalculator(dek)
		// if err != nil {
		// 	logger.WithError(err).Error("Failed to create HMAC calculator")
		// 	return nil, fmt.Errorf("failed to create HMAC calculator: %w", err)
		// }

		// _, err = hmacCalculator.Add(originalData)
		// if err != nil {
		// 	logger.WithError(err).Error("Failed to add data to HMAC calculator")
		// 	return nil, fmt.Errorf("failed to add data to HMAC calculator: %w", err)
		// }

		// finalHMAC := s.hmacManager.FinalizeCalculator(hmacCalculator)
		// if len(finalHMAC) > 0 {
		// 	s.metadataManager.SetHMAC(metadata, finalHMAC)
		// }

		// // Recreate reader for encrypted data
		// encryptedReader = bufio.NewReader(bytes.NewReader(encryptedData))
	}

	logger.WithField("metadata_count", len(metadata)).Debug("GCM encryption completed successfully")

	return &EncryptionResult{
		EncryptedData:  encryptedReader,
		Metadata:       metadata,
		Algorithm:      "aes-gcm",
		KeyFingerprint: s.providerManager.GetActiveFingerprint(),
	}, nil
}

// EncryptCTR encrypts data using AES-CTR for large objects or streaming
func (s *SinglePartOperations) EncryptCTR(ctx context.Context, dataReader *bufio.Reader, objectKey string) (*EncryptionResult, error) {
	logger := s.logger.WithFields(logrus.Fields{
		"operation":  "encrypt-ctr",
		"object_key": objectKey,
	})

	// Get active provider alias
	activeProviderAlias := s.providerManager.GetActiveProviderAlias()
	logger = logger.WithField("active_provider", activeProviderAlias)

	// Generate 32-byte DEK for AES-256
	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		logger.WithError(err).Error("Failed to generate DEK")
		return nil, fmt.Errorf("failed to generate DEK: %w", err)
	}
	defer func() {
		// Clear DEK from memory
		for i := range dek {
			dek[i] = 0
		}
	}()

	// Encrypt DEK with provider
	encryptedDEK, err := s.providerManager.EncryptDEK(dek, objectKey)
	if err != nil {
		logger.WithError(err).Error("Failed to encrypt DEK")
		return nil, fmt.Errorf("failed to encrypt DEK: %w", err)
	}

	// Create AES-CTR data encryptor
	ctrEncryptor := dataencryption.NewAESCTRDataEncryptor()

	// Use object key as associated data for additional security
	associatedData := []byte(objectKey)

	// TODO: Find a better solution for HMAC with CTR encryption

	// For CTR encryption, we have two options based on HMAC requirements:
	// 1. HMAC enabled: Use streaming approach with buffering (needed for single-part CTR)
	// 2. HMAC disabled: Direct streaming without buffering
	var hmacValue []byte

	if s.hmacManager.IsEnabled() {
		// For HMAC-enabled CTR, we need to read the data first to calculate HMAC
		// This is acceptable for single-part operations which are typically smaller
		originalData, err := io.ReadAll(dataReader)
		if err != nil {
			logger.WithError(err).Error("Failed to read data for HMAC calculation")
			return nil, fmt.Errorf("failed to read data for HMAC calculation: %w", err)
		}

		// Calculate HMAC using the streaming interface
		hmacCalculator, err := s.hmacManager.CreateCalculator(dek)
		if err != nil {
			logger.WithError(err).Error("Failed to create HMAC calculator")
			return nil, fmt.Errorf("failed to create HMAC calculator: %w", err)
		}

		_, err = hmacCalculator.AddFromStream(bufio.NewReader(bytes.NewReader(originalData)))
		if err != nil {
			logger.WithError(err).Error("Failed to calculate HMAC from stream")
			return nil, fmt.Errorf("failed to calculate HMAC from stream: %w", err)
		}

		hmacValue = s.hmacManager.FinalizeCalculator(hmacCalculator)

		// Recreate reader for encryption
		dataReader = bufio.NewReader(bytes.NewReader(originalData))
	}

	// Encrypt data using streaming interface
	encryptedReader, err := ctrEncryptor.EncryptStream(ctx, dataReader, dek, associatedData)
	if err != nil {
		logger.WithError(err).Error("Failed to encrypt data with AES-CTR")
		return nil, fmt.Errorf("failed to encrypt data with AES-CTR: %w", err)
	}

	// Get IV from the encryptor (if it implements IVProvider)
	var iv []byte
	if ivProvider, ok := ctrEncryptor.(encryption.IVProvider); ok {
		iv = ivProvider.GetLastIV()
	}
	if iv == nil {
		logger.Error("Failed to get IV from CTR encryptor")
		return nil, fmt.Errorf("failed to get IV from CTR encryptor")
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

	// Add HMAC to metadata if it was computed
	if s.hmacManager.IsEnabled() && len(hmacValue) > 0 {
		s.metadataManager.SetHMAC(metadata, hmacValue)
	}

	logger.WithFields(logrus.Fields{
		"metadata_count": len(metadata),
		"iv_size":        len(iv),
	}).Debug("CTR encryption completed successfully")

	return &EncryptionResult{
		EncryptedData:  encryptedReader,
		Metadata:       metadata,
		Algorithm:      "aes-ctr",
		KeyFingerprint: s.providerManager.GetActiveFingerprint(),
	}, nil
}

// DecryptData decrypts data using metadata to determine the correct algorithm
func (s *SinglePartOperations) DecryptData(ctx context.Context, encryptedReader *bufio.Reader, metadata map[string]string, objectKey string) (*bufio.Reader, error) {
	logger := s.logger.WithFields(logrus.Fields{
		"operation":      "decrypt",
		"object_key":     objectKey,
		"metadata_count": len(metadata),
	})

	// Determine algorithm from metadata
	algorithm := s.getAlgorithmFromMetadata(metadata)
	logger = logger.WithField("algorithm", algorithm)

	switch algorithm {
	case "aes-gcm", "aes-256-gcm":
		logger.Debug("Using GCM decryption")
		return s.DecryptGCM(ctx, encryptedReader, metadata, objectKey)
	case "aes-256-ctr":
		logger.Debug("Using CTR decryption")
		return s.DecryptCTR(ctx, encryptedReader, metadata, objectKey)
	default:
		logger.Error("Unknown algorithm for decryption")
		return nil, fmt.Errorf("unknown algorithm: %s", algorithm)
	}
}

// DecryptGCM decrypts data that was encrypted with AES-GCM
func (s *SinglePartOperations) DecryptGCM(ctx context.Context, encryptedReader *bufio.Reader, metadata map[string]string, objectKey string) (*bufio.Reader, error) {
	logger := s.logger.WithFields(logrus.Fields{
		"operation":  "decrypt-gcm",
		"object_key": objectKey,
	})

	// Check if encrypted data is empty first (before metadata validation)
	if encryptedReader != nil {
		// Peek at the first byte to check if data is available
		_, err := encryptedReader.Peek(1)
		if err == io.EOF {
			logger.Error("Empty encrypted data for decryption")
			return nil, fmt.Errorf("encrypted data is empty")
		}
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

	// Get IV from metadata (for GCM this is the nonce)
	// Note: For GCM, the nonce is also prepended to the encrypted data,
	// so we pass nil to let the decryptor extract it from the data
	var iv []byte = nil // Force extraction from encrypted data

	// Decrypt data using streaming interface
	decryptedReader, err := envelopeEncryptor.DecryptDataStream(ctx, encryptedReader, encryptedDEK, iv, associatedData)
	if err != nil {
		logger.WithError(err).Error("Failed to decrypt GCM data")
		return nil, fmt.Errorf("failed to decrypt GCM data: %w", err)
	}

	// Verify HMAC if enabled and present in metadata
	if s.hmacManager.IsEnabled() {
		// Check if HMAC exists in metadata first
		expectedHMAC, err := s.metadataManager.GetHMAC(metadata)
		if err != nil {
			// HMAC not found in metadata - this is OK for objects encrypted without HMAC
			logger.WithError(err).Debug("HMAC not found in metadata, skipping verification")
			return decryptedReader, nil
		}

		// Read decrypted data for HMAC verification
		decryptedData, err := io.ReadAll(decryptedReader)
		if err != nil {
			logger.WithError(err).Error("Failed to read decrypted data for HMAC verification")
			return nil, fmt.Errorf("failed to read decrypted data for HMAC verification: %w", err)
		}

		hmacCalculator, err := s.hmacManager.CreateCalculator(dek)
		if err != nil {
			logger.WithError(err).Error("Failed to create HMAC calculator for verification")
			return nil, fmt.Errorf("failed to create HMAC calculator: %w", err)
		}

		_, err = hmacCalculator.Add(decryptedData)
		if err != nil {
			logger.WithError(err).Error("Failed to add data to HMAC calculator for verification")
			return nil, fmt.Errorf("failed to add data to HMAC calculator: %w", err)
		}

		err = s.hmacManager.VerifyIntegrity(hmacCalculator, expectedHMAC)
		if err != nil {
			logger.WithError(err).Error("HMAC verification failed")
			return nil, fmt.Errorf("HMAC verification failed: %w", err)
		}

		// Recreate reader for decrypted data
		decryptedReader = bufio.NewReader(bytes.NewReader(decryptedData))
	}

	logger.Debug("GCM decryption completed successfully")
	return decryptedReader, nil
}

// DecryptCTR decrypts data that was encrypted with AES-CTR
func (s *SinglePartOperations) DecryptCTR(ctx context.Context, encryptedReader *bufio.Reader, metadata map[string]string, objectKey string) (*bufio.Reader, error) {
	logger := s.logger.WithFields(logrus.Fields{
		"operation":  "decrypt-ctr",
		"object_key": objectKey,
	})

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
	ctrDecryptor := dataencryption.NewAESCTRDataEncryptor()

	// Use object key as associated data
	associatedData := []byte(objectKey)

	// Decrypt data using streaming interface (AES-CTR decryption is the same operation as encryption)
	decryptedReader, err := ctrDecryptor.DecryptStream(ctx, encryptedReader, dek, iv, associatedData)
	if err != nil {
		logger.WithError(err).Error("Failed to decrypt CTR data")
		return nil, fmt.Errorf("failed to decrypt CTR data: %w", err)
	}

	// Verify HMAC if enabled using streaming approach
	if s.hmacManager.IsEnabled() {
		// Check if HMAC exists in metadata first
		expectedHMAC, err := s.metadataManager.GetHMAC(metadata)
		if err != nil {
			// HMAC not found in metadata - this is OK for objects encrypted without HMAC
			logger.WithError(err).Debug("HMAC not found in metadata, skipping verification")
			return decryptedReader, nil
		}

		// Create HMAC calculator for verification
		hmacCalculator, err := s.hmacManager.CreateCalculator(dek)
		if err != nil {
			logger.WithError(err).Error("Failed to create HMAC calculator for verification")
			return nil, fmt.Errorf("failed to create HMAC calculator: %w", err)
		}

		// Create a TeeReader that calculates HMAC while reading decrypted data
		hmacWriter := &hmacWriter{calculator: hmacCalculator}
		teeReader := io.TeeReader(decryptedReader, hmacWriter)

		// Read through the TeeReader to calculate HMAC and buffer data
		decryptedData, err := io.ReadAll(teeReader)
		if err != nil {
			logger.WithError(err).Error("Failed to read decrypted data for HMAC verification")
			return nil, fmt.Errorf("failed to read decrypted data for HMAC verification: %w", err)
		}

		// Verify HMAC
		err = s.hmacManager.VerifyIntegrity(hmacCalculator, expectedHMAC)
		if err != nil {
			logger.WithError(err).Error("HMAC verification failed")
			return nil, fmt.Errorf("HMAC verification failed: %w", err)
		}

		// Recreate reader for decrypted data
		decryptedReader = bufio.NewReader(bytes.NewReader(decryptedData))
	}

	logger.Debug("CTR decryption completed successfully")
	return decryptedReader, nil
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
