package orchestration

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption/dataencryption"
	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption/factory"
)

// EncryptGCM encrypts data using AES-GCM with streaming (for small objects)
func (m *Manager) EncryptGCM(ctx context.Context, dataReader *bufio.Reader, objectKey string) (*StreamingEncryptionResult, error) {
	m.logger.WithFields(logrus.Fields{
		"object_key": objectKey,
		"algorithm":  "aes-gcm",
	}).Debug("Encrypting data stream with GCM")

	// Create envelope encryptor for whole content (GCM)
	provider, err := m.providerManager.CreateEnvelopeEncryptor(factory.ContentTypeWhole, m.metadataManager.GetMetadataPrefix())
	if err != nil {
		return nil, fmt.Errorf("failed to create envelope encryptor: %w", err)
	}

	// Create associated data
	associatedData := []byte(objectKey)

	// Use the provider to encrypt the stream
	encryptedReader, _, metadata, err := provider.EncryptDataStream(ctx, dataReader, associatedData)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt stream with GCM: %w", err)
	}

	// Extract the actual algorithm used from metadata
	algorithm, err := m.metadataManager.GetAlgorithm(metadata)
	if err != nil {
		// Fallback to expected algorithm if not found in metadata
		algorithm = "aes-gcm"
	}

	return &StreamingEncryptionResult{
		EncryptedDataReader: encryptedReader,
		Metadata:            metadata,
		Algorithm:           algorithm,
	}, nil
}

// EncryptCTR encrypts data using AES-CTR with streaming (for large objects)
func (m *Manager) EncryptCTR(ctx context.Context, dataReader *bufio.Reader, objectKey string) (*StreamingEncryptionResult, error) {
	m.logger.WithFields(logrus.Fields{
		"object_key": objectKey,
		"algorithm":  "aes-ctr",
	}).Debug("Encrypting data stream with CTR")

	// Create associated data
	associatedData := []byte(objectKey)

	// For HMAC-enabled CTR, we need to read the data first to calculate HMAC before encryption
	// This is acceptable for single-part operations which are typically smaller
	var hmacValue []byte

	if m.hmacManager.IsEnabled() {
		// Read all data for HMAC calculation
		originalData, err := io.ReadAll(dataReader)
		if err != nil {
			m.logger.WithError(err).Error("Failed to read data for HMAC calculation")
			return nil, fmt.Errorf("failed to read data for HMAC calculation: %w", err)
		}

		// Create envelope encryptor to get DEK for HMAC calculation
		// We need to do a preliminary encryption to get the DEK
		provider, err := m.providerManager.CreateEnvelopeEncryptor(factory.ContentTypeMultipart, m.metadataManager.GetMetadataPrefix())
		if err != nil {
			return nil, fmt.Errorf("failed to create envelope encryptor: %w", err)
		}

		// Use the provider to encrypt the stream
		encryptedReader, encryptedDEK, metadata, err := provider.EncryptDataStream(ctx, bufio.NewReader(bytes.NewReader(originalData)), associatedData)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt stream with CTR: %w", err)
		}

		// Decrypt the DEK to calculate HMAC (we need the raw DEK for HMAC)
		fingerprint := m.providerManager.GetActiveFingerprint()
		dek, err := m.providerManager.DecryptDEK(encryptedDEK, fingerprint, objectKey)
		if err != nil {
			m.logger.WithError(err).Error("Failed to decrypt DEK for HMAC calculation")
			return nil, fmt.Errorf("failed to decrypt DEK for HMAC: %w", err)
		}
		defer func() {
			// Clear DEK from memory
			for i := range dek {
				dek[i] = 0
			}
		}()

		// Calculate HMAC using the original data (before encryption)
		hmacCalculator, err := m.hmacManager.CreateCalculator(dek)
		if err != nil {
			m.logger.WithError(err).Error("Failed to create HMAC calculator")
			return nil, fmt.Errorf("failed to create HMAC calculator: %w", err)
		}

		_, err = hmacCalculator.AddFromStream(bufio.NewReader(bytes.NewReader(originalData)))
		if err != nil {
			m.logger.WithError(err).Error("Failed to calculate HMAC from stream")
			return nil, fmt.Errorf("failed to calculate HMAC from stream: %w", err)
		}

		hmacValue = m.hmacManager.FinalizeCalculator(hmacCalculator)

		// Add HMAC to metadata
		if len(hmacValue) > 0 {
			m.metadataManager.SetHMAC(metadata, hmacValue)
			m.logger.WithFields(logrus.Fields{
				"object_key": objectKey,
				"hmac_size":  len(hmacValue),
			}).Debug("Added HMAC to CTR metadata")
		}

		// Extract the actual algorithm used from metadata
		algorithm, err := m.metadataManager.GetAlgorithm(metadata)
		if err != nil {
			// Fallback to expected algorithm if not found in metadata
			algorithm = "aes-ctr"
		}

		return &StreamingEncryptionResult{
			EncryptedDataReader: encryptedReader,
			Metadata:            metadata,
			Algorithm:           algorithm,
		}, nil
	}

	// HMAC disabled - use standard encryption path without buffering
	provider, err := m.providerManager.CreateEnvelopeEncryptor(factory.ContentTypeMultipart, m.metadataManager.GetMetadataPrefix())
	if err != nil {
		return nil, fmt.Errorf("failed to create envelope encryptor: %w", err)
	}

	// Use the provider to encrypt the stream
	encryptedReader, _, metadata, err := provider.EncryptDataStream(ctx, dataReader, associatedData)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt stream with CTR: %w", err)
	}

	// Extract the actual algorithm used from metadata
	algorithm, err := m.metadataManager.GetAlgorithm(metadata)
	if err != nil {
		// Fallback to expected algorithm if not found in metadata
		algorithm = "aes-ctr"
	}

	return &StreamingEncryptionResult{
		EncryptedDataReader: encryptedReader,
		Metadata:            metadata,
		Algorithm:           algorithm,
	}, nil
}

// DecryptGCMStream decrypts data using AES-GCM with streaming
func (m *Manager) DecryptGCMStream(ctx context.Context, encryptedDataReader *bufio.Reader, metadata map[string]string, objectKey string) (*bufio.Reader, error) {
	m.logger.WithFields(logrus.Fields{
		"object_key": objectKey,
		"algorithm":  "aes-gcm",
	}).Debug("Decrypting data stream with GCM")

	// Check if encrypted data is empty first (before metadata validation)
	if encryptedDataReader != nil {
		// Peek at the first byte to check if data is available
		_, err := encryptedDataReader.Peek(1)
		if err == io.EOF {
			m.logger.Error("Empty encrypted data for decryption")
			return nil, fmt.Errorf("encrypted data is empty")
		}
	}

	// Get the required key encryptor fingerprint
	fingerprint, err := m.metadataManager.GetFingerprint(metadata)
	if err != nil {
		m.logger.WithError(err).Error("Failed to get fingerprint from metadata")
		return nil, fmt.Errorf("failed to get fingerprint: %w", err)
	}

	// Get the encrypted DEK from metadata
	encryptedDEK, err := m.metadataManager.GetEncryptedDEK(metadata)
	if err != nil {
		m.logger.WithError(err).Error("Failed to get encrypted DEK from metadata")
		return nil, fmt.Errorf("failed to get encrypted DEK: %w", err)
	}

	// Decrypt the DEK
	dek, err := m.providerManager.DecryptDEK(encryptedDEK, fingerprint, objectKey)
	if err != nil {
		m.logger.WithError(err).Error("Failed to decrypt DEK")
		return nil, fmt.Errorf("failed to decrypt DEK: %w", err)
	}
	defer func() {
		// Clear DEK from memory
		for i := range dek {
			dek[i] = 0
		}
	}()

	// Create factory and get envelope encryptor
	factoryInstance := m.providerManager.GetFactory()

	// Use object key as associated data
	associatedData := []byte(objectKey)

	// For GCM, we need to use the envelope decryption
	metadataPrefix := m.metadataManager.GetMetadataPrefix()
	envelopeEncryptor, err := factoryInstance.CreateEnvelopeEncryptor(
		factory.ContentTypeWhole,
		fingerprint,
		metadataPrefix,
	)
	if err != nil {
		m.logger.WithError(err).Error("Failed to create GCM envelope encryptor for decryption")
		return nil, fmt.Errorf("failed to create GCM envelope encryptor: %w", err)
	}

	// Get IV from metadata (for GCM this is the nonce)
	// Note: For GCM, the nonce is also prepended to the encrypted data,
	// so we pass nil to let the decryptor extract it from the data
	var iv []byte // Force extraction from encrypted data

	// Decrypt data using streaming interface
	decryptedReader, err := envelopeEncryptor.DecryptDataStream(ctx, encryptedDataReader, encryptedDEK, iv, associatedData)
	if err != nil {
		m.logger.WithError(err).Error("Failed to decrypt GCM data")
		return nil, fmt.Errorf("failed to decrypt GCM data: %w", err)
	}

	// Verify HMAC if enabled and present in metadata
	if m.hmacManager.IsEnabled() {
		// Check if HMAC exists in metadata first
		expectedHMAC, err := m.metadataManager.GetHMAC(metadata)
		if err != nil {
			// HMAC not found in metadata - this is OK for objects encrypted without HMAC
			m.logger.WithError(err).Debug("HMAC not found in metadata, skipping verification")
			return decryptedReader, nil
		}

		// Read decrypted data for HMAC verification
		decryptedData, err := io.ReadAll(decryptedReader)
		if err != nil {
			m.logger.WithError(err).Error("Failed to read decrypted data for HMAC verification")
			return nil, fmt.Errorf("failed to read decrypted data for HMAC verification: %w", err)
		}

		hmacCalculator, err := m.hmacManager.CreateCalculator(dek)
		if err != nil {
			m.logger.WithError(err).Error("Failed to create HMAC calculator for verification")
			return nil, fmt.Errorf("failed to create HMAC calculator: %w", err)
		}

		_, err = hmacCalculator.Add(decryptedData)
		if err != nil {
			m.logger.WithError(err).Error("Failed to add data to HMAC calculator for verification")
			return nil, fmt.Errorf("failed to add data to HMAC calculator: %w", err)
		}

		err = m.hmacManager.VerifyIntegrity(hmacCalculator, expectedHMAC)
		if err != nil {
			m.logger.WithError(err).Error("HMAC verification failed")
			return nil, fmt.Errorf("HMAC verification failed: %w", err)
		}

		// Recreate reader for decrypted data
		decryptedReader = bufio.NewReader(bytes.NewReader(decryptedData))
	}

	m.logger.Debug("GCM decryption completed successfully")
	return decryptedReader, nil
}

// DecryptCTRStream decrypts data using AES-CTR with streaming
func (m *Manager) DecryptCTRStream(ctx context.Context, encryptedDataReader *bufio.Reader, metadata map[string]string, objectKey string) (*bufio.Reader, error) {
	m.logger.WithFields(logrus.Fields{
		"object_key": objectKey,
		"algorithm":  "aes-ctr",
	}).Debug("Decrypting data stream with CTR")

	// Direct decryption without wrapper
	decryptedReader, err := m.createDecryptionReaderWithSizeInternal(ctx, encryptedDataReader, metadata, objectKey, -1)
	if err != nil {
		return nil, fmt.Errorf("failed to create decryption reader: %w", err)
	}

	// Convert to bufio.Reader if needed
	if br, ok := decryptedReader.(*bufio.Reader); ok {
		return br, nil
	}
	return bufio.NewReader(decryptedReader), nil
}

// DecryptDataWithMetadata decrypts data with full metadata context
func (m *Manager) DecryptDataWithMetadata(ctx context.Context, encryptedData, _ []byte, metadata map[string]string, objectKey string, _ string) ([]byte, error) {
	// For V2, we ignore the separate encryptedDEK and providerAlias parameters
	// since they should be embedded in the metadata

	// Convert byte slice to bufio.Reader for streaming
	encryptedDataReader := bufio.NewReader(bytes.NewReader(encryptedData))

	// Use the streaming method
	decryptedReader, err := m.DecryptData(ctx, encryptedDataReader, metadata, objectKey)
	if err != nil {
		return nil, err
	}

	// Convert streaming result back to bytes for compatibility with existing proxy handlers
	decryptedData, err := io.ReadAll(decryptedReader)
	if err != nil {
		return nil, fmt.Errorf("failed to read decrypted data from stream: %w", err)
	}

	return decryptedData, nil
}

// CreateStreamingDecryptionReaderWithSize creates a streaming decryption reader with size hint
func (m *Manager) CreateStreamingDecryptionReaderWithSize(ctx context.Context, encryptedReader io.ReadCloser, _ []byte, metadata map[string]string, objectKey string, providerAlias string, expectedSize int64) (io.ReadCloser, error) {
	m.logger.WithFields(logrus.Fields{
		"object_key":     objectKey,
		"expected_size":  expectedSize,
		"provider_alias": providerAlias,
	}).Debug("Creating streaming decryption reader with size hint")

	// Convert to bufio.Reader
	bufReader := bufio.NewReader(encryptedReader)

	// Direct call with size hint for HMAC validation
	reader, err := m.createDecryptionReaderWithSizeInternal(ctx, bufReader, metadata, objectKey, expectedSize)
	if err != nil {
		return nil, fmt.Errorf("failed to create decryption reader: %w", err)
	}

	// Always wrap so the underlying S3 response body is closed together with the
	// decryption/HMAC reader. Returning reader directly when it implements
	// io.ReadCloser would leak the S3 connection, because the reader's Close()
	// only releases its own resources (buffers, decryptor state).
	return &readCloserWrapper{Reader: reader, closer: encryptedReader}, nil
}

// isNoneProviderData checks if metadata indicates data was encrypted with none provider
func (m *Manager) isNoneProviderData(metadata map[string]string) bool {
	// Check if any S3EP encryption metadata exists
	prefix := "s3ep-" // default prefix
	if m.config.Encryption.MetadataKeyPrefix != nil && *m.config.Encryption.MetadataKeyPrefix != "" {
		prefix = *m.config.Encryption.MetadataKeyPrefix
	}

	// If no S3EP metadata keys exist, assume none provider
	for key := range metadata {
		if strings.HasPrefix(key, prefix) {
			return false // S3EP metadata found, not none provider
		}
	}
	return true // No S3EP metadata, assume none provider
}

// createStreamingEncryptor creates a streaming encryptor for the given DEK
func (m *Manager) createStreamingEncryptor(dek []byte) (*dataencryption.AESCTRStatefulEncryptor, error) {
	encryptor, err := dataencryption.NewAESCTRStatefulEncryptor(dek)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES-CTR streaming encryptor: %w", err)
	}
	m.logger.WithField("algorithm", "aes-ctr").Debug("Created streaming encryptor")
	return encryptor, nil
}

// createStreamingDecryptor creates a streaming decryptor for the given DEK and metadata
func (m *Manager) createStreamingDecryptor(dek []byte, metadata map[string]string) (*dataencryption.AESCTRStatefulEncryptor, error) {
	iv, err := m.metadataManager.GetIV(metadata)
	if err != nil {
		return nil, fmt.Errorf("failed to get IV from metadata: %w", err)
	}

	decryptor, err := dataencryption.NewAESCTRStatefulEncryptorWithIV(dek, iv)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES-CTR streaming decryptor: %w", err)
	}

	m.logger.WithFields(logrus.Fields{
		"algorithm": "aes-ctr",
		"approach":  "continuous_ctr_stream",
	}).Debug("Created streaming decryptor with continuous CTR state")

	return decryptor, nil
}

// buildEncryptionMetadataSimple builds simplified metadata for streaming encryption
func (m *Manager) buildEncryptionMetadataSimple(ctx context.Context, dek []byte, encryptor *dataencryption.AESCTRStatefulEncryptor) (map[string]string, error) {
	fingerprint := m.providerManager.GetActiveFingerprint()
	provider, err := m.providerManager.GetProviderByFingerprint(fingerprint)
	if err != nil {
		return nil, fmt.Errorf("failed to get provider: %w", err)
	}

	encryptedDEK, _, err := provider.EncryptDEK(ctx, dek)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt DEK: %w", err)
	}

	iv := encryptor.GetIV()

	metadata := m.metadataManager.BuildMetadataForEncryption(
		dek,
		encryptedDEK,
		iv,
		"aes-ctr",
		fingerprint,
		m.providerManager.GetActiveProviderAlgorithm(),
		nil,
	)

	return metadata, nil
}

// createEncryptionReaderInternal creates encryption reader without wrapper logic
func (m *Manager) createEncryptionReaderInternal(ctx context.Context, bufReader *bufio.Reader, objectKey string) (io.Reader, map[string]string, error) {
	m.logger.WithField("object_key", objectKey).Debug("Creating encryption reader for streaming")

	// Generate a new 32-byte DEK for AES-256
	dek := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		return nil, nil, fmt.Errorf("failed to generate DEK: %w", err)
	}

	// Create streaming encryptor
	encryptor, err := m.createStreamingEncryptor(dek)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create streaming encryptor: %w", err)
	}

	// Build metadata
	metadata, err := m.buildEncryptionMetadataSimple(ctx, dek, encryptor)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to build encryption metadata: %w", err)
	}

	// Create encryption reader
	encReader := &encryptionReader{
		reader:    bufReader,
		encryptor: encryptor,
		metadata:  metadata,
		logger:    m.logger.WithField("object_key", objectKey),
	}

	m.logger.WithField("object_key", objectKey).Debug("Created encryption reader with real AES-CTR streaming")
	return encReader, metadata, nil
}

// createDecryptionReaderWithSizeInternal creates decryption reader without wrapper logic
func (m *Manager) createDecryptionReaderWithSizeInternal(ctx context.Context, bufReader *bufio.Reader, metadata map[string]string, objectKey string, expectedSize int64) (io.Reader, error) {
	m.logger.WithFields(logrus.Fields{
		"object_key":    objectKey,
		"expected_size": expectedSize,
	}).Debug("Creating decryption reader with size hint for streaming")

	// Extract fingerprint from metadata
	fingerprint, err := m.metadataManager.GetFingerprint(metadata)
	if err != nil {
		return nil, fmt.Errorf("failed to get fingerprint from metadata: %w", err)
	}

	// Check for none provider
	if fingerprint == "none-provider-fingerprint" {
		m.logger.Debug("Using none provider - no decryption for streaming")
		return bufReader, nil
	}

	// Extract encrypted DEK from metadata
	encryptedDEK, err := m.metadataManager.GetEncryptedDEK(metadata)
	if err != nil {
		return nil, fmt.Errorf("failed to get encrypted DEK from metadata: %w", err)
	}

	// Decrypt DEK via ProviderManager (uses per-object DEK cache so repeated reads
	// of the same object skip the expensive KEK operation).
	dek, err := m.providerManager.DecryptDEK(encryptedDEK, fingerprint, objectKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt DEK: %w", err)
	}
	defer func() {
		// Clear local DEK copy from memory. The decryptor and HMAC calculator
		// have already copied the key material internally.
		for i := range dek {
			dek[i] = 0
		}
	}()

	// Create streaming decryptor
	decryptor, err := m.createStreamingDecryptor(dek, metadata)
	if err != nil {
		return nil, fmt.Errorf("failed to create streaming decryptor: %w", err)
	}

	// Create decryption reader
	decReader := &decryptionReader{
		reader:    bufReader,
		decryptor: decryptor,
		metadata:  metadata,
		logger:    m.logger,
	}

	// Check if HMAC validation is enabled and we have expected size
	if m.hmacManager.IsEnabled() && expectedSize > 0 {
		expectedHMAC, hmacErr := m.metadataManager.GetHMAC(metadata)
		if hmacErr == nil && len(expectedHMAC) > 0 {
			hmacCalculator, calcErr := m.hmacManager.CreateCalculator(dek)
			if calcErr != nil {
				m.logger.WithError(calcErr).Warn("Failed to create HMAC calculator, falling back to unvalidated streaming")
				return decReader, nil
			}

			// Wrap with HMAC validating reader
			hvReader := &hmacValidatingReader{
				reader:         decReader,
				hmacCalculator: hmacCalculator,
				hmacManager:    m.hmacManager,
				expectedHMAC:   expectedHMAC,
				objectKey:      objectKey,
				logger:         m.logger.WithField("reader_type", "hmac_validating"),
				expectedSize:   expectedSize,
			}

			m.logger.WithFields(logrus.Fields{
				"object_key":    objectKey,
				"expected_size": expectedSize,
			}).Info("🔒 Created HMAC-validating decryption reader")
			return hvReader, nil
		}

		m.logger.WithField("object_key", objectKey).Debug("HMAC metadata not found, using standard decryption reader")
	}

	m.logger.Debug("Created decryption reader with real AES-CTR streaming")
	return decReader, nil
}
