package orchestration

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/guided-traffic/s3-encryption-proxy/internal/config"
	"github.com/guided-traffic/s3-encryption-proxy/internal/validation"
	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption"
	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption/dataencryption"
	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption/factory"
)

// readCloserWrapper wraps a Reader to make it a ReadCloser
type readCloserWrapper struct {
	io.Reader
	closer io.Closer
}

func (r *readCloserWrapper) Close() error {
	if r.closer != nil {
		return r.closer.Close()
	}
	return nil
}

// StreamingEncryptionResult represents the result of a streaming encryption operation
type StreamingEncryptionResult struct {
	EncryptedDataReader *bufio.Reader
	Metadata            map[string]string
	Algorithm           string
	KeyFingerprint      string
}

// encryptionReader wraps a *bufio.Reader to provide on-the-fly encryption.
// It implements the io.Reader interface and encrypts data as it's being read,
// enabling memory-efficient streaming encryption for large objects.
type encryptionReader struct {
	reader    *bufio.Reader                                  // Source data reader
	encryptor *dataencryption.AESCTRStatefulEncryptor        // Real streaming encryptor
	buffer    []byte                                         // Internal buffer for processing
	metadata  map[string]string                              // Encryption metadata to be returned
	finished  bool                                           // Flag indicating if reading is complete
	logger    *logrus.Entry                                  // Logger for debugging
}

// decryptionReader wraps a *bufio.Reader to provide on-the-fly decryption.
// It implements the io.Reader interface and decrypts data as it's being read,
// enabling memory-efficient streaming decryption for large objects.
type decryptionReader struct {
	reader    *bufio.Reader                                  // Source encrypted data reader
	decryptor *dataencryption.AESCTRStatefulEncryptor        // Real streaming decryptor
	buffer    []byte                                         // Internal buffer for processing
	finished  bool                                           // Flag indicating if reading is complete
	metadata  map[string]string                              // Metadata containing HMAC for verification
	logger    *logrus.Entry                                  // Logger for debugging
}

// hmacValidatingReader wraps a decryptionReader to provide HMAC validation BEFORE
// releasing the last chunk to the client. This ensures data integrity is verified
// before the HTTP response completes, preventing clients from receiving corrupted data.
type hmacValidatingReader struct {
	reader         io.Reader                   // Underlying decryption reader
	hmacCalculator *validation.HMACCalculator  // HMAC calculator for integrity verification
	hmacManager    *validation.HMACManager     // HMAC manager for verification
	expectedHMAC   []byte                      // Expected HMAC value from metadata
	objectKey      string                      // Object key for logging
	logger         *logrus.Entry               // Logger for debugging

	// Smart buffering for last chunk
	expectedSize   int64  // Total expected size from Content-Length
	totalRead      int64  // Total bytes read so far
	totalDecrypted int64  // Total bytes decrypted and passed to HMAC

	// Last chunk buffering
	lastChunkBuf   []byte // Buffer holding the last chunk for HMAC validation
	lastChunkSize  int    // Actual size of data in lastChunkBuf
	lastChunkPos   int    // Read position within lastChunkBuf
	validated      bool   // HMAC validation completed
	finished       bool   // Reading finished

	// Error state
	validationErr  error  // HMAC validation error (if any)
}

// Manager is the main orchestration layer for all encryption operations
// It coordinates between all specialized components with clear data paths
type Manager struct {
	config          *config.Config
	providerManager *ProviderManager
	multipartOps    *MultipartOperations
	metadataManager *MetadataManager
	hmacManager     *validation.HMACManager
	logger          *logrus.Entry // Public for testing

	// Streaming operations (integrated from streaming.go)
	bufferPool  *sync.Pool // Pool of reusable buffers for memory optimization
	segmentSize int64      // Size of each streaming segment in bytes

	// Background cleanup management
	cleanupCtx    context.Context
	cleanupCancel context.CancelFunc
	cleanupWg     sync.WaitGroup
}

// NewManager creates a new encryption manager with modular architecture
func NewManager(cfg *config.Config) (*Manager, error) {
	if cfg == nil {
		return nil, fmt.Errorf("configuration cannot be nil")
	}

	logger := logrus.WithField("component", "encryption_manager")

	// Create provider manager first
	providerManager, err := NewProviderManager(cfg)
	if err != nil {
		logger.WithError(err).Error("Failed to create provider manager")
		return nil, fmt.Errorf("failed to create provider manager: %w", err)
	}

	// Create metadata manager
	metadataManager := NewMetadataManager(cfg, "")

	// Create HMAC manager
	hmacManager := validation.NewHMACManager(cfg)

	// Determine segment size from configuration
	segmentSize := int64(12 * 1024 * 1024) // Default 12MB
	if cfg != nil {
		segmentSize = cfg.GetStreamingSegmentSize()
	}

	// Create buffer pool for streaming operations
	bufferPool := &sync.Pool{
		New: func() interface{} {
			return make([]byte, segmentSize)
		},
	}

	// Create specialized operation handlers
	multipartOps := NewMultipartOperations(providerManager, hmacManager, metadataManager, cfg)

	// Create background cleanup context
	cleanupCtx, cleanupCancel := context.WithCancel(context.Background())

	manager := &Manager{
		config:          cfg,
		providerManager: providerManager,
		multipartOps:    multipartOps,
		metadataManager: metadataManager,
		hmacManager:     hmacManager,
		bufferPool:      bufferPool,
		segmentSize:     segmentSize,
		logger:          logger,
		cleanupCtx:      cleanupCtx,
		cleanupCancel:   cleanupCancel,
	}

	// Start background cleanup if cleanup interval is configured
	if cfg.Optimizations.MultipartSessionCleanupInterval > 0 {
		manager.startBackgroundCleanup()
	}

	logger.WithFields(logrus.Fields{
		"provider_count":  len(providerManager.GetProviderAliases()),
		"active_provider": providerManager.GetActiveProviderAlias(),
		"hmac_enabled":    hmacManager.IsEnabled(),
		"metadata_prefix": metadataManager.GetMetadataPrefix(),
		"segment_size":    segmentSize,
	}).Info("Successfully initialized Manager")

	return manager, nil
}

// ===== STREAMING ENCRYPTION OPERATIONS =====

// EncryptData encrypts data from a reader using streaming encryption
func (m *Manager) EncryptData(ctx context.Context, dataReader *bufio.Reader, objectKey string) (*StreamingEncryptionResult, error) {
	m.logger.WithField("object_key", objectKey).Debug("Starting streaming data encryption")

	// Check for none provider - complete pass-through
	if m.providerManager.IsNoneProvider() {
		m.logger.WithField("object_key", objectKey).Debug("Using none provider - complete pass-through")
		return &StreamingEncryptionResult{
			EncryptedDataReader: dataReader,
			Metadata:            make(map[string]string),
		}, nil
	}

	// Direct encryption without wrapper
	encryptedReader, metadata, err := m.createEncryptionReaderInternal(ctx, dataReader, objectKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create encryption reader: %w", err)
	}

	// Convert to bufio.Reader if needed
	var bufReader *bufio.Reader
	if br, ok := encryptedReader.(*bufio.Reader); ok {
		bufReader = br
	} else {
		bufReader = bufio.NewReader(encryptedReader)
	}

	return &StreamingEncryptionResult{
		EncryptedDataReader: bufReader,
		Metadata:            metadata,
	}, nil
}

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

// ===== SINGLE PART OPERATIONS =====

// EncryptDataWithContentType encrypts data with explicit content type using streaming
func (m *Manager) EncryptDataWithContentType(ctx context.Context, dataReader *bufio.Reader, objectKey string, contentType factory.ContentType) (*StreamingEncryptionResult, error) {
	m.logger.WithFields(logrus.Fields{
		"object_key":   objectKey,
		"content_type": contentType,
	}).Debug("Encrypting data stream with specified content type")

	// Check for none provider - complete pass-through with no encryption or metadata
	if m.providerManager.IsNoneProvider() {
		m.logger.WithField("object_key", objectKey).Debug("Using none provider - complete pass-through without encryption or HMAC")
		return &StreamingEncryptionResult{
			EncryptedDataReader: dataReader,              // Return data reader unchanged
			Metadata:            make(map[string]string), // No metadata
		}, nil
	}

	// Route based on content type
	switch contentType {
	case factory.ContentTypeWhole:
		return m.EncryptGCM(ctx, dataReader, objectKey)
	case factory.ContentTypeMultipart:
		return m.EncryptCTR(ctx, dataReader, objectKey)
	default:
		return m.EncryptData(ctx, dataReader, objectKey) // Fall back to size-based selection
	}
}

// EncryptDataWithHTTPContentType encrypts data based on HTTP content type using streaming
func (m *Manager) EncryptDataWithHTTPContentType(ctx context.Context, dataReader *bufio.Reader, objectKey string, httpContentType string, isMultipart bool) (*StreamingEncryptionResult, error) {
	m.logger.WithFields(logrus.Fields{
		"object_key":        objectKey,
		"http_content_type": httpContentType,
		"is_multipart":      isMultipart,
	}).Debug("Encrypting data stream with HTTP content type")

	// Convert HTTP content type to factory content type
	var contentType factory.ContentType
	if isMultipart {
		contentType = factory.ContentTypeMultipart
	} else {
		contentType = factory.ContentTypeWhole
	}

	return m.EncryptDataWithContentType(ctx, dataReader, objectKey, contentType)
}

// ===== STREAMING DECRYPTION OPERATIONS =====

// DecryptData decrypts data from a reader using metadata to determine the algorithm
// This is the preferred method for performance as it uses streaming decryption throughout
func (m *Manager) DecryptData(ctx context.Context, encryptedDataReader *bufio.Reader, metadata map[string]string, objectKey string) (*bufio.Reader, error) {
	m.logger.WithField("object_key", objectKey).Debug("Starting streaming data decryption")

	// Check for none provider - if no encryption metadata exists, assume none provider pass-through
	if len(metadata) == 0 || m.isNoneProviderData(metadata) {
		m.logger.WithField("object_key", objectKey).Debug("No encryption metadata found - assuming none provider pass-through")
		return encryptedDataReader, nil
	}

	// Extract algorithm from metadata
	algorithm, err := m.metadataManager.GetAlgorithm(metadata)
	if err != nil {
		m.logger.WithError(err).Error("Failed to get algorithm from metadata")
		return nil, fmt.Errorf("failed to get algorithm from metadata: %w", err)
	}

	// Route to appropriate decryption method
	switch algorithm {
	case "aes-gcm":
		return m.DecryptGCMStream(ctx, encryptedDataReader, metadata, objectKey)
	case "aes-ctr":
		return m.DecryptCTRStream(ctx, encryptedDataReader, metadata, objectKey)
	case "none":
		m.logger.WithField("object_key", objectKey).Debug("Using none algorithm - returning data as-is")
		return encryptedDataReader, nil
	default:
		m.logger.WithFields(logrus.Fields{
			"algorithm":  algorithm,
			"object_key": objectKey,
		}).Error("Unknown algorithm in metadata")
		return nil, fmt.Errorf("unknown algorithm: %s", algorithm)
	}
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

// ===== MULTIPART OPERATIONS =====

// UploadPart encrypts and processes a multipart upload part from a reader
func (m *Manager) UploadPart(ctx context.Context, uploadID string, partNumber int, dataReader *bufio.Reader) (*StreamingEncryptionResult, error) {
	m.logger.WithFields(logrus.Fields{
		"upload_id":   uploadID,
		"part_number": partNumber,
	}).Debug("Processing streaming multipart upload part")

	// Check for none provider - complete pass-through with no encryption or metadata
	if m.providerManager.IsNoneProvider() {
		m.logger.WithFields(logrus.Fields{
			"upload_id":   uploadID,
			"part_number": partNumber,
		}).Debug("Using none provider - multipart part pass-through without encryption")
		return &StreamingEncryptionResult{
			EncryptedDataReader: dataReader,              // Return data reader unchanged
			Metadata:            make(map[string]string), // No metadata
		}, nil
	}

	// Use the new multipart ProcessPart method that maintains persistent CTR state
	// This ensures continuous encryption stream across all parts
	result, err := m.multipartOps.ProcessPart(ctx, uploadID, partNumber, dataReader)
	if err != nil {
		return nil, fmt.Errorf("failed to process multipart part: %w", err)
	}

	m.logger.WithFields(logrus.Fields{
		"upload_id":       uploadID,
		"part_number":     partNumber,
		"algorithm":       result.Algorithm,
		"key_fingerprint": result.KeyFingerprint,
	}).Debug("Successfully processed multipart part with persistent CTR encryptor")

	return &StreamingEncryptionResult{
		EncryptedDataReader: result.EncryptedData,
		Metadata:            result.Metadata,
	}, nil
}

// InitiateMultipartUpload starts a new multipart upload session
func (m *Manager) InitiateMultipartUpload(ctx context.Context, uploadID, objectKey, bucketName string) error {
	m.logger.WithFields(logrus.Fields{
		"upload_id":   uploadID,
		"object_key":  objectKey,
		"bucket_name": bucketName,
	}).Debug("Initiating multipart upload")

	// Check for none provider - no session needed for pass-through
	if m.providerManager.IsNoneProvider() {
		m.logger.WithField("upload_id", uploadID).Debug("Using none provider - no multipart session needed")
		return nil // No session setup needed for none provider
	}

	_, err := m.multipartOps.InitiateSession(ctx, uploadID, objectKey, bucketName)
	return err
}

// UploadPartStreaming encrypts and processes a multipart upload part from a reader
func (m *Manager) UploadPartStreaming(ctx context.Context, uploadID string, partNumber int, reader io.Reader) (*EncryptionResult, error) {
	m.logger.WithFields(logrus.Fields{
		"upload_id":   uploadID,
		"part_number": partNumber,
	}).Debug("Processing streaming multipart upload part (memory-optimized)")

	// Convert io.Reader to bufio.Reader for better performance
	var dataReader *bufio.Reader
	if br, ok := reader.(*bufio.Reader); ok {
		dataReader = br
	} else {
		dataReader = bufio.NewReader(reader)
	}

	// Use the new streaming method that returns a true stream
	streamResult, err := m.UploadPart(ctx, uploadID, partNumber, dataReader)
	if err != nil {
		return nil, err
	}

	// Return the streaming result directly (no io.ReadAll!)
	return &EncryptionResult{
		EncryptedData:  streamResult.EncryptedDataReader, // Use the reader directly
		Metadata:       streamResult.Metadata,
		Algorithm:      streamResult.Algorithm,
		KeyFingerprint: streamResult.KeyFingerprint,
	}, nil
}

// StorePartETag stores the ETag for a multipart upload part
func (m *Manager) StorePartETag(uploadID string, partNumber int, etag string) error {
	return m.multipartOps.StorePartETag(uploadID, partNumber, etag)
}

// CompleteMultipartUpload finalizes a multipart upload and returns final metadata
func (m *Manager) CompleteMultipartUpload(ctx context.Context, uploadID string, parts map[int]string) (map[string]string, error) {
	m.logger.WithFields(logrus.Fields{
		"upload_id":   uploadID,
		"parts_count": len(parts),
	}).Debug("Completing multipart upload")

	// Check for none provider - no metadata to generate
	if m.providerManager.IsNoneProvider() {
		m.logger.WithField("upload_id", uploadID).Debug("Using none provider - no multipart metadata to generate")
		return make(map[string]string), nil // Return empty metadata
	}

	// Store all part ETags
	for partNumber, etag := range parts {
		if err := m.StorePartETag(uploadID, partNumber, etag); err != nil {
			m.logger.WithFields(logrus.Fields{
				"upload_id":   uploadID,
				"part_number": partNumber,
				"etag":        etag,
				"error":       err,
			}).Error("Failed to store part ETag")
			return nil, fmt.Errorf("failed to store part ETag: %w", err)
		}
	}

	return m.multipartOps.FinalizeSession(ctx, uploadID)
}

// AbortMultipartUpload cancels a multipart upload and cleans up resources
func (m *Manager) AbortMultipartUpload(ctx context.Context, uploadID string) error {
	m.logger.WithField("upload_id", uploadID).Debug("Aborting multipart upload")
	return m.multipartOps.AbortSession(ctx, uploadID)
}

// CleanupMultipartUpload removes a multipart upload session (after successful completion)
func (m *Manager) CleanupMultipartUpload(uploadID string) error {
	return m.multipartOps.CleanupSession(uploadID)
}

// GetMultipartUploadState returns the state of a multipart upload session
func (m *Manager) GetMultipartUploadState(uploadID string) (*MultipartSession, error) {
	return m.multipartOps.GetSession(uploadID)
}

// ===== STREAMING OPERATIONS =====

// CreateEncryptionReader creates a reader that encrypts data on-the-fly
func (m *Manager) CreateEncryptionReader(ctx context.Context, reader io.Reader, objectKey string) (io.Reader, map[string]string, error) {
	m.logger.WithField("object_key", objectKey).Debug("Creating encryption reader")

	// Convert to bufio.Reader
	var bufReader *bufio.Reader
	if br, ok := reader.(*bufio.Reader); ok {
		bufReader = br
	} else {
		bufReader = bufio.NewReader(reader)
	}

	// Check for none provider
	if m.providerManager.IsNoneProvider() {
		m.logger.WithField("object_key", objectKey).Debug("Using none provider - streaming pass-through")
		return bufReader, make(map[string]string), nil
	}

	// Direct call to internal method
	return m.createEncryptionReaderInternal(ctx, bufReader, objectKey)
}

// CreateEncryptionReaderBuffered creates a bufio.Reader that encrypts data on-the-fly
func (m *Manager) CreateEncryptionReaderBuffered(ctx context.Context, reader io.Reader, objectKey string) (*bufio.Reader, map[string]string, error) {
	m.logger.WithField("object_key", objectKey).Debug("Creating buffered encryption reader")

	encReader, metadata, err := m.CreateEncryptionReader(ctx, reader, objectKey)
	if err != nil {
		return nil, nil, err
	}

	// Ensure we return a bufio.Reader
	if br, ok := encReader.(*bufio.Reader); ok {
		return br, metadata, nil
	}
	return bufio.NewReader(encReader), metadata, nil
}

// CreateDecryptionReader creates a reader that decrypts data on-the-fly
func (m *Manager) CreateDecryptionReader(ctx context.Context, reader io.Reader, metadata map[string]string) (io.Reader, error) {
	m.logger.Debug("Creating decryption reader")

	// Convert to bufio.Reader
	var bufReader *bufio.Reader
	if br, ok := reader.(*bufio.Reader); ok {
		bufReader = br
	} else {
		bufReader = bufio.NewReader(reader)
	}

	// Direct call to internal method
	return m.createDecryptionReaderWithSizeInternal(ctx, bufReader, metadata, "", -1)
}

// CreateDecryptionReaderBuffered creates a bufio.Reader that decrypts data on-the-fly
func (m *Manager) CreateDecryptionReaderBuffered(ctx context.Context, reader io.Reader, metadata map[string]string) (*bufio.Reader, error) {
	m.logger.Debug("Creating buffered decryption reader")

	decReader, err := m.CreateDecryptionReader(ctx, reader, metadata)
	if err != nil {
		return nil, err
	}

	// Ensure we return a bufio.Reader
	if br, ok := decReader.(*bufio.Reader); ok {
		return br, nil
	}
	return bufio.NewReader(decReader), nil
}

// ===== PROVIDER MANAGEMENT =====

// GetProviderAliases returns all configured provider aliases
func (m *Manager) GetProviderAliases() []string {
	return m.providerManager.GetProviderAliases()
}

// GetActiveProviderAlias returns the active provider alias
func (m *Manager) GetActiveProviderAlias() string {
	return m.providerManager.GetActiveProviderAlias()
}

// GetLoadedProviders returns information about all loaded providers
func (m *Manager) GetLoadedProviders() []ProviderSummary {
	return m.providerManager.GetLoadedProviders()
}

// GetProvider returns a provider by alias
func (m *Manager) GetProvider(_ string) (encryption.EncryptionProvider, bool) {
	// In the modular architecture, we don't expose individual providers
	// This method exists for backward compatibility only
	return nil, false
}

// ===== UTILITY METHODS =====

// GetMetadataKeyPrefix returns the configured metadata key prefix
func (m *Manager) GetMetadataKeyPrefix() string {
	return m.metadataManager.GetMetadataPrefix()
}

// GetStreamingSegmentSize returns the configured streaming segment size
func (m *Manager) GetStreamingSegmentSize() int64 {
	return m.segmentSize
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

	// Wrap as ReadCloser if needed
	if readCloser, ok := reader.(io.ReadCloser); ok {
		return readCloser, nil
	}

	return &readCloserWrapper{Reader: reader, closer: encryptedReader}, nil
}

// UploadPartStreamingBuffer encrypts and uploads a part using true streaming with segment buffering
func (m *Manager) UploadPartStreamingBuffer(ctx context.Context, uploadID string, partNumber int, reader io.Reader, segmentSize int64, onSegmentReady func([]byte) error) error {
	m.logger.WithFields(logrus.Fields{
		"upload_id":    uploadID,
		"part_number":  partNumber,
		"segment_size": segmentSize,
	}).Debug("Processing multipart upload with streaming buffer")

	// Convert to bufio.Reader for better performance
	var bufReader *bufio.Reader
	if br, ok := reader.(*bufio.Reader); ok {
		bufReader = br
	} else {
		bufReader = bufio.NewReader(reader)
	}

	// Check for none provider - stream data directly without encryption
	if m.providerManager.IsNoneProvider() {
		// For none provider, just read segments and pass through
		buffer := make([]byte, segmentSize)
		for {
			n, err := bufReader.Read(buffer)
			if n > 0 {
				if segmentErr := onSegmentReady(buffer[:n]); segmentErr != nil {
					return fmt.Errorf("segment callback failed: %w", segmentErr)
				}
			}
			if err == io.EOF {
				break
			}
			if err != nil {
				return fmt.Errorf("failed to read segment: %w", err)
			}
		}
		return nil
	}

	// For encrypted providers, use streaming encryption
	streamResult, err := m.UploadPart(ctx, uploadID, partNumber, bufReader)
	if err != nil {
		return fmt.Errorf("failed to encrypt part stream: %w", err)
	}

	// Read encrypted data in segments and call the callback
	buffer := make([]byte, segmentSize)
	for {
		n, err := streamResult.EncryptedDataReader.Read(buffer)
		if n > 0 {
			if segmentErr := onSegmentReady(buffer[:n]); segmentErr != nil {
				return fmt.Errorf("segment callback failed: %w", segmentErr)
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to read encrypted segment: %w", err)
		}
	}

	return nil
}

// FilterMetadataForClient removes encryption metadata from client responses
func (m *Manager) FilterMetadataForClient(metadata map[string]string) map[string]string {
	return m.metadataManager.FilterMetadataForClient(metadata)
}

// RotateKEK rotates the Key Encryption Key (not implemented)
func (m *Manager) RotateKEK(_ context.Context) error {
	return fmt.Errorf("KEK rotation not implemented in Manager")
}

// ===== MAINTENANCE OPERATIONS =====

// CleanupExpiredSessions removes expired multipart upload sessions
func (m *Manager) CleanupExpiredSessions(maxAge time.Duration) int {
	cleaned := m.multipartOps.CleanupExpiredSessions(maxAge)
	m.logger.WithField("cleaned_sessions", cleaned).Info("Completed session cleanup")
	return cleaned
}

// ClearCaches clears all internal caches for memory management
func (m *Manager) ClearCaches() {
	m.providerManager.ClearKeyCache()
	m.logger.Info("Cleared encryption manager caches")
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

// GetSessionCount returns the number of active multipart upload sessions
func (m *Manager) GetSessionCount() int {
	return m.multipartOps.GetSessionCount()
}

// ===== STATISTICS AND MONITORING =====

// GetStats returns operational statistics
func (m *Manager) GetStats() map[string]interface{} {
	return map[string]interface{}{
		"active_sessions":        m.GetSessionCount(),
		"provider_count":         len(m.GetProviderAliases()),
		"active_provider":        m.GetActiveProviderAlias(),
		"hmac_enabled":           m.hmacManager.IsEnabled(),
		"metadata_prefix":        m.GetMetadataKeyPrefix(),
		"streaming_threshold":    m.config.GetStreamingThreshold(),
		"streaming_segment_size": m.segmentSize,
	}
}

// ===== BACKGROUND CLEANUP =====

// startBackgroundCleanup starts a background goroutine that periodically cleans up expired multipart sessions
func (m *Manager) startBackgroundCleanup() {
	cleanupInterval := time.Duration(m.config.Optimizations.MultipartSessionCleanupInterval) * time.Second
	maxAge := time.Duration(m.config.Optimizations.MultipartSessionMaxAge) * time.Second

	m.cleanupWg.Add(1)
	go func() {
		defer m.cleanupWg.Done()

		ticker := time.NewTicker(cleanupInterval)
		defer ticker.Stop()

		m.logger.WithFields(logrus.Fields{
			"cleanup_interval": cleanupInterval,
			"max_session_age":  maxAge,
		}).Info("Started background multipart session cleanup")

		for {
			select {
			case <-m.cleanupCtx.Done():
				m.logger.Debug("Background cleanup stopped")
				return
			case <-ticker.C:
				expiredCount := m.multipartOps.CleanupExpiredSessions(maxAge)
				if expiredCount > 0 {
					m.logger.WithField("expired_sessions", expiredCount).Debug("Background cleanup completed")
				}
			}
		}
	}()
}

// Shutdown gracefully shuts down the manager and stops background cleanup
func (m *Manager) Shutdown(ctx context.Context) error {
	m.logger.Info("Shutting down encryption manager")

	// Cancel background cleanup
	if m.cleanupCancel != nil {
		m.cleanupCancel()
	}

	// Wait for cleanup goroutine to finish with timeout
	done := make(chan struct{})
	go func() {
		m.cleanupWg.Wait()
		close(done)
	}()

	select {
	case <-done:
		m.logger.Debug("Background cleanup stopped successfully")
	case <-ctx.Done():
		m.logger.Warn("Timeout waiting for background cleanup to stop")
	}

	return nil
}

// ===== STREAMING HELPER METHODS (integrated from streaming.go) =====

// getBuffer gets a buffer from the pool for streaming operations
func (m *Manager) getBuffer() []byte {
	return m.bufferPool.Get().([]byte)
}

// returnBuffer returns a buffer to the pool after secure clearing
func (m *Manager) returnBuffer(buffer []byte) {
	clear(buffer)
	m.bufferPool.Put(buffer) //nolint:staticcheck
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
		buffer:    m.getBuffer(),
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

	// Get provider for DEK decryption
	provider, err := m.providerManager.GetProviderByFingerprint(fingerprint)
	if err != nil {
		return nil, fmt.Errorf("failed to get provider for fingerprint %s: %w", fingerprint, err)
	}

	// Extract encrypted DEK from metadata
	encryptedDEK, err := m.metadataManager.GetEncryptedDEK(metadata)
	if err != nil {
		return nil, fmt.Errorf("failed to get encrypted DEK from metadata: %w", err)
	}

	// Decrypt DEK
	dek, err := provider.DecryptDEK(ctx, encryptedDEK, fingerprint)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt DEK: %w", err)
	}

	// Create streaming decryptor
	decryptor, err := m.createStreamingDecryptor(dek, metadata)
	if err != nil {
		return nil, fmt.Errorf("failed to create streaming decryptor: %w", err)
	}

	// Create decryption reader
	decReader := &decryptionReader{
		reader:    bufReader,
		decryptor: decryptor,
		buffer:    m.getBuffer(),
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

// ===== READER IMPLEMENTATIONS =====

// Read implements io.Reader for encryptionReader
func (er *encryptionReader) Read(p []byte) (int, error) {
	if er.finished {
		return 0, io.EOF
	}

	n, err := er.reader.Read(p)
	if n > 0 {
		encryptedData, encErr := er.encryptor.EncryptPart(p[:n])
		if encErr != nil {
			er.logger.WithError(encErr).Error("Failed to encrypt streaming data")
			return n, fmt.Errorf("encryption failed: %w", encErr)
		}
		copy(p[:n], encryptedData)
		er.logger.WithFields(logrus.Fields{
			"bytes_read":      n,
			"bytes_encrypted": len(encryptedData),
		}).Debug("Real-time encrypted streaming data")
	}

	if err != nil {
		if err == io.EOF {
			er.finished = true
			er.logger.Debug("Finished encryption reader stream")
		} else {
			er.logger.WithError(err).Error("Error reading from underlying stream")
		}
		return n, err
	}

	return n, nil
}

// Close implements io.Closer for encryptionReader
func (er *encryptionReader) Close() error {
	if er.buffer != nil {
		clear(er.buffer)
		er.buffer = nil
	}
	er.logger.Debug("Closed encryption reader and cleaned up resources")
	return nil
}

// Read implements io.Reader for decryptionReader
func (dr *decryptionReader) Read(p []byte) (int, error) {
	if dr.finished {
		return 0, io.EOF
	}

	n, err := dr.reader.Read(p)
	if n > 0 {
		decryptedData, decErr := dr.decryptor.DecryptPart(p[:n])
		if decErr != nil {
			dr.logger.WithError(decErr).Error("Failed to decrypt streaming data")
			return n, fmt.Errorf("decryption failed: %w", decErr)
		}
		copy(p[:n], decryptedData)
		dr.logger.WithFields(logrus.Fields{
			"bytes_read":      n,
			"bytes_decrypted": len(decryptedData),
		}).Trace("Real-time decrypted streaming data")
	}

	if err != nil {
		if err == io.EOF {
			dr.finished = true
			dr.logger.Debug("Finished decryption reader stream")
		} else {
			dr.logger.WithError(err).Error("Error reading from underlying encrypted stream")
		}
		return n, err
	}

	return n, nil
}

// Close implements io.Closer for decryptionReader
func (dr *decryptionReader) Close() error {
	if dr.buffer != nil {
		clear(dr.buffer)
		dr.buffer = nil
	}
	dr.logger.Debug("Closed decryption reader and cleaned up resources")
	return nil
}

// Read implements io.Reader for hmacValidatingReader
func (hvr *hmacValidatingReader) Read(p []byte) (int, error) {
	if hvr.finished {
		return 0, io.EOF
	}

	if hvr.validationErr != nil {
		return 0, hvr.validationErr
	}

	// Serve buffered data from last chunk first
	if hvr.lastChunkSize > 0 && hvr.lastChunkPos < hvr.lastChunkSize {
		remaining := hvr.lastChunkSize - hvr.lastChunkPos
		n := remaining
		if n > len(p) {
			n = len(p)
		}
		copy(p, hvr.lastChunkBuf[hvr.lastChunkPos:hvr.lastChunkPos+n])
		hvr.lastChunkPos += n

		if hvr.lastChunkPos >= hvr.lastChunkSize {
			hvr.finished = true
			hvr.logger.WithFields(logrus.Fields{
				"object_key":      hvr.objectKey,
				"total_decrypted": hvr.totalDecrypted,
			}).Info("✅ Completed secure streaming with HMAC validation")
			return n, io.EOF
		}
		return n, nil
	}

	// Read from underlying reader
	n, err := hvr.reader.Read(p)

	if n > 0 {
		if hvr.hmacCalculator != nil {
			if _, hmacErr := hvr.hmacCalculator.Add(p[:n]); hmacErr != nil {
				hvr.logger.WithError(hmacErr).Error("Failed to update HMAC during streaming")
				hvr.validationErr = fmt.Errorf("HMAC calculation failed: %w", hmacErr)
				return 0, hvr.validationErr
			}
		}

		hvr.totalRead += int64(n)
		hvr.totalDecrypted += int64(n)

		// Check if near end for buffering
		bufferThreshold := hvr.expectedSize - (2 * int64(len(p)))
		if hvr.expectedSize > 0 && hvr.totalRead >= bufferThreshold && err == nil {
			hvr.logger.WithFields(logrus.Fields{
				"object_key":    hvr.objectKey,
				"total_read":    hvr.totalRead,
				"expected_size": hvr.expectedSize,
			}).Debug("🔒 Near end of stream - preparing to buffer last chunk")
			return n, nil
		}
	}

	// Handle EOF - this is the last chunk
	if err == io.EOF {
		hvr.logger.WithFields(logrus.Fields{
			"object_key":      hvr.objectKey,
			"last_chunk_size": n,
			"total_read":      hvr.totalRead,
		}).Info("🔍 Last chunk detected - buffering for HMAC validation")

		// Buffer this last chunk
		if hvr.lastChunkBuf == nil {
			hvr.lastChunkBuf = make([]byte, len(p))
		}
		copy(hvr.lastChunkBuf, p[:n])
		hvr.lastChunkSize = n
		hvr.lastChunkPos = 0

		// Validate HMAC before releasing
		if hvr.hmacManager != nil && hvr.hmacCalculator != nil && len(hvr.expectedHMAC) > 0 {
			hvr.logger.WithField("object_key", hvr.objectKey).Info("⏳ Validating HMAC before releasing last chunk...")

			if verifyErr := hvr.hmacManager.VerifyIntegrity(hvr.hmacCalculator, hvr.expectedHMAC); verifyErr != nil {
				hvr.logger.WithError(verifyErr).WithField("object_key", hvr.objectKey).Error("❌ HMAC validation FAILED")
				hvr.validationErr = fmt.Errorf("HMAC integrity verification failed: %w", verifyErr)
				hvr.finished = true
				return 0, hvr.validationErr
			}

			hvr.validated = true
			hvr.logger.WithField("object_key", hvr.objectKey).Info("✅ HMAC validation SUCCESSFUL - releasing last chunk")
		}

		// Serve buffered chunk
		return hvr.Read(p)
	}

	if err != nil {
		hvr.logger.WithError(err).Error("Error reading during HMAC validating stream")
		return n, err
	}

	return n, nil
}

// Close implements io.Closer for hmacValidatingReader
func (hvr *hmacValidatingReader) Close() error {
	if hvr.lastChunkBuf != nil {
		clear(hvr.lastChunkBuf)
		hvr.lastChunkBuf = nil
	}
	if hvr.hmacCalculator != nil {
		hvr.hmacCalculator.Cleanup()
		hvr.hmacCalculator = nil
	}
	if closer, ok := hvr.reader.(io.Closer); ok {
		return closer.Close()
	}
	hvr.logger.Debug("Closed HMAC validating reader and cleaned up resources")
	return nil
}
