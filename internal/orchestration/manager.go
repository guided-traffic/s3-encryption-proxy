package orchestration

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/guided-traffic/s3-encryption-proxy/internal/config"
	"github.com/guided-traffic/s3-encryption-proxy/internal/validation"
	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption"
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
	Metadata           map[string]string
	Algorithm          string
	KeyFingerprint     string
}

// Manager is the main orchestration layer for all encryption operations
// It coordinates between all specialized components with clear data paths
type Manager struct {
	config          *config.Config
	providerManager *ProviderManager
	singlePartOps   *SinglePartOperations
	multipartOps    *MultipartOperations
	streamingOps    *StreamingOperations
	metadataManager *MetadataManager
	hmacManager     *validation.HMACManager
	logger          *logrus.Entry // Public for testing

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

	// Create specialized operation handlers
	singlePartOps := NewSinglePartOperations(providerManager, metadataManager, hmacManager, cfg)
	multipartOps := NewMultipartOperations(providerManager, hmacManager, metadataManager, cfg)
	streamingOps := NewStreamingOperations(providerManager, hmacManager, metadataManager, cfg)

	// Create background cleanup context
	cleanupCtx, cleanupCancel := context.WithCancel(context.Background())

	manager := &Manager{
		config:          cfg,
		providerManager: providerManager,
		singlePartOps:   singlePartOps,
		multipartOps:    multipartOps,
		streamingOps:    streamingOps,
		metadataManager: metadataManager,
		hmacManager:     hmacManager,
		logger:          logger,
		cleanupCtx:      cleanupCtx,
		cleanupCancel:   cleanupCancel,
	}

	// Start background cleanup if cleanup interval is configured
	if cfg.Optimizations.MultipartSessionCleanupInterval > 0 {
		manager.startBackgroundCleanup()
	}

	logger.WithFields(logrus.Fields{
		"provider_count":     len(providerManager.GetProviderAliases()),
		"active_provider":    providerManager.GetActiveProviderAlias(),
		"hmac_enabled":       hmacManager.IsEnabled(),
		"metadata_prefix":    metadataManager.GetMetadataPrefix(),
	}).Info("Successfully initialized Manager")

	return manager, nil
}

// ===== STREAMING ENCRYPTION OPERATIONS =====

// EncryptData encrypts data from a reader using size-based algorithm selection (GCM vs CTR)
// This is the preferred method for performance as it uses streaming encryption throughout
func (m *Manager) EncryptData(ctx context.Context, dataReader *bufio.Reader, objectKey string) (*StreamingEncryptionResult, error) {
	m.logger.WithField("object_key", objectKey).Debug("Starting streaming data encryption")

	// Check for none provider - complete pass-through with no encryption or metadata
	if m.providerManager.IsNoneProvider() {
		m.logger.WithField("object_key", objectKey).Debug("Using none provider - complete pass-through without encryption or HMAC")
		return &StreamingEncryptionResult{
			EncryptedDataReader: dataReader, // Return data reader unchanged
			Metadata:           make(map[string]string), // No metadata
		}, nil
	}

	// Use streaming operations for efficient encryption
	encryptedReader, metadata, err := m.streamingOps.CreateEncryptionReader(ctx, dataReader, objectKey)
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
		Metadata:           metadata,
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
		Metadata:           metadata,
		Algorithm:          algorithm,
	}, nil
}

// EncryptCTR encrypts data using AES-CTR with streaming (for large objects)
func (m *Manager) EncryptCTR(ctx context.Context, dataReader *bufio.Reader, objectKey string) (*StreamingEncryptionResult, error) {
	m.logger.WithFields(logrus.Fields{
		"object_key": objectKey,
		"algorithm":  "aes-ctr",
	}).Debug("Encrypting data stream with CTR")

	// Create envelope encryptor for multipart content (CTR)
	provider, err := m.providerManager.CreateEnvelopeEncryptor(factory.ContentTypeMultipart, m.metadataManager.GetMetadataPrefix())
	if err != nil {
		return nil, fmt.Errorf("failed to create envelope encryptor: %w", err)
	}

	// Create associated data
	associatedData := []byte(objectKey)

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
		Metadata:           metadata,
		Algorithm:          algorithm,
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
			EncryptedDataReader: dataReader, // Return data reader unchanged
			Metadata:           make(map[string]string), // No metadata
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

	// Use singlepart operations for GCM decryption (not streaming operations)
	decryptedReader, err := m.singlePartOps.DecryptGCM(ctx, encryptedDataReader, metadata, objectKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt GCM data: %w", err)
	}

	return decryptedReader, nil
}

// DecryptCTRStream decrypts data using AES-CTR with streaming
func (m *Manager) DecryptCTRStream(ctx context.Context, encryptedDataReader *bufio.Reader, metadata map[string]string, objectKey string) (*bufio.Reader, error) {
	m.logger.WithFields(logrus.Fields{
		"object_key": objectKey,
		"algorithm":  "aes-ctr",
	}).Debug("Decrypting data stream with CTR")

	// Use streaming operations for efficient decryption
	decryptedReader, err := m.streamingOps.CreateDecryptionReader(ctx, encryptedDataReader, metadata)
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
func (m *Manager) DecryptDataWithMetadata(ctx context.Context, encryptedData, encryptedDEK []byte, metadata map[string]string, objectKey string, providerAlias string) ([]byte, error) {
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
			EncryptedDataReader: dataReader, // Return data reader unchanged
			Metadata:           make(map[string]string), // No metadata
		}, nil
	}

	// Use the new multipart ProcessPart method that maintains persistent CTR state
	// This ensures continuous encryption stream across all parts
	result, err := m.multipartOps.ProcessPart(ctx, uploadID, partNumber, dataReader)
	if err != nil {
		return nil, fmt.Errorf("failed to process multipart part: %w", err)
	}

	m.logger.WithFields(logrus.Fields{
		"upload_id":        uploadID,
		"part_number":      partNumber,
		"algorithm":        result.Algorithm,
		"key_fingerprint":  result.KeyFingerprint,
	}).Debug("Successfully processed multipart part with persistent CTR encryptor")

	return &StreamingEncryptionResult{
		EncryptedDataReader: result.EncryptedData,
		Metadata:           result.Metadata,
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

// CreateEncryptionReader creates a reader that encrypts data on-the-fly using bufio
func (m *Manager) CreateEncryptionReader(ctx context.Context, reader io.Reader, objectKey string) (io.Reader, map[string]string, error) {
	m.logger.WithField("object_key", objectKey).Debug("Creating encryption reader")

	// Convert to bufio.Reader for better performance
	var bufReader *bufio.Reader
	if br, ok := reader.(*bufio.Reader); ok {
		bufReader = br
	} else {
		bufReader = bufio.NewReader(reader)
	}

	// Check for none provider - complete pass-through with no encryption or metadata
	if m.providerManager.IsNoneProvider() {
		m.logger.WithField("object_key", objectKey).Debug("Using none provider - streaming pass-through without encryption or HMAC")
		return bufReader, make(map[string]string), nil // Return original reader with no metadata
	}

	return m.streamingOps.CreateEncryptionReader(ctx, bufReader, objectKey)
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

// CreateDecryptionReader creates a reader that decrypts data on-the-fly using bufio
func (m *Manager) CreateDecryptionReader(ctx context.Context, reader io.Reader, metadata map[string]string) (io.Reader, error) {
	m.logger.Debug("Creating decryption reader")

	// Convert to bufio.Reader for better performance
	var bufReader *bufio.Reader
	if br, ok := reader.(*bufio.Reader); ok {
		bufReader = br
	} else {
		bufReader = bufio.NewReader(reader)
	}

	return m.streamingOps.CreateDecryptionReader(ctx, bufReader, metadata)
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
func (m *Manager) GetProvider(alias string) (encryption.EncryptionProvider, bool) {
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
	return m.streamingOps.GetSegmentSize()
}

// CreateStreamingDecryptionReaderWithSize creates a streaming decryption reader with size hint for optimal buffer sizing
func (m *Manager) CreateStreamingDecryptionReaderWithSize(ctx context.Context, encryptedReader io.ReadCloser, encryptedDEK []byte, metadata map[string]string, objectKey string, providerAlias string, expectedSize int64) (io.ReadCloser, error) {
	m.logger.WithFields(logrus.Fields{
		"object_key":     objectKey,
		"expected_size":  expectedSize,
		"provider_alias": providerAlias,
	}).Debug("Creating streaming decryption reader with size hint")

	// Convert to bufio.Reader for better performance
	var bufReader *bufio.Reader
	bufReader = bufio.NewReader(encryptedReader)

	// For V2, we delegate to the streaming operations
	reader, err := m.streamingOps.CreateDecryptionReader(ctx, bufReader, metadata)
	if err != nil {
		return nil, fmt.Errorf("failed to create decryption reader: %w", err)
	}

	// Wrap as ReadCloser if needed
	if readCloser, ok := reader.(io.ReadCloser); ok {
		return readCloser, nil
	}

	// Create a simple ReadCloser wrapper
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
func (m *Manager) RotateKEK(ctx context.Context) error {
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
		"active_sessions":     m.GetSessionCount(),
		"provider_count":      len(m.GetProviderAliases()),
		"active_provider":     m.GetActiveProviderAlias(),
		"hmac_enabled":        m.hmacManager.IsEnabled(),
		"metadata_prefix":     m.GetMetadataKeyPrefix(),
		"streaming_threshold": m.singlePartOps.GetThreshold(),
		"streaming_segment_size": m.streamingOps.GetSegmentSize(),
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
