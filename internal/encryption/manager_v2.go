package encryption

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/guided-traffic/s3-encryption-proxy/internal/config"
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

// ManagerV2 is the main orchestration layer for all encryption operations
// It coordinates between all specialized components with clear data paths
type ManagerV2 struct {
	config          *config.Config
	providerManager *ProviderManager
	singlePartOps   *SinglePartOperations
	multipartOps    *MultipartOperations
	streamingOps    *StreamingOperations
	metadataManager *MetadataManagerV2
	hmacManager     *HMACManager
	logger          *logrus.Entry
}

// NewManagerV2 creates a new encryption manager with modular architecture
func NewManagerV2(cfg *config.Config) (*ManagerV2, error) {
	logger := logrus.WithField("component", "manager_v2")

	// Create provider manager first
	providerManager, err := NewProviderManager(cfg)
	if err != nil {
		logger.WithError(err).Error("Failed to create provider manager")
		return nil, fmt.Errorf("failed to create provider manager: %w", err)
	}

	// Create metadata manager
	metadataManager := NewMetadataManagerV2(cfg, "")

	// Create HMAC manager
	hmacManager := NewHMACManager(cfg)

	// Create specialized operation handlers
	singlePartOps := NewSinglePartOperations(providerManager, metadataManager, hmacManager, cfg)
	multipartOps := NewMultipartOperations(providerManager, hmacManager, metadataManager, cfg)
	streamingOps := NewStreamingOperations(providerManager, hmacManager, metadataManager, cfg)

	manager := &ManagerV2{
		config:          cfg,
		providerManager: providerManager,
		singlePartOps:   singlePartOps,
		multipartOps:    multipartOps,
		streamingOps:    streamingOps,
		metadataManager: metadataManager,
		hmacManager:     hmacManager,
		logger:          logger,
	}

	logger.WithFields(logrus.Fields{
		"provider_count":     len(providerManager.GetProviderAliases()),
		"active_provider":    providerManager.GetActiveProviderAlias(),
		"hmac_enabled":       hmacManager.IsEnabled(),
		"metadata_prefix":    metadataManager.GetMetadataPrefix(),
	}).Info("Successfully initialized ManagerV2")

	return manager, nil
}

// ===== SINGLE PART OPERATIONS =====

// EncryptData encrypts data using size-based algorithm selection (GCM vs CTR)
func (m *ManagerV2) EncryptData(ctx context.Context, data []byte, objectKey string) (*encryption.EncryptionResult, error) {
	m.logger.WithFields(logrus.Fields{
		"object_key": objectKey,
		"data_size":  len(data),
	}).Debug("Starting data encryption")

	// Use single part operations to determine the appropriate algorithm
	if m.singlePartOps.ShouldUseGCM(int64(len(data))) {
		return m.EncryptGCM(ctx, data, objectKey)
	}
	return m.EncryptCTR(ctx, data, objectKey)
}

// EncryptGCM encrypts data using AES-GCM (for small objects)
func (m *ManagerV2) EncryptGCM(ctx context.Context, data []byte, objectKey string) (*encryption.EncryptionResult, error) {
	m.logger.WithFields(logrus.Fields{
		"object_key": objectKey,
		"data_size":  len(data),
		"algorithm":  "aes-gcm",
	}).Debug("Encrypting data with GCM")

	result, err := m.singlePartOps.EncryptGCM(ctx, data, objectKey)
	if err != nil {
		return nil, err
	}

	return &encryption.EncryptionResult{
		EncryptedData: result.EncryptedData,
		Metadata:      result.Metadata,
	}, nil
}

// EncryptCTR encrypts data using AES-CTR (for large objects)
func (m *ManagerV2) EncryptCTR(ctx context.Context, data []byte, objectKey string) (*encryption.EncryptionResult, error) {
	m.logger.WithFields(logrus.Fields{
		"object_key": objectKey,
		"data_size":  len(data),
		"algorithm":  "aes-ctr",
	}).Debug("Encrypting data with CTR")

	result, err := m.singlePartOps.EncryptCTR(ctx, data, objectKey)
	if err != nil {
		return nil, err
	}

	return &encryption.EncryptionResult{
		EncryptedData: result.EncryptedData,
		Metadata:      result.Metadata,
	}, nil
}

// EncryptDataWithContentType encrypts data with explicit content type specification
func (m *ManagerV2) EncryptDataWithContentType(ctx context.Context, data []byte, objectKey string, contentType factory.ContentType) (*encryption.EncryptionResult, error) {
	m.logger.WithFields(logrus.Fields{
		"object_key":   objectKey,
		"data_size":    len(data),
		"content_type": contentType,
	}).Debug("Encrypting data with specified content type")

	// Route based on content type
	switch contentType {
	case factory.ContentTypeWhole:
		return m.EncryptGCM(ctx, data, objectKey)
	case factory.ContentTypeMultipart:
		return m.EncryptCTR(ctx, data, objectKey)
	default:
		return m.EncryptData(ctx, data, objectKey) // Fall back to size-based selection
	}
}

// EncryptDataWithHTTPContentType encrypts data based on HTTP content type and multipart flag
func (m *ManagerV2) EncryptDataWithHTTPContentType(ctx context.Context, data []byte, objectKey string, httpContentType string, isMultipart bool) (*encryption.EncryptionResult, error) {
	m.logger.WithFields(logrus.Fields{
		"object_key":        objectKey,
		"data_size":         len(data),
		"http_content_type": httpContentType,
		"is_multipart":      isMultipart,
	}).Debug("Encrypting data with HTTP content type")

	// Convert HTTP content type to factory content type
	var contentType factory.ContentType
	if isMultipart {
		contentType = factory.ContentTypeMultipart
	} else {
		contentType = factory.ContentTypeWhole
	}

	return m.EncryptDataWithContentType(ctx, data, objectKey, contentType)
}

// DecryptData decrypts data using metadata to determine the algorithm
func (m *ManagerV2) DecryptData(ctx context.Context, encryptedData []byte, metadata map[string]string, objectKey string) ([]byte, error) {
	m.logger.WithFields(logrus.Fields{
		"object_key":     objectKey,
		"encrypted_size": len(encryptedData),
	}).Debug("Starting data decryption")

	// Extract algorithm from metadata
	algorithm, err := m.metadataManager.GetAlgorithm(metadata)
	if err != nil {
		m.logger.WithError(err).Error("Failed to get algorithm from metadata")
		return nil, fmt.Errorf("failed to get algorithm from metadata: %w", err)
	}

	// Route to appropriate decryption method
	switch algorithm {
	case "aes-gcm", "aes-256-gcm":
		return m.singlePartOps.DecryptGCM(ctx, encryptedData, metadata, objectKey)
	case "aes-ctr", "aes-256-ctr":
		return m.singlePartOps.DecryptCTR(ctx, encryptedData, metadata, objectKey)
	case "none":
		m.logger.WithField("object_key", objectKey).Debug("Using none algorithm - returning data as-is")
		return encryptedData, nil
	default:
		m.logger.WithFields(logrus.Fields{
			"algorithm":  algorithm,
			"object_key": objectKey,
		}).Error("Unknown algorithm in metadata")
		return nil, fmt.Errorf("unknown algorithm: %s", algorithm)
	}
}

// DecryptDataWithMetadata decrypts data with full metadata context (legacy interface)
func (m *ManagerV2) DecryptDataWithMetadata(ctx context.Context, encryptedData, encryptedDEK []byte, metadata map[string]string, objectKey string, providerAlias string) ([]byte, error) {
	// For V2, we ignore the separate encryptedDEK and providerAlias parameters
	// since they should be embedded in the metadata
	return m.DecryptData(ctx, encryptedData, metadata, objectKey)
}

// ===== MULTIPART OPERATIONS =====

// InitiateMultipartUpload starts a new multipart upload session
func (m *ManagerV2) InitiateMultipartUpload(ctx context.Context, uploadID, objectKey, bucketName string) error {
	m.logger.WithFields(logrus.Fields{
		"upload_id":   uploadID,
		"object_key":  objectKey,
		"bucket_name": bucketName,
	}).Debug("Initiating multipart upload")

	_, err := m.multipartOps.InitiateSession(ctx, uploadID, objectKey, bucketName)
	return err
}

// UploadPart encrypts and processes a multipart upload part
func (m *ManagerV2) UploadPart(ctx context.Context, uploadID string, partNumber int, data []byte) (*encryption.EncryptionResult, error) {
	m.logger.WithFields(logrus.Fields{
		"upload_id":   uploadID,
		"part_number": partNumber,
		"data_size":   len(data),
	}).Debug("Processing multipart upload part")

	result, err := m.multipartOps.ProcessPart(ctx, uploadID, partNumber, data)
	if err != nil {
		return nil, err
	}

	return &encryption.EncryptionResult{
		EncryptedData: result.EncryptedData,
		Metadata:      result.Metadata,
	}, nil
}

// UploadPartStreaming encrypts and processes a multipart upload part from a reader
func (m *ManagerV2) UploadPartStreaming(ctx context.Context, uploadID string, partNumber int, reader io.Reader) (*encryption.EncryptionResult, error) {
	m.logger.WithFields(logrus.Fields{
		"upload_id":   uploadID,
		"part_number": partNumber,
	}).Debug("Processing streaming multipart upload part")

	// Read the data from the reader
	data, err := io.ReadAll(reader)
	if err != nil {
		m.logger.WithError(err).Error("Failed to read data from streaming reader")
		return nil, fmt.Errorf("failed to read data from reader: %w", err)
	}

	return m.UploadPart(ctx, uploadID, partNumber, data)
}

// StorePartETag stores the ETag for a multipart upload part
func (m *ManagerV2) StorePartETag(uploadID string, partNumber int, etag string) error {
	return m.multipartOps.StorePartETag(uploadID, partNumber, etag)
}

// CompleteMultipartUpload finalizes a multipart upload and returns final metadata
func (m *ManagerV2) CompleteMultipartUpload(ctx context.Context, uploadID string, parts map[int]string) (map[string]string, error) {
	m.logger.WithFields(logrus.Fields{
		"upload_id":   uploadID,
		"parts_count": len(parts),
	}).Debug("Completing multipart upload")

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
func (m *ManagerV2) AbortMultipartUpload(ctx context.Context, uploadID string) error {
	m.logger.WithField("upload_id", uploadID).Debug("Aborting multipart upload")
	return m.multipartOps.AbortSession(ctx, uploadID)
}

// CleanupMultipartUpload removes a multipart upload session (alias for abort)
func (m *ManagerV2) CleanupMultipartUpload(uploadID string) error {
	return m.AbortMultipartUpload(context.Background(), uploadID)
}

// GetMultipartUploadState returns the state of a multipart upload session
func (m *ManagerV2) GetMultipartUploadState(uploadID string) (*MultipartSession, error) {
	return m.multipartOps.GetSession(uploadID)
}

// ===== STREAMING OPERATIONS =====

// CreateEncryptionReader creates a reader that encrypts data on-the-fly
func (m *ManagerV2) CreateEncryptionReader(ctx context.Context, reader io.Reader, objectKey string) (io.Reader, map[string]string, error) {
	m.logger.WithField("object_key", objectKey).Debug("Creating encryption reader")
	return m.streamingOps.CreateEncryptionReader(ctx, reader, objectKey)
}

// CreateDecryptionReader creates a reader that decrypts data on-the-fly
func (m *ManagerV2) CreateDecryptionReader(ctx context.Context, reader io.Reader, metadata map[string]string) (io.Reader, error) {
	m.logger.Debug("Creating decryption reader")
	return m.streamingOps.CreateDecryptionReader(ctx, reader, metadata)
}

// ===== PROVIDER MANAGEMENT =====

// GetProviderAliases returns all configured provider aliases
func (m *ManagerV2) GetProviderAliases() []string {
	return m.providerManager.GetProviderAliases()
}

// GetActiveProviderAlias returns the active provider alias
func (m *ManagerV2) GetActiveProviderAlias() string {
	return m.providerManager.GetActiveProviderAlias()
}

// GetLoadedProviders returns information about all loaded providers
func (m *ManagerV2) GetLoadedProviders() []ProviderSummary {
	return m.providerManager.GetLoadedProviders()
}

// GetProvider returns a provider by alias (legacy interface - not recommended)
func (m *ManagerV2) GetProvider(alias string) (encryption.EncryptionProvider, bool) {
	// In V2 architecture, we don't expose individual providers
	// This method exists for backward compatibility only
	return nil, false
}

// ===== UTILITY METHODS =====

// GetMetadataKeyPrefix returns the configured metadata key prefix
func (m *ManagerV2) GetMetadataKeyPrefix() string {
	return m.metadataManager.GetMetadataPrefix()
}

// GetStreamingSegmentSize returns the configured streaming segment size
func (m *ManagerV2) GetStreamingSegmentSize() int64 {
	return m.streamingOps.GetSegmentSize()
}

// CreateStreamingDecryptionReaderWithSize creates a streaming decryption reader with size hint for optimal buffer sizing
func (m *ManagerV2) CreateStreamingDecryptionReaderWithSize(ctx context.Context, encryptedReader io.ReadCloser, encryptedDEK []byte, metadata map[string]string, objectKey string, providerAlias string, expectedSize int64) (io.ReadCloser, error) {
	// For V2, we delegate to the streaming operations
	reader, err := m.streamingOps.CreateDecryptionReader(ctx, encryptedReader, metadata)
	if err != nil {
		return nil, err
	}

	// Wrap as ReadCloser if needed
	if readCloser, ok := reader.(io.ReadCloser); ok {
		return readCloser, nil
	}

	// Create a simple ReadCloser wrapper
	return &readCloserWrapper{Reader: reader, closer: encryptedReader}, nil
}

// UploadPartStreamingBuffer encrypts and uploads a part using true streaming with segment buffering
func (m *ManagerV2) UploadPartStreamingBuffer(ctx context.Context, uploadID string, partNumber int, reader io.Reader, segmentSize int64, onSegmentReady SegmentCallback) error {
	// For V2, we use the multipart operations with streaming
	// This is a simplified implementation - in the real refactor, this would use streaming operations
	_, err := m.multipartOps.ProcessPart(ctx, uploadID, partNumber, nil) // TODO: Implement proper streaming buffer logic
	return err
}

// FilterMetadataForClient removes encryption metadata from client responses
func (m *ManagerV2) FilterMetadataForClient(metadata map[string]string) map[string]string {
	return m.metadataManager.FilterMetadataForClient(metadata)
}

// RotateKEK rotates the Key Encryption Key (not implemented in V2)
func (m *ManagerV2) RotateKEK(ctx context.Context) error {
	return fmt.Errorf("KEK rotation not implemented in ManagerV2")
}

// ===== MAINTENANCE OPERATIONS =====

// CleanupExpiredSessions removes expired multipart upload sessions
func (m *ManagerV2) CleanupExpiredSessions(maxAge time.Duration) int {
	cleaned := m.multipartOps.CleanupExpiredSessions(maxAge)
	m.logger.WithField("cleaned_sessions", cleaned).Info("Completed session cleanup")
	return cleaned
}

// ClearCaches clears all internal caches for memory management
func (m *ManagerV2) ClearCaches() {
	m.providerManager.ClearKeyCache()
	m.logger.Info("Cleared all internal caches")
}

// GetSessionCount returns the number of active multipart upload sessions
func (m *ManagerV2) GetSessionCount() int {
	return m.multipartOps.GetSessionCount()
}

// ===== STATISTICS AND MONITORING =====

// GetStats returns operational statistics
func (m *ManagerV2) GetStats() map[string]interface{} {
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
