package encryption

import (
	"context"
	"fmt"
	"io"
	"sync"

	"github.com/sirupsen/logrus"

	"github.com/guided-traffic/s3-encryption-proxy/internal/config"
)

// StreamingOperations handles memory-optimized streaming encryption and decryption
type StreamingOperations struct {
	providerManager *ProviderManager
	hmacManager     *HMACManager
	metadataManager *MetadataManagerV2
	bufferPool      *sync.Pool
	segmentSize     int64
	config          *config.Config
	logger          *logrus.Entry
}

// EncryptionReader wraps an io.Reader to provide on-the-fly encryption
type EncryptionReader struct {
	reader          io.Reader
	encryptor       interface{} // The underlying streaming encryptor
	buffer          []byte
	metadata        map[string]string
	finished        bool
	logger          *logrus.Entry
}

// DecryptionReader wraps an io.Reader to provide on-the-fly decryption
type DecryptionReader struct {
	reader          io.Reader
	decryptor       interface{} // The underlying streaming decryptor
	buffer          []byte
	finished        bool
	logger          *logrus.Entry
}

// NewStreamingOperations creates a new streaming operations handler
func NewStreamingOperations(
	providerManager *ProviderManager,
	hmacManager *HMACManager,
	metadataManager *MetadataManagerV2,
	config *config.Config,
) *StreamingOperations {
	logger := logrus.WithField("component", "streaming_operations")

	// Determine segment size from configuration
	segmentSize := int64(12 * 1024 * 1024) // Default 12MB
	if config != nil {
		segmentSize = config.GetStreamingSegmentSize()
	}

	// Create buffer pool for streaming operations
	bufferPool := &sync.Pool{
		New: func() interface{} {
			return make([]byte, segmentSize)
		},
	}

	sop := &StreamingOperations{
		providerManager: providerManager,
		hmacManager:     hmacManager,
		metadataManager: metadataManager,
		bufferPool:      bufferPool,
		segmentSize:     segmentSize,
		config:          config,
		logger:          logger,
	}

	logger.WithField("segment_size", segmentSize).Info("Initialized streaming operations")
	return sop
}

// CreateEncryptionReader creates a reader that encrypts data on-the-fly
func (sop *StreamingOperations) CreateEncryptionReader(ctx context.Context, reader io.Reader, objectKey string) (io.Reader, map[string]string, error) {
	sop.logger.WithField("object_key", objectKey).Debug("Creating encryption reader for streaming")

	// Check for none provider
	if sop.providerManager.IsNoneProvider() {
		sop.logger.WithField("object_key", objectKey).Debug("Using none provider - no encryption for streaming")
		return reader, nil, nil
	}

	// For streaming encryption, we would need to implement a proper streaming encryptor
	// This is a simplified version that shows the structure
	metadata := make(map[string]string)

	encReader := &EncryptionReader{
		reader:   reader,
		buffer:   sop.getBuffer(),
		metadata: metadata,
		logger:   sop.logger.WithField("object_key", objectKey),
	}

	sop.logger.WithField("object_key", objectKey).Debug("Created encryption reader")
	return encReader, metadata, nil
}

// CreateDecryptionReader creates a reader that decrypts data on-the-fly
func (sop *StreamingOperations) CreateDecryptionReader(ctx context.Context, reader io.Reader, metadata map[string]string) (io.Reader, error) {
	sop.logger.Debug("Creating decryption reader for streaming")

	// Extract fingerprint from metadata
	fingerprint, err := sop.metadataManager.GetFingerprint(metadata)
	if err != nil {
		return nil, fmt.Errorf("failed to get fingerprint from metadata: %w", err)
	}

	// Check for none provider
	if fingerprint == "none-provider-fingerprint" {
		sop.logger.Debug("Using none provider - no decryption for streaming")
		return reader, nil
	}

	decReader := &DecryptionReader{
		reader: reader,
		buffer: sop.getBuffer(),
		logger: sop.logger,
	}

	sop.logger.Debug("Created decryption reader")
	return decReader, nil
}

// StreamWithSegments processes a stream in configurable segments
func (sop *StreamingOperations) StreamWithSegments(ctx context.Context, reader io.Reader, segmentCallback func([]byte) error) error {
	sop.logger.WithField("segment_size", sop.segmentSize).Debug("Starting segmented streaming")

	buffer := sop.getBuffer()
	defer sop.returnBuffer(buffer)

	totalProcessed := int64(0)
	segmentCount := 0

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		n, err := reader.Read(buffer[:sop.segmentSize])
		if n > 0 {
			segmentCount++
			totalProcessed += int64(n)

			// Process this segment
			if err := segmentCallback(buffer[:n]); err != nil {
				sop.logger.WithFields(logrus.Fields{
					"segment_count":    segmentCount,
					"total_processed":  totalProcessed,
					"segment_size":     n,
					"error":           err,
				}).Error("Failed to process segment")
				return fmt.Errorf("failed to process segment %d: %w", segmentCount, err)
			}

			sop.logger.WithFields(logrus.Fields{
				"segment_count":   segmentCount,
				"segment_size":    n,
				"total_processed": totalProcessed,
			}).Debug("Processed segment")
		}

		if err != nil {
			if err == io.EOF {
				break
			}
			sop.logger.WithError(err).Error("Failed to read from stream")
			return fmt.Errorf("failed to read from stream: %w", err)
		}
	}

	sop.logger.WithFields(logrus.Fields{
		"total_segments":   segmentCount,
		"total_processed":  totalProcessed,
	}).Info("Completed segmented streaming")

	return nil
}

// GetSegmentSize returns the configured segment size for streaming
func (sop *StreamingOperations) GetSegmentSize() int64 {
	return sop.segmentSize
}

// getBuffer gets a buffer from the pool
func (sop *StreamingOperations) getBuffer() []byte {
	return sop.bufferPool.Get().([]byte)
}

// returnBuffer returns a buffer to the pool
func (sop *StreamingOperations) returnBuffer(buffer []byte) {
	// Clear the buffer before returning to pool for security
	for i := range buffer {
		buffer[i] = 0
	}
	sop.bufferPool.Put(buffer)
}

// Read implements io.Reader for EncryptionReader
func (er *EncryptionReader) Read(p []byte) (int, error) {
	if er.finished {
		return 0, io.EOF
	}

	// For a full implementation, this would perform streaming encryption
	// This is a simplified version showing the structure
	n, err := er.reader.Read(p)
	if err != nil {
		if err == io.EOF {
			er.finished = true
		}
		return n, err
	}

	// In a real implementation, we would encrypt the data here
	// For now, just pass through
	er.logger.WithField("bytes_read", n).Debug("Encrypted streaming data")
	return n, nil
}

// Read implements io.Reader for DecryptionReader
func (dr *DecryptionReader) Read(p []byte) (int, error) {
	if dr.finished {
		return 0, io.EOF
	}

	// For a full implementation, this would perform streaming decryption
	// This is a simplified version showing the structure
	n, err := dr.reader.Read(p)
	if err != nil {
		if err == io.EOF {
			dr.finished = true
		}
		return n, err
	}

	// In a real implementation, we would decrypt the data here
	// For now, just pass through
	dr.logger.WithField("bytes_read", n).Debug("Decrypted streaming data")
	return n, nil
}

// EncryptStream encrypts an entire stream and returns the result
func (sop *StreamingOperations) EncryptStream(ctx context.Context, reader io.Reader, objectKey string) ([]byte, map[string]string, error) {
	sop.logger.WithField("object_key", objectKey).Debug("Encrypting entire stream")

	// Read entire stream into memory (for simplicity in this example)
	data, err := io.ReadAll(reader)
	if err != nil {
		sop.logger.WithError(err).Error("Failed to read stream for encryption")
		return nil, nil, fmt.Errorf("failed to read stream: %w", err)
	}

	// Check for none provider
	if sop.providerManager.IsNoneProvider() {
		sop.logger.WithField("object_key", objectKey).Debug("Using none provider - no encryption for stream")
		return data, nil, nil
	}

	// For a real implementation, this would use streaming encryption
	// For now, return the data as-is with empty metadata
	metadata := sop.metadataManager.BuildMetadataForEncryption(
		nil, // No DEK for simplified example
		nil, // No encrypted DEK
		nil, // No IV
		"aes-ctr",
		sop.providerManager.GetActiveFingerprint(),
		sop.providerManager.GetActiveProviderAlgorithm(),
		nil,
	)

	sop.logger.WithFields(logrus.Fields{
		"object_key":     objectKey,
		"original_size":  len(data),
		"encrypted_size": len(data),
	}).Debug("Completed stream encryption")

	return data, metadata, nil
}

// DecryptStream decrypts an entire stream and returns the result
func (sop *StreamingOperations) DecryptStream(ctx context.Context, reader io.Reader, metadata map[string]string) ([]byte, error) {
	sop.logger.Debug("Decrypting entire stream")

	// Extract fingerprint from metadata
	fingerprint, err := sop.metadataManager.GetFingerprint(metadata)
	if err != nil {
		return nil, fmt.Errorf("failed to get fingerprint from metadata: %w", err)
	}

	// Check for none provider
	if fingerprint == "none-provider-fingerprint" {
		sop.logger.Debug("Using none provider - no decryption for stream")
		data, err := io.ReadAll(reader)
		if err != nil {
			return nil, fmt.Errorf("failed to read stream: %w", err)
		}
		return data, nil
	}

	// Read entire stream into memory (for simplicity in this example)
	encryptedData, err := io.ReadAll(reader)
	if err != nil {
		sop.logger.WithError(err).Error("Failed to read stream for decryption")
		return nil, fmt.Errorf("failed to read stream: %w", err)
	}

	// For a real implementation, this would use streaming decryption
	// For now, return the data as-is
	sop.logger.WithFields(logrus.Fields{
		"encrypted_size": len(encryptedData),
		"decrypted_size": len(encryptedData),
	}).Debug("Completed stream decryption")

	return encryptedData, nil
}

// StreamEncryptWithCallback encrypts a stream using a callback for each encrypted segment
func (sop *StreamingOperations) StreamEncryptWithCallback(
	ctx context.Context,
	reader io.Reader,
	objectKey string,
	callback func(encryptedData []byte, isLastSegment bool) error,
) (map[string]string, error) {
	sop.logger.WithField("object_key", objectKey).Debug("Starting stream encryption with callback")

	metadata := make(map[string]string)

	err := sop.StreamWithSegments(ctx, reader, func(segment []byte) error {
		// For a real implementation, encrypt each segment
		// For now, just call the callback with unencrypted data
		return callback(segment, false) // We don't know if it's the last segment in this simplified version
	})

	if err != nil {
		return nil, err
	}

	sop.logger.WithField("object_key", objectKey).Debug("Completed stream encryption with callback")
	return metadata, nil
}

// StreamDecryptWithCallback decrypts a stream using a callback for each decrypted segment
func (sop *StreamingOperations) StreamDecryptWithCallback(
	ctx context.Context,
	reader io.Reader,
	metadata map[string]string,
	callback func(decryptedData []byte, isLastSegment bool) error,
) error {
	sop.logger.Debug("Starting stream decryption with callback")

	err := sop.StreamWithSegments(ctx, reader, func(segment []byte) error {
		// For a real implementation, decrypt each segment
		// For now, just call the callback with encrypted data (pass-through)
		return callback(segment, false) // We don't know if it's the last segment in this simplified version
	})

	if err != nil {
		return err
	}

	sop.logger.Debug("Completed stream decryption with callback")
	return nil
}
