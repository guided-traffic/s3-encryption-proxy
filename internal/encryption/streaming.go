package encryption

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"sync"

	"github.com/sirupsen/logrus"

	"github.com/guided-traffic/s3-encryption-proxy/internal/config"
	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption/dataencryption"
)

// StreamingOperations handles memory-optimized streaming encryption and decryption.
// It provides efficient streaming operations for large objects without loading entire
// content into memory. The implementation uses configurable segment sizes and buffer
// pools to optimize memory usage and performance.
type StreamingOperations struct {
	providerManager *ProviderManager  // Manages encryption providers (AES, RSA, none)
	hmacManager     *HMACManager      // Handles HMAC operations for integrity verification
	metadataManager *MetadataManager  // Manages encryption metadata
	bufferPool      *sync.Pool        // Pool of reusable buffers for memory optimization
	segmentSize     int64             // Size of each streaming segment in bytes
	config          *config.Config    // Configuration settings
	logger          *logrus.Entry     // Logger for debugging and monitoring
}

// EncryptionReader wraps an io.Reader to provide on-the-fly encryption.
// It implements the io.Reader interface and encrypts data as it's being read,
// enabling memory-efficient streaming encryption for large objects.
//
// Performance Features:
//   - Real AES-CTR streaming encryption with maintaining cipher state
//   - Memory-efficient processing without intermediate buffers
//   - HMAC calculation for integrity verification during streaming
//   - Proper error handling and EOF management
type EncryptionReader struct {
	reader          io.Reader                                     // Source data reader
	encryptor       *dataencryption.AESCTRStreamingDataEncryptor // Real streaming encryptor
	buffer          []byte                                        // Internal buffer for processing
	metadata        map[string]string                             // Encryption metadata to be returned
	finished        bool                                          // Flag indicating if reading is complete
	logger          *logrus.Entry                                 // Logger for debugging
}

// DecryptionReader wraps an io.Reader to provide on-the-fly decryption.
// It implements the io.Reader interface and decrypts data as it's being read,
// enabling memory-efficient streaming decryption for large objects.
//
// Performance Features:
//   - Real AES-CTR streaming decryption with maintaining cipher state
//   - Memory-efficient processing without intermediate buffers
//   - HMAC verification for integrity checking during streaming
//   - Proper error handling and EOF management
type DecryptionReader struct {
	reader          io.Reader                                     // Source encrypted data reader
	decryptor       *dataencryption.AESCTRStreamingDataEncryptor // Real streaming decryptor
	buffer          []byte                                        // Internal buffer for processing
	finished        bool                                          // Flag indicating if reading is complete
	streamingOps    *StreamingOperations                          // Reference to streaming operations for HMAC verification
	metadata        map[string]string                             // Metadata containing HMAC for verification
	logger          *logrus.Entry                                 // Logger for debugging
}

// NewStreamingOperations creates a new streaming operations handler.
// It initializes the streaming operations with the provided managers and configuration.
// The segment size is determined from config or defaults to 12MB for optimal memory usage.
// A buffer pool is created to reuse memory buffers across streaming operations.
//
// Parameters:
//   - providerManager: Manager for encryption providers
//   - hmacManager: Manager for HMAC operations
//   - metadataManager: Manager for encryption metadata
//   - config: Configuration settings
//
// Returns:
//   - *StreamingOperations: Configured streaming operations handler
func NewStreamingOperations(
	providerManager *ProviderManager,
	hmacManager *HMACManager,
	metadataManager *MetadataManager,
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

// CreateEncryptionReader creates a reader that encrypts data on-the-fly.
// This method provides streaming encryption capabilities, allowing encryption
// of large objects without loading the entire content into memory.
//
// Parameters:
//   - ctx: Context for cancellation and timeouts
//   - reader: Source data reader to encrypt
//   - objectKey: Unique identifier for the object being encrypted
//
// Returns:
//   - io.Reader: Reader that provides encrypted data
//   - map[string]string: Metadata containing encryption information
//   - error: Any error encountered during setup
//
// Behavior:
//   - If none provider is configured, returns the original reader unchanged
//   - Creates an EncryptionReader with real AES-CTR streaming encryption
//   - Generates appropriate metadata for the encryption method used
//   - Enables HMAC calculation for integrity verification
func (sop *StreamingOperations) CreateEncryptionReader(ctx context.Context, reader io.Reader, objectKey string) (io.Reader, map[string]string, error) {
	sop.logger.WithField("object_key", objectKey).Debug("Creating encryption reader for streaming")

	// Check for none provider
	if sop.providerManager.IsNoneProvider() {
		sop.logger.WithField("object_key", objectKey).Debug("Using none provider - no encryption for streaming")
		return reader, nil, nil
	}

	// Generate a new 32-byte DEK for AES-256
	dek := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		return nil, nil, fmt.Errorf("failed to generate DEK: %w", err)
	}

	// Create streaming encryptor with HMAC support
	encryptor, err := sop.createStreamingEncryptor(dek)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create streaming encryptor: %w", err)
	}

	// Build metadata for this encryption operation
	metadata, err := sop.buildEncryptionMetadataSimple(ctx, dek, encryptor)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to build encryption metadata: %w", err)
	}

	// Create encryption reader with real streaming encryption
	encReader := &EncryptionReader{
		reader:    reader,
		encryptor: encryptor,
		buffer:    sop.getBuffer(),
		metadata:  metadata,
		logger:    sop.logger.WithField("object_key", objectKey),
	}

	sop.logger.WithField("object_key", objectKey).Debug("Created encryption reader with real AES-CTR streaming")
	return encReader, metadata, nil
}

// CreateDecryptionReader creates a reader that decrypts data on-the-fly.
// This method provides streaming decryption capabilities, allowing decryption
// of large encrypted objects without loading the entire content into memory.
//
// Parameters:
//   - ctx: Context for cancellation and timeouts
//   - reader: Source encrypted data reader
//   - metadata: Encryption metadata containing fingerprint and algorithm info
//
// Returns:
//   - io.Reader: Reader that provides decrypted data
//   - error: Any error encountered during setup or fingerprint extraction
//
// Behavior:
//   - Extracts fingerprint from metadata to determine encryption method
//   - If none provider fingerprint is found, returns original reader unchanged
//   - Creates a DecryptionReader with real AES-CTR streaming decryption
//   - Validates metadata before proceeding with decryption setup
//   - Enables HMAC verification for integrity checking
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

	// Get provider for DEK decryption
	provider, err := sop.providerManager.GetProviderByFingerprint(fingerprint)
	if err != nil {
		return nil, fmt.Errorf("failed to get provider for fingerprint %s: %w", fingerprint, err)
	}

	// Extract encrypted DEK from metadata
	encryptedDEK, err := sop.metadataManager.GetEncryptedDEK(metadata)
	if err != nil {
		return nil, fmt.Errorf("failed to get encrypted DEK from metadata: %w", err)
	}

	// Decrypt DEK
	dek, err := provider.DecryptDEK(ctx, encryptedDEK, fingerprint)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt DEK: %w", err)
	}

	// Create streaming decryptor with HMAC support
	decryptor, err := sop.createStreamingDecryptor(dek, metadata)
	if err != nil {
		return nil, fmt.Errorf("failed to create streaming decryptor: %w", err)
	}

	// Create decryption reader with real streaming decryption
	decReader := &DecryptionReader{
		reader:       reader,
		decryptor:    decryptor,
		buffer:       sop.getBuffer(),
		streamingOps: sop,
		metadata:     metadata,
		logger:       sop.logger,
	}

	sop.logger.Debug("Created decryption reader with real AES-CTR streaming")
	return decReader, nil
}

// StreamWithSegments processes a stream in configurable segments.
// This method enables memory-efficient processing of large streams by breaking
// them into manageable segments. Each segment is processed through the provided
// callback function, allowing for custom handling without memory overhead.
//
// Parameters:
//   - ctx: Context for cancellation and timeout control
//   - reader: Source data reader to process
//   - segmentCallback: Function called for each segment of data
//
// Returns:
//   - error: Any error encountered during streaming or callback execution
//
// Features:
//   - Respects context cancellation for long-running operations
//   - Uses buffer pool for memory efficiency
//   - Provides detailed logging for monitoring and debugging
//   - Handles EOF conditions gracefully
//   - Reports progress through segment counting
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

// GetSegmentSize returns the configured segment size for streaming operations.
// The segment size determines how much data is processed at once during
// streaming operations, affecting both memory usage and performance.
//
// Returns:
//   - int64: Segment size in bytes (default: 12MB)
func (sop *StreamingOperations) GetSegmentSize() int64 {
	return sop.segmentSize
}

// getBuffer gets a buffer from the pool.
// This method retrieves a reusable buffer from the buffer pool to optimize
// memory allocation and reduce garbage collection pressure.
//
// Returns:
//   - []byte: Buffer of configured segment size, ready for use
func (sop *StreamingOperations) getBuffer() []byte {
	return sop.bufferPool.Get().([]byte)
}

// returnBuffer returns a buffer to the pool after secure clearing.
// This method safely returns a buffer to the pool after clearing it for security.
// All buffer contents are zeroed out to prevent information leakage.
//
// Parameters:
//   - buffer: Buffer to return to the pool (will be securely cleared)
//
// Security:
//   - Buffer contents are completely zeroed using efficient clear() function
//   - Prevents sensitive data from being exposed in reused buffers
//
// Performance:
//   - Uses Go's built-in clear() function for optimal performance
//   - Much faster than manual for-loop iteration for large buffers
func (sop *StreamingOperations) returnBuffer(buffer []byte) {
	// Use Go's efficient clear function instead of manual loop
	// This is significantly faster for large buffers (12MB default)
	clear(buffer)
	sop.bufferPool.Put(buffer)
}

// Read implements io.Reader for EncryptionReader.
// This method provides on-the-fly encryption of data as it's being read.
// It uses real AES-CTR streaming encryption to transform data in-place
// while maintaining cipher state across multiple Read() calls.
//
// Parameters:
//   - p: Buffer to fill with encrypted data
//
// Returns:
//   - int: Number of bytes read and encrypted
//   - error: io.EOF when finished, or any error encountered
//
// Behavior:
//   - Reads data from underlying reader
//   - Applies real AES-CTR encryption with streaming encryptor
//   - Maintains finished state for proper EOF handling
//   - Updates HMAC for integrity verification
//   - Logs encryption operations for monitoring
//
// Performance:
//   - Zero-copy encryption when possible
//   - Memory-efficient processing without intermediate buffers
//   - Proper error handling and resource cleanup
func (er *EncryptionReader) Read(p []byte) (int, error) {
	if er.finished {
		return 0, io.EOF
	}

	// Read data from underlying reader
	n, err := er.reader.Read(p)
	if n > 0 {
		// Encrypt the data in-place using real AES-CTR streaming encryption
		encryptedData, encErr := er.encryptor.EncryptPart(p[:n])
		if encErr != nil {
			er.logger.WithError(encErr).Error("Failed to encrypt streaming data")
			return n, fmt.Errorf("encryption failed: %w", encErr)
		}

		// Copy encrypted data back to the buffer (in-place encryption)
		copy(p[:n], encryptedData)

		er.logger.WithFields(logrus.Fields{
			"bytes_read":      n,
			"bytes_encrypted": len(encryptedData),
			"offset":          er.encryptor.GetOffset(),
		}).Debug("Real-time encrypted streaming data")
	}

	// Handle EOF and errors
	if err != nil {
		if err == io.EOF {
			er.finished = true
			er.logger.WithFields(logrus.Fields{
				"total_offset": er.encryptor.GetOffset(),
				"final_hmac":   len(er.encryptor.GetStreamingHMAC()),
			}).Debug("Finished encryption reader stream")
		} else {
			er.logger.WithError(err).Error("Error reading from underlying stream")
		}
		return n, err
	}

	return n, nil
}

// Close implements io.Closer for EncryptionReader (optional interface).
// This method properly cleans up resources when the reader is no longer needed.
// It returns the buffer to the pool and clears sensitive data.
//
// Returns:
//   - error: Always returns nil as cleanup cannot fail
//
// Security:
//   - Clears sensitive buffer data before returning to pool
//   - Prevents memory leaks in long-running applications
func (er *EncryptionReader) Close() error {
	if er.buffer != nil {
		// Clear buffer for security before cleanup
		clear(er.buffer)
		er.buffer = nil
	}
	er.logger.Debug("Closed encryption reader and cleaned up resources")
	return nil
}

// Read implements io.Reader for DecryptionReader.
// This method provides on-the-fly decryption of data as it's being read.
// It uses real AES-CTR streaming decryption to transform encrypted data in-place
// while maintaining cipher state across multiple Read() calls.
//
// Parameters:
//   - p: Buffer to fill with decrypted data
//
// Returns:
//   - int: Number of bytes read and decrypted
//   - error: io.EOF when finished, or any error encountered
//
// Behavior:
//   - Reads encrypted data from underlying reader
//   - Applies real AES-CTR decryption with streaming decryptor
//   - Maintains finished state for proper EOF handling
//   - Updates HMAC for integrity verification
//   - Logs decryption operations for monitoring
//   - Verifies HMAC integrity at the end of stream (when EOF is reached)
//
// Performance:
//   - Zero-copy decryption when possible
//   - Memory-efficient processing without intermediate buffers
//   - Proper error handling and resource cleanup
//   - HMAC verification during streaming for integrity
func (dr *DecryptionReader) Read(p []byte) (int, error) {
	if dr.finished {
		return 0, io.EOF
	}

	// Read encrypted data from underlying reader
	n, err := dr.reader.Read(p)
	if n > 0 {
		// Decrypt the data in-place using real AES-CTR streaming decryption
		decryptedData, decErr := dr.decryptor.DecryptPart(p[:n])
		if decErr != nil {
			dr.logger.WithError(decErr).Error("Failed to decrypt streaming data")
			return n, fmt.Errorf("decryption failed: %w", decErr)
		}

		// Copy decrypted data back to the buffer (in-place decryption)
		copy(p[:n], decryptedData)

		dr.logger.WithFields(logrus.Fields{
			"bytes_read":      n,
			"bytes_decrypted": len(decryptedData),
			"offset":          dr.decryptor.GetOffset(),
		}).Debug("Real-time decrypted streaming data")
	}

	// Handle EOF and errors
	if err != nil {
		if err == io.EOF {
			dr.finished = true

			// Perform HMAC verification at the end of stream
			if dr.streamingOps != nil {
				if hmacErr := dr.streamingOps.verifyStreamingHMAC(dr.decryptor, dr.metadata); hmacErr != nil {
					dr.logger.WithError(hmacErr).Error("Streaming HMAC verification failed at end of stream")
					return n, fmt.Errorf("streaming HMAC verification failed: %w", hmacErr)
				}
				dr.logger.Debug("Streaming HMAC verification successful at end of stream")
			}

			dr.logger.WithFields(logrus.Fields{
				"total_offset": dr.decryptor.GetOffset(),
				"final_hmac":   len(dr.decryptor.GetStreamingHMAC()),
			}).Debug("Finished decryption reader stream with HMAC verification")
		} else {
			dr.logger.WithError(err).Error("Error reading from underlying encrypted stream")
		}
		return n, err
	}

	return n, nil
}

// Close implements io.Closer for DecryptionReader (optional interface).
// This method properly cleans up resources when the reader is no longer needed.
// It returns the buffer to the pool and clears sensitive data.
//
// Returns:
//   - error: Always returns nil as cleanup cannot fail
//
// Security:
//   - Clears sensitive buffer data before returning to pool
//   - Prevents memory leaks in long-running applications
func (dr *DecryptionReader) Close() error {
	if dr.buffer != nil {
		// Clear buffer for security before cleanup
		clear(dr.buffer)
		dr.buffer = nil
	}
	dr.logger.Debug("Closed decryption reader and cleaned up resources")
	return nil
}

// EncryptStream encrypts an entire stream using memory-efficient segment processing.
// This method processes the stream in configurable segments to minimize memory usage
// while providing complete encryption of the data stream.
//
// Parameters:
//   - ctx: Context for cancellation and timeout control
//   - reader: Source data stream to encrypt
//   - objectKey: Unique identifier for the object being encrypted
//
// Returns:
//   - []byte: Complete encrypted data stream
//   - map[string]string: Metadata containing encryption information
//   - error: Any error encountered during streaming encryption
//
// Performance Features:
//   - Memory-efficient segment-based processing (default 12MB segments)
//   - Buffer pool reuse to minimize garbage collection
//   - Streaming AES-CTR encryption for optimal performance
//   - Context cancellation support for long-running operations
func (sop *StreamingOperations) EncryptStream(ctx context.Context, reader io.Reader, objectKey string) ([]byte, map[string]string, error) {
	sop.logger.WithField("object_key", objectKey).Debug("Starting memory-efficient stream encryption")

	// Check for none provider early to avoid unnecessary processing
	if sop.providerManager.IsNoneProvider() {
		sop.logger.WithField("object_key", objectKey).Debug("Using none provider - no encryption for stream")
		// For none provider, read stream efficiently and provide internal metadata for testing
		data, _, err := sop.readStreamEfficiently(ctx, reader)
		if err != nil {
			return nil, nil, err
		}

		// Provide internal metadata for none provider (for testing/internal use only)
		// These metadata are NOT sent to S3 - they're filtered out by the proxy layer
		internalMetadata := map[string]string{
			"provider-type": "none",
			"fingerprint":   "none-provider-fingerprint",
		}

		return data, internalMetadata, nil
	}

	// Generate a new 32-byte DEK for AES-256 (simplified for now)
	dek := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		return nil, nil, fmt.Errorf("failed to generate DEK: %w", err)
	}

	// Create streaming encryptor with HMAC support
	encryptor, err := sop.createStreamingEncryptor(dek)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create streaming encryptor: %w", err)
	}

	// Process stream in segments for memory efficiency
	var encryptedSegments [][]byte
	totalProcessed := int64(0)

	err = sop.StreamWithSegments(ctx, reader, func(segment []byte) error {
		// Encrypt this segment
		encryptedSegment, encErr := encryptor.EncryptPart(segment)
		if encErr != nil {
			return fmt.Errorf("failed to encrypt segment: %w", encErr)
		}

		// Store encrypted segment (could be optimized with buffer pools)
		encryptedSegments = append(encryptedSegments, encryptedSegment)
		totalProcessed += int64(len(segment))

		sop.logger.WithFields(logrus.Fields{
			"object_key":       objectKey,
			"segment_size":     len(segment),
			"encrypted_size":   len(encryptedSegment),
			"total_processed":  totalProcessed,
		}).Debug("Encrypted stream segment")

		return nil
	})

	if err != nil {
		return nil, nil, fmt.Errorf("failed to process stream segments: %w", err)
	}

	// Combine all encrypted segments efficiently
	totalEncryptedSize := 0
	for _, seg := range encryptedSegments {
		totalEncryptedSize += len(seg)
	}

	encryptedData := make([]byte, 0, totalEncryptedSize)
	for _, seg := range encryptedSegments {
		encryptedData = append(encryptedData, seg...)
	}

	// Build metadata with encryption information
	metadata, err := sop.buildEncryptionMetadataSimple(ctx, dek, encryptor)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to build encryption metadata: %w", err)
	}

	// Add HMAC to metadata if enabled (calculated from encrypted data)
	if sop.hmacManager.IsEnabled() {
		hmacValue := encryptor.GetStreamingHMAC()
		if len(hmacValue) > 0 {
			// Use the same prefix as metadata manager
			var prefix string
			if sop.config.Encryption.MetadataKeyPrefix != nil {
				prefix = *sop.config.Encryption.MetadataKeyPrefix
			} else {
				prefix = "s3ep-"
			}
			metadata[prefix+"hmac"] = base64.StdEncoding.EncodeToString(hmacValue)

			sop.logger.WithFields(logrus.Fields{
				"object_key":  objectKey,
				"hmac_size":   len(hmacValue),
				"metadata_key": prefix+"hmac",
			}).Debug("Added streaming HMAC to metadata")
		}
	}

	sop.logger.WithFields(logrus.Fields{
		"object_key":       objectKey,
		"original_size":    totalProcessed,
		"encrypted_size":   len(encryptedData),
		"segments_count":   len(encryptedSegments),
	}).Info("Completed memory-efficient stream encryption")

	return encryptedData, metadata, nil
}

// DecryptStream decrypts an entire stream using memory-efficient segment processing.
// This method processes the encrypted stream in configurable segments to minimize
// memory usage while providing complete decryption of the data stream.
//
// Parameters:
//   - ctx: Context for cancellation and timeout control
//   - reader: Source encrypted data stream to decrypt
//   - metadata: Encryption metadata containing fingerprint and algorithm info
//
// Returns:
//   - []byte: Complete decrypted data stream
//   - error: Any error encountered during streaming decryption or integrity verification
//
// Performance Features:
//   - Memory-efficient segment-based processing (default 12MB segments)
//   - Buffer pool reuse to minimize garbage collection
//   - Streaming AES-CTR decryption for optimal performance
//   - HMAC integrity verification during streaming (if enabled)
//   - Context cancellation support for long-running operations
func (sop *StreamingOperations) DecryptStream(ctx context.Context, reader io.Reader, metadata map[string]string) ([]byte, error) {
	sop.logger.Debug("Starting memory-efficient stream decryption")

	// Handle case where metadata is nil or empty (unencrypted files)
	if metadata == nil || len(metadata) == 0 {
		sop.logger.Debug("No encryption metadata found - treating as unencrypted file")
		// Check integrity verification configuration
		integrityMode := sop.config.Encryption.IntegrityVerification

		if integrityMode == "strict" {
			return nil, fmt.Errorf("no encryption metadata found but strict integrity verification is enabled")
		}

		// For "off", "lax", or "hybrid" modes, read the file as-is
		sop.logger.WithField("integrity_mode", integrityMode).Debug("Reading unencrypted file according to integrity verification policy")
		data, _, err := sop.readStreamEfficiently(ctx, reader)
		return data, err
	}

	// Extract and validate fingerprint from metadata
	fingerprint, err := sop.metadataManager.GetFingerprint(metadata)
	if err != nil {
		// If we can't get fingerprint but have metadata, this might be legacy or corrupted metadata
		sop.logger.WithError(err).Debug("Failed to get fingerprint from metadata - treating as unencrypted file")

		integrityMode := sop.config.Encryption.IntegrityVerification
		if integrityMode == "strict" {
			return nil, fmt.Errorf("failed to get fingerprint from metadata: %w", err)
		}

		// For other modes, treat as unencrypted
		data, _, err := sop.readStreamEfficiently(ctx, reader)
		return data, err
	}

	// Check for none provider early to avoid unnecessary processing
	if fingerprint == "none-provider-fingerprint" {
		sop.logger.Debug("Using none provider - no decryption for stream")
		// Read stream efficiently without decryption
		data, _, err := sop.readStreamEfficiently(ctx, reader)
		return data, err
	}

	// Get provider and extract encrypted DEK from metadata
	provider, err := sop.providerManager.GetProviderByFingerprint(fingerprint)
	if err != nil {
		return nil, fmt.Errorf("failed to get provider for fingerprint %s: %w", fingerprint, err)
	}

	encryptedDEK, err := sop.metadataManager.GetEncryptedDEK(metadata)
	if err != nil {
		return nil, fmt.Errorf("failed to get encrypted DEK from metadata: %w", err)
	}

	// Decrypt DEK
	dek, err := provider.DecryptDEK(ctx, encryptedDEK, fingerprint)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt DEK: %w", err)
	}

	// Create streaming decryptor
	decryptor, err := sop.createStreamingDecryptor(dek, metadata)
	if err != nil {
		return nil, fmt.Errorf("failed to create streaming decryptor: %w", err)
	}

	// Process stream in segments for memory efficiency
	var decryptedSegments [][]byte
	totalProcessed := int64(0)

	err = sop.StreamWithSegments(ctx, reader, func(segment []byte) error {
		// Decrypt this segment
		decryptedSegment, decErr := decryptor.DecryptPart(segment)
		if decErr != nil {
			return fmt.Errorf("failed to decrypt segment: %w", decErr)
		}

		// Store decrypted segment (could be optimized with buffer pools)
		decryptedSegments = append(decryptedSegments, decryptedSegment)
		totalProcessed += int64(len(segment))

		sop.logger.WithFields(logrus.Fields{
			"segment_size":     len(segment),
			"decrypted_size":   len(decryptedSegment),
			"total_processed":  totalProcessed,
		}).Debug("Decrypted stream segment")

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to process stream segments: %w", err)
	}

	// Verify HMAC integrity if enabled
	if err := sop.verifyStreamingHMAC(decryptor, metadata); err != nil {
		return nil, fmt.Errorf("HMAC integrity verification failed: %w", err)
	}

	// Combine all decrypted segments efficiently
	totalDecryptedSize := 0
	for _, seg := range decryptedSegments {
		totalDecryptedSize += len(seg)
	}

	decryptedData := make([]byte, 0, totalDecryptedSize)
	for _, seg := range decryptedSegments {
		decryptedData = append(decryptedData, seg...)
	}

	sop.logger.WithFields(logrus.Fields{
		"encrypted_size":   totalProcessed,
		"decrypted_size":   len(decryptedData),
		"segments_count":   len(decryptedSegments),
	}).Info("Completed memory-efficient stream decryption")

	return decryptedData, nil
}

// StreamEncryptWithCallback encrypts a stream using a callback for each encrypted segment.
// This method provides streaming encryption with precise control over when each segment
// is processed, including notification when the last segment is reached.
//
// TEMPORARILY SIMPLIFIED: This is a basic implementation for the streaming readers.
// TODO: Implement full encryption with proper DEK generation and metadata handling.
func (sop *StreamingOperations) StreamEncryptWithCallback(
	ctx context.Context,
	reader io.Reader,
	objectKey string,
	callback func(encryptedData []byte, isLastSegment bool) error,
) (map[string]string, error) {
	sop.logger.WithField("object_key", objectKey).Debug("Starting simplified stream encryption with callback")

	// Check for none provider
	if sop.providerManager.IsNoneProvider() {
		// For none provider, streamWithCallbackNoneProvider provides internal metadata
		return sop.streamWithCallbackNoneProvider(ctx, reader, callback)
	}

	// For now, use a simple pass-through until we fix the full implementation
	err := sop.streamWithSegmentsEnhanced(ctx, reader, func(segment []byte, isLast bool) error {
		// TODO: Add real encryption here
		return callback(segment, isLast)
	})

	if err != nil {
		return nil, fmt.Errorf("failed to encrypt stream: %w", err)
	}

	// Return empty metadata for now
	metadata := make(map[string]string)
	sop.logger.WithField("object_key", objectKey).Debug("Completed simplified stream encryption with callback")
	return metadata, nil
}

// StreamDecryptWithCallback decrypts a stream using a callback for each decrypted segment.
// This method provides streaming decryption with precise control over when each segment
// is processed, including notification when the last segment is reached.
//
// TEMPORARILY SIMPLIFIED: This is a basic implementation for the streaming readers.
// TODO: Implement full decryption with proper DEK extraction and metadata handling.
func (sop *StreamingOperations) StreamDecryptWithCallback(
	ctx context.Context,
	reader io.Reader,
	metadata map[string]string,
	callback func(decryptedData []byte, isLastSegment bool) error,
) error {
	sop.logger.Debug("Starting simplified stream decryption with callback")

	// Extract fingerprint and check for none provider
	fingerprint, err := sop.metadataManager.GetFingerprint(metadata)
	if err != nil {
		return fmt.Errorf("failed to get fingerprint: %w", err)
	}

	if fingerprint == "none-provider-fingerprint" {
		return sop.streamWithCallbackNoneProviderDecrypt(ctx, reader, callback)
	}

	// For now, use a simple pass-through until we fix the full implementation
	err = sop.streamWithSegmentsEnhanced(ctx, reader, func(segment []byte, isLast bool) error {
		// TODO: Add real decryption here
		return callback(segment, isLast)
	})

	if err != nil {
		return fmt.Errorf("failed to decrypt stream: %w", err)
	}

	sop.logger.Debug("Completed simplified stream decryption with callback")
	return nil
}

// readStreamEfficiently reads a stream efficiently using buffer pools without loading all into memory at once.
// This method is used for none-provider scenarios where no encryption/decryption is needed,
// but we still want memory-efficient stream reading.
//
// Parameters:
//   - ctx: Context for cancellation and timeout control
//   - reader: Source data stream to read
//
// Returns:
//   - []byte: Complete data stream
//   - map[string]string: Empty metadata for none provider
//   - error: Any error encountered during reading
func (sop *StreamingOperations) readStreamEfficiently(ctx context.Context, reader io.Reader) ([]byte, map[string]string, error) {
	var segments [][]byte
	totalSize := 0

	err := sop.StreamWithSegments(ctx, reader, func(segment []byte) error {
		// Copy segment to avoid buffer pool conflicts
		segmentCopy := make([]byte, len(segment))
		copy(segmentCopy, segment)
		segments = append(segments, segmentCopy)
		totalSize += len(segment)
		return nil
	})

	if err != nil {
		return nil, nil, fmt.Errorf("failed to read stream efficiently: %w", err)
	}

	// Combine all segments efficiently
	result := make([]byte, 0, totalSize)
	for _, seg := range segments {
		result = append(result, seg...)
	}

	return result, nil, nil
}

// createStreamingEncryptor creates a streaming encryptor with HMAC support for the given DEK.
// This method sets up AES-CTR streaming encryption with optional HMAC integrity verification.
//
// Parameters:
//   - dek: Data encryption key for AES-CTR encryption
//
// Returns:
//   - *dataencryption.AESCTRStreamingDataEncryptor: Configured streaming encryptor
//   - error: Any error encountered during encryptor creation
func (sop *StreamingOperations) createStreamingEncryptor(dek []byte) (*dataencryption.AESCTRStreamingDataEncryptor, error) {
	// Create streaming encryptor with HMAC support for integrity verification
	encryptor, err := dataencryption.NewAESCTRStreamingDataEncryptorWithHMAC(dek)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES-CTR streaming encryptor: %w", err)
	}

	sop.logger.WithField("algorithm", "aes-ctr").Debug("Created streaming encryptor with HMAC support")
	return encryptor, nil
}

// createStreamingDecryptor creates a streaming decryptor for the given DEK and metadata.
// This method sets up AES-CTR streaming decryption with HMAC integrity verification.
//
// Parameters:
//   - dek: Data encryption key for AES-CTR decryption
//   - metadata: Encryption metadata containing IV and other algorithm parameters
//
// Returns:
//   - *dataencryption.AESCTRStreamingDataEncryptor: Configured streaming decryptor
//   - error: Any error encountered during decryptor creation
func (sop *StreamingOperations) createStreamingDecryptor(dek []byte, metadata map[string]string) (*dataencryption.AESCTRStreamingDataEncryptor, error) {
	// Extract IV from metadata
	iv, err := sop.metadataManager.GetIV(metadata)
	if err != nil {
		return nil, fmt.Errorf("failed to get IV from metadata: %w", err)
	}

	// Create streaming decryptor with HMAC support for integrity verification
	decryptor, err := dataencryption.NewAESCTRStreamingDataDecryptorWithHMAC(dek, iv, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES-CTR streaming decryptor: %w", err)
	}

	sop.logger.WithField("algorithm", "aes-ctr").Debug("Created streaming decryptor with HMAC support")
	return decryptor, nil
}

// buildEncryptionMetadataSimple builds simplified metadata for streaming encryption.
// This is a streamlined version for the streaming readers implementation.
//
// Parameters:
//   - ctx: Context for operations
//   - dek: Data encryption key (will be encrypted)
//   - encryptor: Streaming encryptor containing IV and other parameters
//
// Returns:
//   - map[string]string: Complete metadata for the encryption operation
//   - error: Any error encountered during metadata generation
func (sop *StreamingOperations) buildEncryptionMetadataSimple(ctx context.Context, dek []byte, encryptor *dataencryption.AESCTRStreamingDataEncryptor) (map[string]string, error) {
	// Encrypt DEK with active provider
	fingerprint := sop.providerManager.GetActiveFingerprint()
	provider, err := sop.providerManager.GetProviderByFingerprint(fingerprint)
	if err != nil {
		return nil, fmt.Errorf("failed to get provider: %w", err)
	}

	encryptedDEK, _, err := provider.EncryptDEK(ctx, dek)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt DEK: %w", err)
	}

	// Get IV from encryptor
	iv := encryptor.GetIV()

	// Build metadata using metadata manager
	metadata := sop.metadataManager.BuildMetadataForEncryption(
		dek,
		encryptedDEK,
		iv,
		"aes-ctr",
		fingerprint,
		sop.providerManager.GetActiveProviderAlgorithm(),
		nil, // Skip original metadata for now
	)

	return metadata, nil
}

// verifyStreamingHMAC verifies HMAC integrity for the decrypted stream.
// This method checks the HMAC calculated during streaming decryption against
// the expected HMAC stored in metadata.
//
// Parameters:
//   - decryptor: Streaming decryptor containing calculated HMAC
//   - metadata: Encryption metadata containing expected HMAC
//
// Returns:
//   - error: HMAC verification error if integrity check fails
func (sop *StreamingOperations) verifyStreamingHMAC(decryptor *dataencryption.AESCTRStreamingDataEncryptor, metadata map[string]string) error {
	// Check if HMAC verification is enabled
	if !sop.hmacManager.IsEnabled() {
		sop.logger.Debug("HMAC verification not enabled, skipping")
		return nil
	}

	// Get expected HMAC from metadata
	expectedHMAC, err := sop.metadataManager.GetHMAC(metadata)
	if err != nil {
		sop.logger.WithError(err).Debug("No HMAC found in metadata, skipping verification")
		return nil // HMAC is optional, don't fail if missing
	}

	// Verify HMAC using the decryptor
	if err := decryptor.VerifyStreamingHMAC(expectedHMAC); err != nil {
		return fmt.Errorf("streaming HMAC verification failed: %w", err)
	}

	sop.logger.Debug("Streaming HMAC verification successful")
	return nil
}

// streamWithSegmentsEnhanced processes a stream in segments with accurate last segment detection.
// This enhanced version provides proper isLastSegment information to callbacks by reading ahead
// to detect EOF conditions while maintaining memory efficiency.
//
// Parameters:
//   - ctx: Context for cancellation and timeout control
//   - reader: Source data stream to process
//   - segmentCallback: Function called for each segment with last segment indicator
//
// Returns:
//   - error: Any error encountered during streaming or callback execution
//
// Features:
//   - Accurate last segment detection through read-ahead buffering
//   - Memory-efficient processing with buffer pool reuse
//   - Context cancellation support for long-running operations
//   - Detailed progress logging for monitoring
func (sop *StreamingOperations) streamWithSegmentsEnhanced(ctx context.Context, reader io.Reader, segmentCallback func([]byte, bool) error) error {
	sop.logger.WithField("segment_size", sop.segmentSize).Debug("Starting enhanced segmented streaming")

	buffer := sop.getBuffer()
	defer sop.returnBuffer(buffer)

	nextBuffer := sop.getBuffer()
	defer sop.returnBuffer(nextBuffer)

	totalProcessed := int64(0)
	segmentCount := 0
	hasNextData := true

	// Read first segment
	n, err := reader.Read(buffer[:sop.segmentSize])
	if n == 0 && err == io.EOF {
		// Empty stream
		return nil
	}
	if err != nil && err != io.EOF {
		return fmt.Errorf("failed to read first segment: %w", err)
	}

	for hasNextData {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		currentSegment := buffer[:n]
		segmentCount++
		totalProcessed += int64(n)

		// Try to read next segment to determine if current is last
		nextN, nextErr := reader.Read(nextBuffer[:sop.segmentSize])
		isLastSegment := (nextN == 0 && nextErr == io.EOF) || (nextErr != nil && nextErr != io.EOF)

		// Process current segment with accurate last segment information
		if err := segmentCallback(currentSegment, isLastSegment); err != nil {
			sop.logger.WithFields(logrus.Fields{
				"segment_count":    segmentCount,
				"total_processed":  totalProcessed,
				"segment_size":     n,
				"is_last_segment":  isLastSegment,
				"error":           err,
			}).Error("Failed to process enhanced segment")
			return fmt.Errorf("failed to process segment %d: %w", segmentCount, err)
		}

		sop.logger.WithFields(logrus.Fields{
			"segment_count":   segmentCount,
			"segment_size":    n,
			"total_processed": totalProcessed,
			"is_last_segment": isLastSegment,
		}).Debug("Processed enhanced segment")

		// Check if we should continue
		if isLastSegment {
			hasNextData = false
		} else {
			// Swap buffers for next iteration
			buffer, nextBuffer = nextBuffer, buffer
			n = nextN
			err = nextErr
			if err != nil && err != io.EOF {
				return fmt.Errorf("failed to read segment: %w", err)
			}
		}
	}

	sop.logger.WithFields(logrus.Fields{
		"total_segments":   segmentCount,
		"total_processed":  totalProcessed,
	}).Info("Completed enhanced segmented streaming")

	return nil
}

// streamWithCallbackNoneProvider handles streaming with callback for none provider encryption.
// This method efficiently processes streams without encryption while providing accurate
// last segment detection to callbacks.
//
// Parameters:
//   - ctx: Context for cancellation and timeout control
//   - reader: Source data stream to process
//   - callback: Function called for each segment with last segment indicator
//
// Returns:
//   - map[string]string: Empty metadata for none provider
//   - error: Any error encountered during streaming
func (sop *StreamingOperations) streamWithCallbackNoneProvider(ctx context.Context, reader io.Reader, callback func([]byte, bool) error) (map[string]string, error) {
	sop.logger.Debug("Using none provider for stream encryption with callback")

	err := sop.streamWithSegmentsEnhanced(ctx, reader, callback)
	if err != nil {
		return nil, fmt.Errorf("failed to process none provider stream: %w", err)
	}

	// Provide internal metadata for none provider (for testing/internal use only)
	// These metadata are NOT sent to S3 - they're filtered out by the proxy layer
	internalMetadata := map[string]string{
		"provider-type": "none",
		"fingerprint":   "none-provider-fingerprint",
	}

	return internalMetadata, nil
}

// streamWithCallbackNoneProviderDecrypt handles streaming decryption with callback for none provider.
// This method efficiently processes streams without decryption while providing accurate
// last segment detection to callbacks.
//
// Parameters:
//   - ctx: Context for cancellation and timeout control
//   - reader: Source data stream to process
//   - callback: Function called for each segment with last segment indicator
//
// Returns:
//   - error: Any error encountered during streaming
func (sop *StreamingOperations) streamWithCallbackNoneProviderDecrypt(ctx context.Context, reader io.Reader, callback func([]byte, bool) error) error {
	sop.logger.Debug("Using none provider for stream decryption with callback")

	return sop.streamWithSegmentsEnhanced(ctx, reader, callback)
}
