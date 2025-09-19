package orchestration

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"hash"
	"io"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/guided-traffic/s3-encryption-proxy/internal/config"
	"github.com/guided-traffic/s3-encryption-proxy/internal/validation"
	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption/dataencryption"
	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption/factory"
)


// MultipartSession represents an active multipart upload session
type MultipartSession struct {
	UploadID         string
	ObjectKey        string
	BucketName       string
	DEK              []byte
	IV               []byte
	KeyFingerprint   string
	PartETags        map[int]string
	HMACCalculator   hash.Hash
	NextPartNumber   int
	CreatedAt        time.Time

	// Additional fields for proxy handler compatibility
	ContentType      factory.ContentType
	Metadata         map[string]string
	IsCompleted      bool

	mutex            sync.RWMutex
}

// MultipartOperations handles encryption and decryption for multipart uploads
// with session-based state management
type MultipartOperations struct {
	sessions        map[string]*MultipartSession
	mutex           sync.RWMutex
	providerManager *ProviderManager
	hmacManager     *validation.HMACManager
	metadataManager *MetadataManager
	config          *config.Config
	logger          *logrus.Entry
}

// NewMultipartOperations creates a new multipart operations handler
func NewMultipartOperations(
	providerManager *ProviderManager,
	hmacManager *validation.HMACManager,
	metadataManager *MetadataManager,
	config *config.Config,
) *MultipartOperations {
	logger := logrus.WithField("component", "multipart_operations")

	mpo := &MultipartOperations{
		sessions:        make(map[string]*MultipartSession),
		providerManager: providerManager,
		hmacManager:     hmacManager,
		metadataManager: metadataManager,
		config:          config,
		logger:          logger,
	}

	logger.Info("Initialized multipart operations")
	return mpo
}

// InitiateSession creates a new multipart upload session with streaming HMAC support.
// This function sets up the foundational components for secure multipart uploads by:
// 1. Generating cryptographically secure DEK (Data Encryption Key) for AES-256-CTR
// 2. Creating random IV (Initialization Vector) for CTR mode encryption
// 3. Initializing HMAC calculator for streaming integrity verification
// 4. Setting up session state tracking for parts and metadata
// 5. Preparing session for concurrent part uploads with proper synchronization
//
// Streaming HMAC workflow initialization:
// - Creates HMAC calculator using HKDF-derived key from DEK
// - Calculator will be updated incrementally during ProcessPart() calls
// - HMAC calculation covers all parts in sequential order
// - Final HMAC will be computed in FinalizeSession() without additional data processing
//
// Security components:
// - DEK: 32-byte (256-bit) key for AES-256-CTR encryption
// - IV: 16-byte (128-bit) initialization vector for CTR mode
// - HMAC: SHA-256 based integrity verification using HKDF key derivation
// - Session state: Thread-safe tracking of upload progress and metadata
//
// Performance considerations:
// - Session creation is O(1) operation
// - HMAC calculator initialization is lightweight
// - Memory usage remains constant regardless of planned upload size
// - Thread-safe design supports concurrent part uploads
func (mpo *MultipartOperations) InitiateSession(ctx context.Context, uploadID, objectKey, bucketName string) (*MultipartSession, error) {
	mpo.logger.WithFields(logrus.Fields{
		"upload_id":   uploadID,
		"object_key":  objectKey,
		"bucket_name": bucketName,
	}).Debug("Initiating multipart upload session with streaming HMAC")

	mpo.mutex.Lock()
	defer mpo.mutex.Unlock()

	// Check if session already exists
	if _, exists := mpo.sessions[uploadID]; exists {
		return nil, fmt.Errorf("multipart upload %s already exists", uploadID)
	}

	// Check for none provider
	if mpo.providerManager.IsNoneProvider() {
		return mpo.createNoneProviderSession(uploadID, objectKey, bucketName)
	}

	// Generate DEK for this upload session
	dek := make([]byte, 32) // 256-bit key
	if _, err := rand.Read(dek); err != nil {
		mpo.logger.WithError(err).Error("Failed to generate DEK for multipart session")
		return nil, fmt.Errorf("failed to generate DEK: %w", err)
	}

	// Generate IV for AES-CTR
	iv := make([]byte, 16) // 128-bit IV
	if _, err := rand.Read(iv); err != nil {
		mpo.logger.WithError(err).Error("Failed to generate IV for multipart session")
		return nil, fmt.Errorf("failed to generate IV: %w", err)
	}

	// Create HMAC calculator if enabled
	var hmacCalculator hash.Hash
	if mpo.hmacManager.IsEnabled() {
		var err error
		hmacCalculator, err = mpo.hmacManager.CreateCalculator(dek)
		if err != nil {
			mpo.logger.WithError(err).Error("Failed to create HMAC calculator for multipart session")
			return nil, fmt.Errorf("failed to create HMAC calculator: %w", err)
		}
	}

	// Initialize metadata map with DEK algorithm for multipart uploads
	metadata := make(map[string]string)
	metadataPrefix := mpo.metadataManager.GetMetadataPrefix()
	metadata[metadataPrefix+"dek-algorithm"] = "aes-256-ctr"

	session := &MultipartSession{
		UploadID:         uploadID,
		ObjectKey:        objectKey,
		BucketName:       bucketName,
		DEK:              dek,
		IV:               iv,
		KeyFingerprint:   mpo.providerManager.GetActiveFingerprint(),
		PartETags:        make(map[int]string),
		HMACCalculator:   hmacCalculator,
		NextPartNumber:   1,
		CreatedAt:        time.Now(),
		ContentType:      factory.ContentTypeMultipart,
		Metadata:         metadata,
	}

	// DEBUG: Verify session fields are set correctly
	mpo.logger.WithFields(logrus.Fields{
		"DEBUG_VERIFICATION": "CONTENT_TYPE_AND_METADATA_SET",
		"content_type":       string(session.ContentType),
		"metadata_count":     len(session.Metadata),
		"metadata_content":   session.Metadata,
	}).Error("DEBUG: Session fields verification")

	mpo.sessions[uploadID] = session

	mpo.logger.WithFields(logrus.Fields{
		"upload_id":      uploadID,
		"object_key":     objectKey,
		"bucket_name":    bucketName,
		"key_fingerprint": session.KeyFingerprint,
		"hmac_enabled":   mpo.hmacManager.IsEnabled(),
	}).Debug("Successfully initiated multipart upload session")

	return session, nil
}

// ProcessPart encrypts a part and updates the session state with streaming HMAC calculation.
// This function provides memory-efficient processing by:
// 1. Using streaming HMAC calculation without loading data into memory
// 2. Processing data through encryption pipeline with minimal buffering
// 3. Tracking data size during streaming for part size verification
// 4. Updating HMAC calculator incrementally for each part in sequence
//
// Performance optimizations:
// - Uses streaming HMAC updates instead of io.ReadAll()
// - HMAC calculation happens during data processing
// - Memory usage remains constant regardless of part size
// - Supports parts from 5MB up to 5GB without memory concerns
func (mpo *MultipartOperations) ProcessPart(ctx context.Context, uploadID string, partNumber int, dataReader *bufio.Reader) (*EncryptionResult, error) {
	mpo.logger.WithFields(logrus.Fields{
		"upload_id":   uploadID,
		"part_number": partNumber,
	}).Debug("Processing multipart upload part with streaming HMAC")

	// Get session
	session, err := mpo.getSession(uploadID)
	if err != nil {
		return nil, err
	}

	session.mutex.Lock()
	defer session.mutex.Unlock()

	// Check for none provider
	if mpo.providerManager.IsNoneProvider() {
		return mpo.processNoneProviderPartStream(session, partNumber, dataReader)
	}

	// Calculate the CTR offset for this specific part based on part number
	// Part numbers start at 1, so (partNumber - 1) * partSize gives us the correct offset
	const standardPartSize = 5242880 // 5MB standard part size
	partOffset := uint64(partNumber-1) * standardPartSize

	// Create part-specific CTR encryptor at the correct offset for this part number
	// This ensures each part is encrypted at the correct position in the stream
	partCTREncryptor, err := dataencryption.NewAESCTRStreamingDataEncryptorWithIV(session.DEK, session.IV, partOffset)
	if err != nil {
		mpo.logger.WithError(err).Error("Failed to create part-specific CTR encryptor")
		return nil, fmt.Errorf("failed to create CTR encryptor for part %d: %w", partNumber, err)
	}

	mpo.logger.WithFields(logrus.Fields{
		"upload_id":     uploadID,
		"part_number":   partNumber,
		"part_offset":   partOffset,
	}).Debug("Created part-specific CTR encryptor at correct offset")

	// Create a streaming encryption reader that:
	// 1. Reads data from the input stream in chunks
	// 2. Updates HMAC calculator sequentially
	// 3. Encrypts data on-the-fly with CTR encryptor
	// 4. Returns encrypted data without buffering everything in memory
	encryptedReader := mpo.createStreamingEncryptionReader(dataReader, partCTREncryptor, session.HMACCalculator, partNumber)

	// Create minimal metadata (KEK encryption will be handled during finalization)
	metadata := make(map[string]string)

	result := &EncryptionResult{
		EncryptedData:  bufio.NewReader(encryptedReader), // Wrap the streaming reader in bufio.Reader for compatibility
		Metadata:       metadata,
		Algorithm:      "aes-ctr",
		KeyFingerprint: session.KeyFingerprint,
	}

	mpo.logger.WithFields(logrus.Fields{
		"upload_id":        uploadID,
		"part_number":      partNumber,
		"key_fingerprint":  session.KeyFingerprint,
		"hmac_enabled":     mpo.hmacManager.IsEnabled(),
	}).Debug("Successfully processed multipart upload part with streaming")

	return result, nil
}

// StorePartETag stores the ETag for a completed part
func (mpo *MultipartOperations) StorePartETag(uploadID string, partNumber int, etag string) error {
	session, err := mpo.getSession(uploadID)
	if err != nil {
		return err
	}

	session.mutex.Lock()
	defer session.mutex.Unlock()

	session.PartETags[partNumber] = etag

	mpo.logger.WithFields(logrus.Fields{
		"upload_id":   uploadID,
		"part_number": partNumber,
		"etag":        etag,
	}).Debug("Stored part ETag")

	return nil
}

// FinalizeSession completes the multipart upload and generates final metadata with HMAC validation.
// This function handles the critical final phase of multipart uploads by:
// 1. Encrypting the DEK (Data Encryption Key) for secure storage in metadata
// 2. Building comprehensive encryption metadata with all required fields
// 3. Finalizing streaming HMAC calculation from all processed parts
// 4. Adding HMAC to metadata for integrity verification during downloads
// 5. Cleaning up session state and preparing final metadata for S3 storage
//
// HMAC verification workflow:
// - Uses HMAC calculator that was updated during each ProcessPart() call
// - HMAC covers all parts in sequential order (part 1, part 2, ...)
// - Final HMAC value is stored in metadata as base64-encoded string
// - During downloads, the same sequential HMAC calculation verifies data integrity
//
// Security considerations:
// - DEK is encrypted with active KEK provider before metadata storage
// - HMAC provides cryptographic integrity verification for entire object
// - Metadata includes all necessary information for decryption and verification
//
// Performance characteristics:
// - HMAC finalization is O(1) operation regardless of object size
// - No additional data processing - HMAC was calculated during upload streaming
// - Memory usage remains constant during finalization
func (mpo *MultipartOperations) FinalizeSession(ctx context.Context, uploadID string) (map[string]string, error) {
	mpo.logger.WithField("upload_id", uploadID).Debug("Finalizing multipart upload session with HMAC")

	session, err := mpo.getSession(uploadID)
	if err != nil {
		return nil, err
	}

	session.mutex.Lock()
	defer session.mutex.Unlock()

	// Check for none provider
	if mpo.providerManager.IsNoneProvider() {
		return nil, nil // No metadata for none provider
	}

	// Encrypt the DEK for final metadata
	encryptedDEK, err := mpo.providerManager.EncryptDEK(session.DEK, session.ObjectKey)
	if err != nil {
		mpo.logger.WithError(err).Error("Failed to encrypt DEK for final metadata")
		return nil, fmt.Errorf("failed to encrypt DEK: %w", err)
	}

	// Build final metadata
	metadata := mpo.metadataManager.BuildMetadataForEncryption(
		session.DEK,
		encryptedDEK,
		session.IV,
		"aes-ctr",
		session.KeyFingerprint,
		mpo.providerManager.GetActiveProviderAlgorithm(),
		nil,
	)

	mpo.logger.WithFields(logrus.Fields{
		"upload_id":    uploadID,
		"total_parts":  len(session.PartETags),
		"part_size":    5242880, // 5MB standard part size
	}).Debug("Finalizing multipart upload with metadata")

	// Finalize and add streaming HMAC if enabled
	// The HMAC calculator contains the cumulative hash of all parts processed in sequence
	if mpo.hmacManager.IsEnabled() && session.HMACCalculator != nil {
		finalHMAC := mpo.hmacManager.FinalizeCalculator(session.HMACCalculator)
		if len(finalHMAC) > 0 {
			mpo.metadataManager.SetHMAC(metadata, finalHMAC)

			mpo.logger.WithFields(logrus.Fields{
				"upload_id":   uploadID,
				"hmac_size":   len(finalHMAC),
				"total_parts": len(session.PartETags),
			}).Debug("Added final streaming HMAC to metadata")
		} else {
			mpo.logger.WithField("upload_id", uploadID).Warn("HMAC calculator returned empty result")
		}
	}

	mpo.logger.WithFields(logrus.Fields{
		"upload_id":        uploadID,
		"object_key":       session.ObjectKey,
		"total_parts":      len(session.PartETags),
		"metadata_keys":    len(metadata),
		"key_fingerprint":  session.KeyFingerprint,
		"hmac_enabled":     mpo.hmacManager.IsEnabled(),
	}).Info("Successfully finalized multipart upload session with streaming HMAC")

	return metadata, nil
}

// AbortSession cleans up a multipart upload session
func (mpo *MultipartOperations) AbortSession(ctx context.Context, uploadID string) error {
	mpo.logger.WithField("upload_id", uploadID).Debug("Aborting multipart upload session")

	mpo.mutex.Lock()
	defer mpo.mutex.Unlock()

	session, exists := mpo.sessions[uploadID]
	if !exists {
		mpo.logger.WithField("upload_id", uploadID).Warn("Multipart upload session not found for abort")
		return fmt.Errorf("multipart upload %s not found", uploadID)
	}

	// Clean up sensitive data
	if session.DEK != nil {
		mpo.hmacManager.ClearSensitiveData(session.DEK)
	}
	if session.IV != nil {
		mpo.hmacManager.ClearSensitiveData(session.IV)
	}

	delete(mpo.sessions, uploadID)

	mpo.logger.WithFields(logrus.Fields{
		"upload_id":   uploadID,
		"object_key":  session.ObjectKey,
		"parts_count": len(session.PartETags),
	}).Debug("Successfully aborted multipart upload session")

	return nil
}

// CleanupSession removes a multipart upload session without logging as "abort"
// This is used after successful completion to clean up resources
func (mpo *MultipartOperations) CleanupSession(uploadID string) error {
	mpo.mutex.Lock()
	defer mpo.mutex.Unlock()

	session, exists := mpo.sessions[uploadID]
	if !exists {
		mpo.logger.WithField("upload_id", uploadID).Debug("Multipart upload session not found for cleanup")
		return fmt.Errorf("multipart upload %s not found", uploadID)
	}

	// Clean up sensitive data
	if session.DEK != nil {
		mpo.hmacManager.ClearSensitiveData(session.DEK)
	}
	if session.IV != nil {
		mpo.hmacManager.ClearSensitiveData(session.IV)
	}

	delete(mpo.sessions, uploadID)

	mpo.logger.WithFields(logrus.Fields{
		"upload_id":   uploadID,
		"object_key":  session.ObjectKey,
		"parts_count": len(session.PartETags),
	}).Debug("Successfully cleaned up multipart upload session")

	return nil
}

// GetSession returns a multipart upload session (for external access)
func (mpo *MultipartOperations) GetSession(uploadID string) (*MultipartSession, error) {
	return mpo.getSession(uploadID)
}

// getSession returns a multipart upload session (internal use)
func (mpo *MultipartOperations) getSession(uploadID string) (*MultipartSession, error) {
	mpo.mutex.RLock()
	defer mpo.mutex.RUnlock()

	session, exists := mpo.sessions[uploadID]
	if !exists {
		return nil, fmt.Errorf("multipart upload %s not found", uploadID)
	}

	return session, nil
}

// createNoneProviderSession creates a minimal session for the none provider
func (mpo *MultipartOperations) createNoneProviderSession(uploadID, objectKey, bucketName string) (*MultipartSession, error) {
	session := &MultipartSession{
		UploadID:       uploadID,
		ObjectKey:      objectKey,
		BucketName:     bucketName,
		KeyFingerprint: "none-provider-fingerprint",
		PartETags:      make(map[int]string),
		NextPartNumber: 1,
		CreatedAt:      time.Now(),
		ContentType:    factory.ContentTypeMultipart,
		Metadata:       make(map[string]string),
	}

	// DEBUG: Verify session fields are set correctly
	mpo.logger.WithFields(logrus.Fields{
		"DEBUG_VERIFICATION": "NONE_PROVIDER_CONTENT_TYPE_SET",
		"content_type":       string(session.ContentType),
		"metadata_count":     len(session.Metadata),
	}).Error("DEBUG: None provider session fields verification")

	mpo.sessions[uploadID] = session

	mpo.logger.WithFields(logrus.Fields{
		"upload_id":   uploadID,
		"object_key":  objectKey,
		"bucket_name": bucketName,
	}).Debug("Created none provider multipart session")

	return session, nil
}

// processNoneProviderPart processes a part when using the none provider (pass-through)
func (mpo *MultipartOperations) processNoneProviderPart(session *MultipartSession, partNumber int, data []byte) (*EncryptionResult, error) {
	return &EncryptionResult{
		EncryptedData:  bufio.NewReader(bytes.NewReader(data)), // No encryption, but wrap in reader
		Metadata:       nil,                                    // No metadata for none provider
		Algorithm:      "none",
		KeyFingerprint: "none-provider-fingerprint",
	}, nil
}

// processNoneProviderPartStream processes a part when using the none provider (pass-through) with streaming
func (mpo *MultipartOperations) processNoneProviderPartStream(session *MultipartSession, partNumber int, dataReader *bufio.Reader) (*EncryptionResult, error) {
	// For none provider, pass data through unchanged - pure streaming, no buffering
	return &EncryptionResult{
		EncryptedData:  dataReader, // No encryption, pass reader through directly
		Metadata:       nil,        // No metadata for none provider
		Algorithm:      "none",
		KeyFingerprint: "none-provider-fingerprint",
	}, nil
}

// CleanupExpiredSessions removes sessions that have been idle for too long
func (mpo *MultipartOperations) CleanupExpiredSessions(maxAge time.Duration) int {
	mpo.mutex.Lock()
	defer mpo.mutex.Unlock()

	now := time.Now()
	expiredCount := 0

	for uploadID, session := range mpo.sessions {
		if now.Sub(session.CreatedAt) > maxAge {
			// Clean up sensitive data
			if session.DEK != nil {
				mpo.hmacManager.ClearSensitiveData(session.DEK)
			}
			if session.IV != nil {
				mpo.hmacManager.ClearSensitiveData(session.IV)
			}

			delete(mpo.sessions, uploadID)
			expiredCount++

			mpo.logger.WithFields(logrus.Fields{
				"upload_id":  uploadID,
				"object_key": session.ObjectKey,
				"age":        now.Sub(session.CreatedAt),
			}).Info("Cleaned up expired multipart upload session")
		}
	}

	if expiredCount > 0 {
		mpo.logger.WithFields(logrus.Fields{
			"expired_sessions": expiredCount,
			"remaining_sessions": len(mpo.sessions),
		}).Info("Completed multipart session cleanup")
	}

	return expiredCount
}

// createStreamingEncryptionReader creates a reader that streams data through encryption and HMAC calculation
// without loading the entire part into memory. This prevents OOM issues for large parts.
func (mpo *MultipartOperations) createStreamingEncryptionReader(
	dataReader *bufio.Reader,
	encryptor *dataencryption.AESCTRStreamingDataEncryptor,
	hmacCalculator hash.Hash,
	partNumber int,
) io.Reader {
	pr, pw := io.Pipe()

	go func() {
		defer pw.Close()

		buffer := make([]byte, 64*1024) // 64KB chunks for efficient streaming
		totalBytesProcessed := 0

		for {
			n, err := dataReader.Read(buffer)
			if n > 0 {
				chunk := buffer[:n]
				totalBytesProcessed += n

				// Update HMAC calculator with plaintext data (sequential, thread-safe within session lock)
				if mpo.hmacManager.IsEnabled() && hmacCalculator != nil {
					if _, hmacErr := hmacCalculator.Write(chunk); hmacErr != nil {
						mpo.logger.WithError(hmacErr).Error("Failed to update HMAC during streaming")
						pw.CloseWithError(fmt.Errorf("failed to update HMAC: %w", hmacErr))
						return
					}
				}

				// Encrypt chunk
				encryptedChunk, encErr := encryptor.EncryptPart(chunk)
				if encErr != nil {
					mpo.logger.WithError(encErr).Error("Failed to encrypt chunk during streaming")
					pw.CloseWithError(fmt.Errorf("failed to encrypt chunk: %w", encErr))
					return
				}

				// Write encrypted chunk to pipe
				if _, writeErr := pw.Write(encryptedChunk); writeErr != nil {
					mpo.logger.WithError(writeErr).Error("Failed to write encrypted chunk")
					pw.CloseWithError(writeErr)
					return
				}
			}

			if err == io.EOF {
				mpo.logger.WithFields(logrus.Fields{
					"part_number":    partNumber,
					"bytes_processed": totalBytesProcessed,
				}).Debug("Completed streaming encryption for part")
				break
			}

			if err != nil {
				mpo.logger.WithError(err).Error("Error reading during streaming encryption")
				pw.CloseWithError(err)
				return
			}
		}
	}()

	return pr
}

// GetSessionCount returns the number of active sessions
func (mpo *MultipartOperations) GetSessionCount() int {
	mpo.mutex.RLock()
	defer mpo.mutex.RUnlock()
	return len(mpo.sessions)
}
