package orchestration

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/guided-traffic/s3-encryption-proxy/internal/config"
	"github.com/guided-traffic/s3-encryption-proxy/internal/validation"
	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption/dataencryption"
	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption/factory"
)


// PartBuffer represents a part waiting to be processed in order
type PartBuffer struct {
	PartNumber int
	DataReader *bufio.Reader // Contains the buffered part data
	ResultChan chan *EncryptionResult
	ErrorChan  chan error
}

// MultipartSession represents an active multipart upload session
type MultipartSession struct {
	UploadID         string
	ObjectKey        string
	BucketName       string
	DEK              []byte
	IV               []byte
	KeyFingerprint   string
	PartETags        map[int]string
	HMACCalculator   *validation.HMACCalculator
	CreatedAt        time.Time

	// Additional fields for proxy handler compatibility
	ContentType      factory.ContentType
	Metadata         map[string]string
	IsCompleted      bool

	// Persistent CTR encryptor for streaming throughout the entire upload
	CTREncryptor     *dataencryption.AESCTRStatefulEncryptor

	// Ordered part processing
	ExpectedPartNumber int                    // Next part number we expect to process
	PendingParts       map[int]*PartBuffer   // Parts waiting to be processed in order
	OrderingMutex      sync.Mutex            // Separate mutex for ordering logic

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
// 1. Generating cryptographically secure DEK (Data Encryption Key) for aes-ctr
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
// - DEK: 32-byte (256-bit) key for aes-ctr encryption
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

	// Create persistent CTR encryptor for this session
	// This encryptor will be used for all parts, maintaining stream continuity
	// The encryptor will generate its own IV which we'll use for the session
	ctrEncryptor, err := dataencryption.NewAESCTRStatefulEncryptor(dek)
	if err != nil {
		mpo.logger.WithError(err).Error("Failed to create CTR encryptor for multipart session")
		return nil, fmt.Errorf("failed to create CTR encryptor: %w", err)
	}

	// Get the IV from the CTR encryptor for session storage
	iv := ctrEncryptor.GetIV()

	// Create HMAC calculator if enabled
	var hmacCalculator *validation.HMACCalculator
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
	metadata[metadataPrefix+"dek-algorithm"] = "aes-ctr"

	session := &MultipartSession{
		UploadID:           uploadID,
		ObjectKey:          objectKey,
		BucketName:         bucketName,
		DEK:                dek,
		IV:                 iv,
		KeyFingerprint:     mpo.providerManager.GetActiveFingerprint(),
		PartETags:          make(map[int]string),
		HMACCalculator:     hmacCalculator,
		CreatedAt:          time.Now(),
		ContentType:        factory.ContentTypeMultipart,
		Metadata:           metadata,
		CTREncryptor:       ctrEncryptor,
		ExpectedPartNumber: 1,
		PendingParts:       make(map[int]*PartBuffer),
	}

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

// ProcessPart encrypts a part using ordered streaming to ensure HMAC integrity.
// Parts may arrive out of order, but they are processed sequentially for proper HMAC calculation.
// This function provides memory-efficient processing by:
// 1. Buffering only parts that are waiting for their turn (not all parts)
// 2. Processing parts in correct sequence for HMAC calculation
// 3. Using streaming encryption with minimal memory footprint
// 4. Immediately releasing processed parts from memory
//
// Ordered streaming workflow:
// - If this is the next expected part: process immediately
// - If this part is ahead: buffer it and wait for earlier parts
// - When a part is processed: check if any buffered parts can now be processed
//
// Memory optimization:
// - Only stores parts waiting for their sequence turn
// - Processed parts are immediately removed from memory
// - No buffering of already processed data
func (mpo *MultipartOperations) ProcessPart(ctx context.Context, uploadID string, partNumber int, dataReader *bufio.Reader) (*EncryptionResult, error) {
	// Validate part number (S3 allows 1-10000)
	if partNumber < 1 || partNumber > 10000 {
		return nil, fmt.Errorf("invalid part number %d: must be between 1 and 10000", partNumber)
	}

	// Get session
	session, err := mpo.getSession(uploadID)
	if err != nil {
		return nil, err
	}

	// Check for none provider
	if mpo.providerManager.IsNoneProvider() {
		session.mutex.Lock()
		defer session.mutex.Unlock()
		return mpo.processNoneProviderPartStream(session, partNumber, dataReader)
	}

	// For ordered processing, we need to handle parts that may arrive out of sequence
	return mpo.processPartOrdered(session, partNumber, dataReader)
}

// processPartOrdered handles part processing with strict ordering for HMAC and CTR encryption integrity
func (mpo *MultipartOperations) processPartOrdered(session *MultipartSession, partNumber int, dataReader *bufio.Reader) (*EncryptionResult, error) {
	// Read all part data immediately to prevent blocking the reader
	var partData []byte
	buffer := make([]byte, 64*1024) // 64KB chunks
	totalBytes := 0

	for {
		n, err := dataReader.Read(buffer)
		if n > 0 {
			partData = append(partData, buffer[:n]...)
			totalBytes += n
		}

		if err == io.EOF {
			break
		}

		if err != nil {
			mpo.logger.WithError(err).Error("Error reading part data for ordered processing")
			return nil, fmt.Errorf("failed to read part data: %w", err)
		}
	}

	session.OrderingMutex.Lock()

	// Check if this is the part we're waiting for
	if partNumber == session.ExpectedPartNumber {
		// Process this part immediately
		session.OrderingMutex.Unlock()

		// Process the part data with proper ordering
		result, err := mpo.processPartDataInOrder(session, partNumber, partData)
		if err != nil {
			return nil, err
		}

		// After processing, check if we can process any buffered parts
		mpo.processBufferedPartsData(session)
		return result, nil
	} else {
		// This part is out of order, buffer it
		partBuffer := &PartBuffer{
			PartNumber: partNumber,
			DataReader: bufio.NewReader(bytes.NewReader(partData)), // Store the data
			ResultChan: make(chan *EncryptionResult, 1),
			ErrorChan:  make(chan error, 1),
		}

		session.PendingParts[partNumber] = partBuffer
		session.OrderingMutex.Unlock()

		mpo.logger.WithFields(logrus.Fields{
			"upload_id":         session.UploadID,
			"part_number":       partNumber,
			"expected_part":     session.ExpectedPartNumber,
			"buffered_parts":    len(session.PendingParts),
			"part_size_bytes":   totalBytes,
		}).Debug("Buffered out-of-order part for sequential processing")

		// Wait for this part to be processed in order
		select {
		case result := <-partBuffer.ResultChan:
			return result, nil
		case err := <-partBuffer.ErrorChan:
			return nil, err
			// Note: We don't use context timeout here as the proxy handles request timeouts
		}
	}
}

// processPartDataInOrder processes part data ensuring both HMAC and CTR encryption happen sequentially
func (mpo *MultipartOperations) processPartDataInOrder(session *MultipartSession, partNumber int, partData []byte) (*EncryptionResult, error) {
	session.mutex.Lock()
	defer session.mutex.Unlock()

	// Use the session's persistent CTR encryptor
	if session.CTREncryptor == nil {
		mpo.logger.WithError(fmt.Errorf("CTR encryptor not initialized")).Error("Session CTR encryptor is nil")
		return nil, fmt.Errorf("CTR encryptor not initialized for session %s", session.UploadID)
	}

	// Update HMAC calculator with plaintext data BEFORE encryption (in correct order)
	if mpo.hmacManager.IsEnabled() && session.HMACCalculator != nil {
		if _, hmacErr := session.HMACCalculator.Add(partData); hmacErr != nil {
			mpo.logger.WithError(hmacErr).Error("Failed to update HMAC during ordered processing")
			return nil, fmt.Errorf("failed to update HMAC: %w", hmacErr)
		}
	}

	// Encrypt the data with persistent CTR encryptor (maintains state across parts)
	encryptedData, err := session.CTREncryptor.EncryptPart(partData)
	if err != nil {
		mpo.logger.WithError(err).Error("Failed to encrypt part data in order")
		return nil, fmt.Errorf("failed to encrypt part: %w", err)
	}

	// Create minimal metadata (KEK encryption will be handled during finalization)
	metadata := make(map[string]string)

	result := &EncryptionResult{
		EncryptedData:  bufio.NewReader(bytes.NewReader(encryptedData)),
		Metadata:       metadata,
		Algorithm:      "aes-ctr",
		KeyFingerprint: session.KeyFingerprint,
	}

	mpo.logger.WithFields(logrus.Fields{
		"upload_id":        session.UploadID,
		"part_number":      partNumber,
		"bytes_processed":  len(partData),
		"key_fingerprint":  session.KeyFingerprint,
		"hmac_enabled":     mpo.hmacManager.IsEnabled(),
	}).Debug("Successfully processed multipart upload part in correct sequential order")

	return result, nil
}

// processBufferedPartsData checks for and processes any parts that are now in sequence
func (mpo *MultipartOperations) processBufferedPartsData(session *MultipartSession) {
	session.OrderingMutex.Lock()
	defer session.OrderingMutex.Unlock()

	// Increment the expected part number since we just processed one
	session.ExpectedPartNumber++

	// Process any buffered parts that are now in sequence
	for {
		partBuffer, exists := session.PendingParts[session.ExpectedPartNumber]
		if !exists {
			// No more sequential parts available
			break
		}

		// Remove from pending
		delete(session.PendingParts, session.ExpectedPartNumber)

		// Read the buffered data
		var partData []byte
		buffer := make([]byte, 64*1024)
		for {
			n, err := partBuffer.DataReader.Read(buffer)
			if n > 0 {
				partData = append(partData, buffer[:n]...)
			}
			if err == io.EOF {
				break
			}
			if err != nil {
				partBuffer.ErrorChan <- fmt.Errorf("failed to read buffered part data: %w", err)
				return
			}
		}

		// Temporarily release the ordering mutex to avoid deadlock with session.mutex
		session.OrderingMutex.Unlock()

		// Process this part in sequence
		result, err := mpo.processPartDataInOrder(session, partBuffer.PartNumber, partData)
		if err != nil {
			partBuffer.ErrorChan <- err
		} else {
			partBuffer.ResultChan <- result
		}

		// Re-acquire the ordering mutex and increment expected part number
		session.OrderingMutex.Lock()
		session.ExpectedPartNumber++

		mpo.logger.WithFields(logrus.Fields{
			"upload_id":         session.UploadID,
			"processed_part":    partBuffer.PartNumber,
			"next_expected":     session.ExpectedPartNumber,
			"remaining_buffered": len(session.PendingParts),
		}).Debug("Processed buffered part in sequence")
	}
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

	// Clean up CTR encryptor
	if session.CTREncryptor != nil {
		session.CTREncryptor.Cleanup()
	}

	// Clean up HMAC calculator
	if session.HMACCalculator != nil {
		session.HMACCalculator.Cleanup()
	}

	// Clean up pending parts
	session.OrderingMutex.Lock()
	for partNumber, partBuffer := range session.PendingParts {
		// Send error to any waiting goroutines
		select {
		case partBuffer.ErrorChan <- fmt.Errorf("session aborted"):
		default:
		}
		delete(session.PendingParts, partNumber)
	}
	session.OrderingMutex.Unlock()

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

	// Clean up CTR encryptor
	if session.CTREncryptor != nil {
		session.CTREncryptor.Cleanup()
	}

	// Clean up HMAC calculator
	if session.HMACCalculator != nil {
		session.HMACCalculator.Cleanup()
	}

	// Clean up pending parts
	session.OrderingMutex.Lock()
	for partNumber, partBuffer := range session.PendingParts {
		// Send error to any waiting goroutines
		select {
		case partBuffer.ErrorChan <- fmt.Errorf("session cleaned up"):
		default:
		}
		delete(session.PendingParts, partNumber)
	}
	session.OrderingMutex.Unlock()

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
		UploadID:           uploadID,
		ObjectKey:          objectKey,
		BucketName:         bucketName,
		PartETags:          make(map[int]string),
		KeyFingerprint:     "none-provider-fingerprint",
		CreatedAt:          time.Now(),
		ContentType:        factory.ContentTypeMultipart,
		Metadata:           make(map[string]string),
		ExpectedPartNumber: 1,
		PendingParts:       make(map[int]*PartBuffer),
	}

	mpo.sessions[uploadID] = session

	mpo.logger.WithFields(logrus.Fields{
		"upload_id":   uploadID,
		"object_key":  objectKey,
		"bucket_name": bucketName,
	}).Debug("Created none provider multipart session")

	return session, nil
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

			// Clean up CTR encryptor
			if session.CTREncryptor != nil {
				session.CTREncryptor.Cleanup()
			}

			// Clean up HMAC calculator
			if session.HMACCalculator != nil {
				session.HMACCalculator.Cleanup()
			}

			// Clean up pending parts
			session.OrderingMutex.Lock()
			for partNumber, partBuffer := range session.PendingParts {
				// Send error to any waiting goroutines
				select {
				case partBuffer.ErrorChan <- fmt.Errorf("session expired"):
				default:
				}
				delete(session.PendingParts, partNumber)
			}
			session.OrderingMutex.Unlock()

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

// GetSessionCount returns the number of active sessions
func (mpo *MultipartOperations) GetSessionCount() int {
	mpo.mutex.RLock()
	defer mpo.mutex.RUnlock()
	return len(mpo.sessions)
}

// DecryptMultipartWithHMACVerification decrypts a multipart object and verifies its integrity.
// This function is used for downloading multipart objects that were uploaded with HMAC verification.
// It creates a session-based decryption process that verifies the HMAC across all parts sequentially.
//
// Parameters:
// - ctx: Context for cancellation and deadlines
// - objectKey: S3 object key for the multipart object
// - metadata: S3 metadata containing encryption information including HMAC
// - encryptedReader: Reader for the encrypted multipart object data
//
// Returns:
// - *bufio.Reader: Decrypted data stream
// - error: Any error during decryption or HMAC verification
//
// Security considerations:
// - HMAC verification ensures data integrity across the entire multipart object
// - Sequential processing maintains proper HMAC calculation order
// - Memory-efficient streaming without loading entire object into memory
//
// Performance characteristics:
// - Streaming decryption with constant memory usage
// - HMAC verification happens during decryption for optimal performance
// - Supports objects from 5MB to 5TB without memory concerns
func (mpo *MultipartOperations) DecryptMultipartWithHMACVerification(ctx context.Context, objectKey string, metadata map[string]string, encryptedReader *bufio.Reader) (*bufio.Reader, error) {
	mpo.logger.WithField("object_key", objectKey).Debug("Starting multipart decryption with HMAC verification")

	// Get encrypted DEK from metadata
	encryptedDEK, err := mpo.metadataManager.GetEncryptedDEK(metadata)
	if err != nil {
		mpo.logger.WithError(err).Error("Failed to get encrypted DEK from metadata")
		return nil, fmt.Errorf("failed to get encrypted DEK: %w", err)
	}

	// Get key fingerprint from metadata
	keyFingerprint, err := mpo.metadataManager.GetFingerprint(metadata)
	if err != nil {
		mpo.logger.WithError(err).Error("Failed to get key fingerprint from metadata")
		return nil, fmt.Errorf("failed to get key fingerprint: %w", err)
	}

	// Decrypt DEK
	dek, err := mpo.providerManager.DecryptDEK(encryptedDEK, keyFingerprint, objectKey)
	if err != nil {
		mpo.logger.WithError(err).Error("Failed to decrypt DEK for multipart object")
		return nil, fmt.Errorf("failed to decrypt DEK: %w", err)
	}
	defer mpo.hmacManager.ClearSensitiveData(dek)

	// Get IV from metadata
	iv, err := mpo.metadataManager.GetIV(metadata)
	if err != nil {
		mpo.logger.WithError(err).Error("Failed to get IV from metadata")
		return nil, fmt.Errorf("failed to get IV: %w", err)
	}
	defer mpo.hmacManager.ClearSensitiveData(iv)

	// Get HMAC from metadata if enabled
	var expectedHMAC []byte
	if mpo.hmacManager.IsEnabled() {
		expectedHMAC, err = mpo.metadataManager.GetHMAC(metadata)
		if err != nil {
			mpo.logger.WithError(err).Error("Failed to get HMAC from metadata")
			return nil, fmt.Errorf("failed to get HMAC from metadata: %w", err)
		}
	}

	// Create HMAC calculator for verification if enabled
	var hmacCalculator *validation.HMACCalculator
	if mpo.hmacManager.IsEnabled() && len(expectedHMAC) > 0 {
		hmacCalculator, err = mpo.hmacManager.CreateCalculator(dek)
		if err != nil {
			mpo.logger.WithError(err).Error("Failed to create HMAC calculator for multipart decryption")
			return nil, fmt.Errorf("failed to create HMAC calculator: %w", err)
		}
	}

	// Create CTR decryptor (using the same stateful encryptor but with existing IV)
	ctrDecryptor, err := dataencryption.NewAESCTRStatefulEncryptorWithIV(dek, iv)
	if err != nil {
		mpo.logger.WithError(err).Error("Failed to create CTR decryptor for multipart object")
		return nil, fmt.Errorf("failed to create CTR decryptor: %w", err)
	}

	// Create streaming decryption reader with HMAC verification
	decryptedReader := mpo.createStreamingDecryptionReader(encryptedReader, ctrDecryptor, hmacCalculator, expectedHMAC, objectKey)

	mpo.logger.WithFields(logrus.Fields{
		"object_key":     objectKey,
		"hmac_enabled":   mpo.hmacManager.IsEnabled(),
		"has_expected_hmac": len(expectedHMAC) > 0,
	}).Debug("Successfully started multipart decryption with HMAC verification")

	return bufio.NewReader(decryptedReader), nil
}

// createStreamingDecryptionReader creates a reader that streams data through decryption and HMAC verification
// without loading the entire object into memory. This prevents OOM issues for large multipart objects.
func (mpo *MultipartOperations) createStreamingDecryptionReader(
	encryptedReader *bufio.Reader,
	decryptor *dataencryption.AESCTRStatefulEncryptor,
	hmacCalculator *validation.HMACCalculator,
	expectedHMAC []byte,
	objectKey string,
) io.Reader {
	pr, pw := io.Pipe()

	go func() {
		defer pw.Close()

		// Clean up HMAC calculator on exit
		defer func() {
			if hmacCalculator != nil {
				hmacCalculator.Cleanup()
			}
		}()

		buffer := make([]byte, 64*1024) // 64KB chunks for efficient streaming
		totalBytesProcessed := 0

		for {
			n, err := encryptedReader.Read(buffer)
			if n > 0 {
				encryptedChunk := buffer[:n]
				totalBytesProcessed += n

				// Decrypt chunk
				decryptedChunk, decErr := decryptor.DecryptPart(encryptedChunk)
				if decErr != nil {
					mpo.logger.WithError(decErr).Error("Failed to decrypt chunk during streaming")
					pw.CloseWithError(fmt.Errorf("failed to decrypt chunk: %w", decErr))
					return
				}

				// Update HMAC calculator with decrypted data (sequential, for integrity verification)
				if mpo.hmacManager.IsEnabled() && hmacCalculator != nil {
					if _, hmacErr := hmacCalculator.Add(decryptedChunk); hmacErr != nil {
						mpo.logger.WithError(hmacErr).Error("Failed to update HMAC during decryption streaming")
						pw.CloseWithError(fmt.Errorf("failed to update HMAC: %w", hmacErr))
						return
					}
				}

				// Write decrypted chunk to pipe
				if _, writeErr := pw.Write(decryptedChunk); writeErr != nil {
					mpo.logger.WithError(writeErr).Error("Failed to write decrypted chunk")
					pw.CloseWithError(writeErr)
					return
				}
			}

			if err == io.EOF {
				// Verify HMAC at the end if enabled
				if mpo.hmacManager.IsEnabled() && hmacCalculator != nil && len(expectedHMAC) > 0 {
					if verifyErr := mpo.hmacManager.VerifyIntegrity(hmacCalculator, expectedHMAC); verifyErr != nil {
						mpo.logger.WithError(verifyErr).Error("HMAC verification failed for multipart object")
						pw.CloseWithError(fmt.Errorf("HMAC verification failed: %w", verifyErr))
						return
					}
					mpo.logger.WithField("object_key", objectKey).Debug("HMAC verification successful for multipart object")
				}

				mpo.logger.WithFields(logrus.Fields{
					"object_key":      objectKey,
					"bytes_processed": totalBytesProcessed,
				}).Debug("Completed streaming decryption for multipart object")
				break
			}

			if err != nil {
				mpo.logger.WithError(err).Error("Error reading during streaming decryption")
				pw.CloseWithError(err)
				return
			}
		}
	}()

	return pr
}
