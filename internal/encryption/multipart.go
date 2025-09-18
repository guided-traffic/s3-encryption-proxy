package encryption

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
	PartSizes        map[int]int64
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
	hmacManager     *HMACManager
	metadataManager *MetadataManager
	config          *config.Config
	logger          *logrus.Entry
}

// NewMultipartOperations creates a new multipart operations handler
func NewMultipartOperations(
	providerManager *ProviderManager,
	hmacManager *HMACManager,
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

// InitiateSession creates a new multipart upload session
func (mpo *MultipartOperations) InitiateSession(ctx context.Context, uploadID, objectKey, bucketName string) (*MultipartSession, error) {
	mpo.logger.WithFields(logrus.Fields{
		"upload_id":   uploadID,
		"object_key":  objectKey,
		"bucket_name": bucketName,
	}).Debug("Initiating multipart upload session")

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

	session := &MultipartSession{
		UploadID:         uploadID,
		ObjectKey:        objectKey,
		BucketName:       bucketName,
		DEK:              dek,
		IV:               iv,
		KeyFingerprint:   mpo.providerManager.GetActiveFingerprint(),
		PartETags:        make(map[int]string),
		PartSizes:        make(map[int]int64),
		HMACCalculator:   hmacCalculator,
		NextPartNumber:   1,
		CreatedAt:        time.Now(),
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

// ProcessPart encrypts a part and updates the session state
func (mpo *MultipartOperations) ProcessPart(ctx context.Context, uploadID string, partNumber int, dataReader *bufio.Reader) (*EncryptionResult, error) {
	mpo.logger.WithFields(logrus.Fields{
		"upload_id":   uploadID,
		"part_number": partNumber,
	}).Debug("Processing multipart upload part")

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

	// Create envelope encryptor for multipart content (uses CTR)
	envelopeEncryptor, err := mpo.providerManager.CreateEnvelopeEncryptor(
		factory.ContentTypeMultipart,
		mpo.metadataManager.GetMetadataPrefix(),
	)
	if err != nil {
		mpo.logger.WithError(err).Error("Failed to create envelope encryptor for multipart part")
		return nil, fmt.Errorf("failed to create envelope encryptor: %w", err)
	}

	// Use object key as associated data
	associatedData := []byte(session.ObjectKey)

	// For HMAC calculation, we need to read the data first
	var data []byte
	if mpo.hmacManager.IsEnabled() {
		data, err = io.ReadAll(dataReader)
		if err != nil {
			return nil, fmt.Errorf("failed to read data for HMAC calculation: %w", err)
		}

		// Update HMAC calculator with sequential data
		if err := mpo.hmacManager.UpdateCalculatorSequential(session.HMACCalculator, data, partNumber); err != nil {
			mpo.logger.WithError(err).Error("Failed to update HMAC calculator")
			return nil, fmt.Errorf("failed to update HMAC calculator: %w", err)
		}

		// Create a new reader from the data
		dataReader = bufio.NewReader(bytes.NewReader(data))
	}

	// Use streaming encryption
	encryptedReader, _, metadata, err := envelopeEncryptor.EncryptDataStream(ctx, dataReader, associatedData)
	if err != nil {
		mpo.logger.WithFields(logrus.Fields{
			"upload_id":   uploadID,
			"part_number": partNumber,
		}).Error("Failed to encrypt multipart data")
		return nil, fmt.Errorf("failed to encrypt data: %w", err)
	}

	// For multipart operations, we need to know the data size for part size tracking
	var dataSize int64
	if len(data) > 0 {
		dataSize = int64(len(data))
	} else {
		// If HMAC is not enabled, we need to peek at the data size
		// This is a limitation of the current API design
		tempData, err := io.ReadAll(dataReader)
		if err != nil {
			return nil, fmt.Errorf("failed to read data for size calculation: %w", err)
		}
		dataSize = int64(len(tempData))
		// Create new readers
		dataReader = bufio.NewReader(bytes.NewReader(tempData))
		encryptedReader, _, metadata, err = envelopeEncryptor.EncryptDataStream(ctx, dataReader, associatedData)
		if err != nil {
			return nil, fmt.Errorf("failed to re-encrypt data: %w", err)
		}
	}

	// Store part size for verification
	session.PartSizes[partNumber] = dataSize

	result := &EncryptionResult{
		EncryptedData:  encryptedReader,
		Metadata:       metadata,
		Algorithm:      "aes-ctr",
		KeyFingerprint: session.KeyFingerprint,
	}

	mpo.logger.WithFields(logrus.Fields{
		"upload_id":        uploadID,
		"part_number":      partNumber,
		"data_size":        dataSize,
		"key_fingerprint":  session.KeyFingerprint,
	}).Debug("Successfully processed multipart upload part")

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

// FinalizeSession completes the multipart upload and generates final metadata
func (mpo *MultipartOperations) FinalizeSession(ctx context.Context, uploadID string) (map[string]string, error) {
	mpo.logger.WithField("upload_id", uploadID).Debug("Finalizing multipart upload session")

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

	// Add final HMAC if enabled
	if mpo.hmacManager.IsEnabled() && session.HMACCalculator != nil {
		finalHMAC := mpo.hmacManager.FinalizeCalculator(session.HMACCalculator)
		if len(finalHMAC) > 0 {
			mpo.metadataManager.SetHMAC(metadata, finalHMAC)
		}
	}

	mpo.logger.WithFields(logrus.Fields{
		"upload_id":        uploadID,
		"object_key":       session.ObjectKey,
		"total_parts":      len(session.PartETags),
		"metadata_keys":    len(metadata),
		"key_fingerprint":  session.KeyFingerprint,
		"hmac_enabled":     mpo.hmacManager.IsEnabled(),
	}).Info("Successfully finalized multipart upload session")

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
		PartSizes:      make(map[int]int64),
		NextPartNumber: 1,
		CreatedAt:      time.Now(),
	}

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
	session.PartSizes[partNumber] = int64(len(data))

	return &EncryptionResult{
		EncryptedData:  bufio.NewReader(bytes.NewReader(data)), // No encryption, but wrap in reader
		Metadata:       nil,                                    // No metadata for none provider
		Algorithm:      "none",
		KeyFingerprint: "none-provider-fingerprint",
	}, nil
}

// processNoneProviderPartStream processes a part when using the none provider (pass-through) with streaming
func (mpo *MultipartOperations) processNoneProviderPartStream(session *MultipartSession, partNumber int, dataReader *bufio.Reader) (*EncryptionResult, error) {
	// For none provider, we need to calculate the size but pass the data through unchanged
	data, err := io.ReadAll(dataReader)
	if err != nil {
		return nil, fmt.Errorf("failed to read data for none provider: %w", err)
	}

	session.PartSizes[partNumber] = int64(len(data))

	return &EncryptionResult{
		EncryptedData:  bufio.NewReader(bytes.NewReader(data)), // No encryption, but wrap in reader
		Metadata:       nil,                                    // No metadata for none provider
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

// GetSessionCount returns the number of active sessions
func (mpo *MultipartOperations) GetSessionCount() int {
	mpo.mutex.RLock()
	defer mpo.mutex.RUnlock()
	return len(mpo.sessions)
}
