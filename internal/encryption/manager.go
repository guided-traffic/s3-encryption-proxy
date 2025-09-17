package encryption

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"hash"
	"io"
	"sync"

	"golang.org/x/crypto/hkdf"
	"github.com/sirupsen/logrus"

	"github.com/guided-traffic/s3-encryption-proxy/internal/config"
	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption"
	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption/dataencryption"
	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption/factory"
)

// MultipartUploadState holds state for an ongoing multipart upload
type MultipartUploadState struct {
	UploadID           string                                       // S3 Upload ID
	ObjectKey          string                                       // S3 Object Key
	BucketName         string                                       // S3 bucket name
	KeyFingerprint     string                                       // Fingerprint of key encryptor used
	ContentType        factory.ContentType                          // Content type for algorithm selection
	EnvelopeEncryptor  encryption.EnvelopeEncryptor                 // Shared encryptor for all parts
	StreamingEncryptor *dataencryption.AESCTRStreamingDataEncryptor // Streaming encryptor for CTR mode
	DEK                []byte                                       // The Data Encryption Key for this upload
	PartETags          map[int]string                               // ETags for each uploaded part
	PartSizes          map[int]int64                                // Sizes for each uploaded part (for verification)
	ExpectedPartSize   int64                                        // Standard part size for offset calculation
	Metadata           map[string]string                            // Additional metadata
	IsCompleted        bool                                         // Whether the upload is completed
	CompletionErr      error                                        // Error from completion, if any
	mutex              sync.RWMutex                                 // Thread-safe access

	// HMAC support for streaming integrity verification
	HMACEnabled              bool                                         // Whether HMAC is enabled for this upload
	StreamingHMACEncryptor   *dataencryption.AESCTRStreamingDataEncryptor // HMAC-enabled streaming encryptor
	ContinuousHMACCalculator hash.Hash                                    // Continuous HMAC calculator across all parts (replaces PartHMACHashes)

	// Sequential HMAC support (to handle out-of-order parts)
	PartDataBuffer       map[int][]byte                                   // Buffer for part data to ensure sequential HMAC calculation
	NextExpectedPart     int                                              // Next part number expected for sequential HMAC processing

	// OPTIMIZATION: Cache frequently used values to avoid repeated processing
	precomputedEncryptedDEK []byte // Cached encrypted DEK bytes (avoid repeated Base64 decoding)
}

// MultipartDecryptionState holds state for an ongoing multipart decryption
type MultipartDecryptionState struct {
	DecryptionID     string            // Unique identifier for this decryption session
	ObjectKey        string            // S3 Object Key
	BucketName       string            // S3 bucket name (optional, for context)
	KeyFingerprint   string            // Fingerprint of key encryptor used
	DEK              []byte            // The Data Encryption Key for this decryption
	IV               []byte            // The initialization vector for AES-CTR
	ExpectedPartSize int64             // Standard part size for offset calculation
	Metadata         map[string]string // Object metadata

	// HMAC verification state
	HMACEnabled      bool      // Whether HMAC verification is enabled
	HMACCalculator   hash.Hash // The HMAC calculator that accumulates data sequentially
	ExpectedHMAC     []byte    // The expected HMAC from metadata
	HMACVerified     bool      // Whether HMAC has been verified successfully
	NextPartNumber   int       // The next expected part number (for sequential verification)
	TotalBytesRead   int64     // Total bytes processed for logging

	// Thread-safe access
	mutex sync.RWMutex

	// Session state
	IsCompleted   bool  // Whether the decryption session is completed
	CompletionErr error // Error from completion, if any
}

// Manager handles encryption operations using the new Factory-based approach
type Manager struct {
	factory           *factory.Factory
	activeFingerprint string // Fingerprint of the active key encryptor
	config            *config.Config
	metadataManager   *MetadataManager // HMAC metadata management
	// Multipart upload state management
	multipartUploads map[string]*MultipartUploadState // Keyed by uploadID
	uploadsMutex     sync.RWMutex                     // Thread-safe access to uploads map
	// Multipart decryption state management
	multipartDecryptions map[string]*MultipartDecryptionState // Keyed by decryptionID
	decryptionsMutex     sync.RWMutex                         // Thread-safe access to decryptions map
}

// NewManager creates a new encryption manager with the new Factory approach
func NewManager(cfg *config.Config) (*Manager, error) {
	// Create factory instance
	factoryInstance := factory.NewFactory()

	// Get active provider for encryption
	activeProvider, err := cfg.GetActiveProvider()
	if err != nil {
		return nil, fmt.Errorf("failed to get active provider: %w", err)
	}

	// Create key encryptors for all providers and register them with the factory
	allProviders := cfg.GetAllProviders()
	var activeFingerprint string

	for _, provider := range allProviders {
		// Handle "none" provider separately - no encryption, no metadata
		if provider.Type == "none" {
			if provider.Alias == activeProvider.Alias {
				activeFingerprint = "none-provider-fingerprint"
			}
			continue
		}

		// Map KEK provider types to factory types
		var keyType factory.KeyEncryptionType
		switch provider.Type {
		case "aes":
			keyType = factory.KeyEncryptionTypeAES
		case "rsa":
			keyType = factory.KeyEncryptionTypeRSA
		case "tink":
			keyType = factory.KeyEncryptionTypeTink
		default:
			return nil, fmt.Errorf("unsupported provider type: %s", provider.Type)
		}

		// Create key encryptor
		keyEncryptor, err := factoryInstance.CreateKeyEncryptorFromConfig(keyType, provider.Config)
		if err != nil {
			return nil, fmt.Errorf("failed to create key encryptor for provider '%s': %w", provider.Alias, err)
		}

		// Register with factory
		factoryInstance.RegisterKeyEncryptor(keyEncryptor)

		// Track the active provider's fingerprint
		if provider.Alias == activeProvider.Alias {
			activeFingerprint = keyEncryptor.Fingerprint()
		}
	}

	if activeFingerprint == "" {
		return nil, fmt.Errorf("active provider '%s' not found or not supported", activeProvider.Alias)
	}

	// Create metadata manager with configured prefix
	metadataPrefix := ""
	if cfg.Encryption.MetadataKeyPrefix != nil {
		metadataPrefix = *cfg.Encryption.MetadataKeyPrefix
	}
	if metadataPrefix == "" {
		metadataPrefix = "s3ep-" // default prefix
	}
	metadataManager := NewMetadataManager(metadataPrefix)

	return &Manager{
		factory:              factoryInstance,
		activeFingerprint:    activeFingerprint,
		config:               cfg,
		metadataManager:      metadataManager,
		multipartUploads:     make(map[string]*MultipartUploadState),
		multipartDecryptions: make(map[string]*MultipartDecryptionState),
	}, nil
}

// EncryptData encrypts data using the active encryption method with content-type based algorithm selection
func (m *Manager) EncryptData(ctx context.Context, data []byte, objectKey string) (*encryption.EncryptionResult, error) {
	return m.EncryptDataWithContentType(ctx, data, objectKey, factory.ContentTypeWhole)
}

// EncryptDataWithContentType encrypts data with explicit content type specification
func (m *Manager) EncryptDataWithContentType(ctx context.Context, data []byte, objectKey string, contentType factory.ContentType) (*encryption.EncryptionResult, error) {
	// Check if we're using the "none" provider - no encryption, no metadata
	if m.activeFingerprint == "none-provider-fingerprint" {
		return m.encryptWithNoneProvider(ctx, data, objectKey)
	}

	// Use object key as associated data for additional security
	associatedData := []byte(objectKey)

	// Create envelope encryptor with metadata prefix
	metadataPrefix := m.GetMetadataKeyPrefix()
	envelopeEncryptor, err := m.factory.CreateEnvelopeEncryptorWithPrefix(contentType, m.activeFingerprint, metadataPrefix)
	if err != nil {
		return nil, fmt.Errorf("failed to create envelope encryptor: %w", err)
	}

	// Encrypt data with or without HMAC based on configuration
	var encryptedData []byte
	var encryptedDEK []byte
	var metadata map[string]string

	if m.config != nil && m.config.Encryption.IntegrityVerification {
		// Use HMAC-enabled encryption for integrity verification
		encryptedData, encryptedDEK, metadata, err = envelopeEncryptor.EncryptDataWithHMAC(ctx, data, associatedData)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt data with HMAC: %w", err)
		}
	} else {
		// Use standard encryption without HMAC
		encryptedData, encryptedDEK, metadata, err = envelopeEncryptor.EncryptData(ctx, data, associatedData)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt data: %w", err)
		}
	}

	// Create encryption result (metadata already contains prefix from envelope encryptor)
	encResult := &encryption.EncryptionResult{
		EncryptedData: encryptedData,
		EncryptedDEK:  encryptedDEK,
		Metadata:      metadata,
	}

	return encResult, nil
}

// EncryptDataWithHTTPContentType encrypts data with HTTP Content-Type based algorithm selection
// This allows clients to force specific encryption modes via Content-Type headers
func (m *Manager) EncryptDataWithHTTPContentType(ctx context.Context, data []byte, objectKey string, httpContentType string, isMultipart bool) (*encryption.EncryptionResult, error) {
	// Get streaming threshold from config, default to 5MB if not configured
	streamingThreshold := int64(5 * 1024 * 1024) // 5MB default
	if m.config != nil && m.config.Optimizations.StreamingThreshold > 0 {
		streamingThreshold = m.config.Optimizations.StreamingThreshold
	}

	// Determine encryption content type based on HTTP Content-Type header
	contentType := factory.DetermineContentTypeFromHTTPContentType(httpContentType, int64(len(data)), isMultipart, streamingThreshold)

	// Log the decision for debugging
	logrus.WithFields(logrus.Fields{
		"objectKey":          objectKey,
		"httpContentType":    httpContentType,
		"encryptionType":     string(contentType),
		"dataSize":           len(data),
		"isMultipart":        isMultipart,
		"activeProvider":     m.activeFingerprint,
		"streamingThreshold": streamingThreshold,
	}).Info("ENCRYPTION-MANAGER: Content-Type based encryption mode selection")

	return m.EncryptDataWithContentType(ctx, data, objectKey, contentType)
}

// EncryptChunkedData encrypts data that comes in chunks (always uses AES-CTR)
func (m *Manager) EncryptChunkedData(ctx context.Context, data []byte, objectKey string) (*encryption.EncryptionResult, error) {
	return m.EncryptDataWithContentType(ctx, data, objectKey, factory.ContentTypeMultipart)
}

// DecryptData decrypts data using metadata to find the correct encryptors
func (m *Manager) DecryptData(ctx context.Context, encryptedData, encryptedDEK []byte, objectKey string, providerAlias string) ([]byte, error) {
	return m.DecryptDataWithMetadata(ctx, encryptedData, encryptedDEK, nil, objectKey, providerAlias)
}

// DecryptDataWithMetadata decrypts data with optional metadata for advanced decryption scenarios
func (m *Manager) DecryptDataWithMetadata(ctx context.Context, encryptedData, encryptedDEK []byte, metadata map[string]string, objectKey string, providerAlias string) ([]byte, error) {
	// Check if we're using the "none" provider
	if m.activeFingerprint == "none-provider-fingerprint" ||
		(metadata != nil && metadata["provider-type"] == "none") ||
		(providerAlias != "" && m.isNoneProvider(providerAlias)) {
		return m.decryptWithNoneProvider(ctx, encryptedData, encryptedDEK, objectKey)
	}

	// STEP 1: Validate that we have the correct KEK before attempting decryption
	requiredFingerprint := m.extractRequiredFingerprint(metadata)
	if requiredFingerprint != "" {
		// Check if we have the required KEK in our factory
		if !m.hasKeyEncryptor(requiredFingerprint) {
			return nil, m.createMissingKEKError(objectKey, requiredFingerprint, metadata)
		}
	}

	// Check if this is an AES-CTR object (streaming or regular)
	if metadata != nil {
		metadataPrefix := m.GetMetadataKeyPrefix()

		// Check for algorithm with prefix first, then fallback
		algorithm := metadata[metadataPrefix+"dek-algorithm"]
		if algorithm == "" {
			algorithm = metadata["dek-algorithm"]
		}

		if algorithm == "aes-256-ctr" {
			// This is an AES-CTR object (either streaming with IV in metadata, or regular with IV prepended)
			// Handle both cases with our enhanced CTR decryption logic
			decryptedData, err := m.decryptSinglePartCTRObject(ctx, encryptedData, encryptedDEK, metadata, objectKey)
			if err != nil {
				return nil, err
			}

			// Verify HMAC if integrity verification is enabled and DEK is available
			if m.config != nil && m.config.Encryption.IntegrityVerification && metadata != nil {
				err = m.verifyHMACWithDEK(ctx, metadata, decryptedData, encryptedDEK, requiredFingerprint)
				if err != nil {
					return nil, fmt.Errorf("HMAC verification failed for CTR object: %w", err)
				}
			}

			return decryptedData, nil
		}
	}

	// Use object key as associated data for regular decryption
	associatedData := []byte(objectKey)

	var decryptedData []byte
	var decryptErr error

	// STEP 2: Try decryption with all available KEKs if no specific fingerprint found
	if requiredFingerprint != "" {
		// We know which KEK to use, try it directly
		decryptedData, decryptErr = m.tryDecryptWithFingerprint(ctx, encryptedData, encryptedDEK, associatedData, requiredFingerprint)
	} else {
		// STEP 3: Try all available KEKs
		decryptedData, decryptErr = m.tryDecryptWithAllKEKs(ctx, encryptedData, encryptedDEK, associatedData, objectKey)
	}

	if decryptErr != nil {
		return nil, decryptErr
	}

	// Verify HMAC if integrity verification is enabled
	if m.config != nil && m.config.Encryption.IntegrityVerification && metadata != nil {
		err := m.verifyHMACWithDEK(ctx, metadata, decryptedData, encryptedDEK, requiredFingerprint)
		if err != nil {
			return nil, fmt.Errorf("HMAC verification failed: %w", err)
		}
	}

	return decryptedData, nil
}

// decryptSinglePartCTRObject decrypts a single-part object that was encrypted with AES-CTR
func (m *Manager) decryptSinglePartCTRObject(ctx context.Context, encryptedData, encryptedDEK []byte, metadata map[string]string, objectKey string) ([]byte, error) {
	// Validate that we have the correct KEK before attempting decryption
	requiredFingerprint := m.extractRequiredFingerprint(metadata)
	if requiredFingerprint != "" && !m.hasKeyEncryptor(requiredFingerprint) {
		return nil, m.createMissingKEKError(objectKey, requiredFingerprint, metadata)
	}

	// Use the required fingerprint if available, otherwise use active fingerprint
	fingerprintToUse := m.activeFingerprint
	if requiredFingerprint != "" {
		fingerprintToUse = requiredFingerprint
	}

	// Decrypt the DEK using the key encryptor
	keyEncryptor, err := m.factory.GetKeyEncryptor(fingerprintToUse)
	if err != nil {
		return nil, fmt.Errorf("failed to get key encryptor for fingerprint '%s': %w", fingerprintToUse, err)
	}

	dek, err := keyEncryptor.DecryptDEK(ctx, encryptedDEK, fingerprintToUse)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt DEK: %w", err)
	}

	// Check if IV is stored in metadata (now the only supported way for AES-CTR)
	metadataPrefix := m.GetMetadataKeyPrefix()
	ivBase64, hasIVInMetadata := metadata[metadataPrefix+"aes-iv"]

	if !hasIVInMetadata {
		return nil, fmt.Errorf("missing IV in AES-CTR metadata - AES-CTR encryption now always stores IV in metadata")
	}

	// IV is in metadata - decode it
	iv, err := base64.StdEncoding.DecodeString(ivBase64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode IV from metadata: %w", err)
	}

	// For single-part CTR objects, decrypt as one piece starting from offset 0
	decryptor, err := dataencryption.NewAESCTRStreamingDataEncryptorWithIV(dek, iv, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES-CTR streaming decryptor: %w", err)
	}

	// Decrypt the entire data (AES-CTR decryption is the same as encryption)
	plaintext, err := decryptor.EncryptPart(encryptedData)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt AES-CTR streaming data: %w", err)
	}

	return plaintext, nil
}

// RotateKEK is not supported in the new Factory-based approach
// Key rotation should be handled externally by updating the configuration
func (m *Manager) RotateKEK(_ context.Context) error {
	return fmt.Errorf("key rotation not supported in Factory-based approach - update configuration externally")
}

// GetProviderAliases returns all available provider aliases from configuration
func (m *Manager) GetProviderAliases() []string {
	allProviders := m.config.GetAllProviders()
	aliases := make([]string, 0, len(allProviders))
	for _, provider := range allProviders {
		aliases = append(aliases, provider.Alias)
	}
	return aliases
}

// GetProvider returns error since we don't expose individual providers in the new approach
func (m *Manager) GetProvider(_ string) (encryption.EncryptionProvider, bool) {
	// In the new approach, we don't expose individual providers
	// All encryption goes through the Factory
	return nil, false
}

// GetActiveProviderAlias returns the alias of the active provider from configuration
func (m *Manager) GetActiveProviderAlias() string {
	activeProvider, err := m.config.GetActiveProvider()
	if err != nil {
		return ""
	}
	return activeProvider.Alias
}

// ProviderSummary holds information about a loaded provider
type ProviderSummary struct {
	Alias       string
	Type        string
	Fingerprint string
	IsActive    bool
}

// GetLoadedProviders returns information about all loaded encryption providers
func (m *Manager) GetLoadedProviders() []ProviderSummary {
	allProviders := m.config.GetAllProviders()
	factoryProviders := m.factory.GetRegisteredProviderInfo()

	// Create a map of fingerprints to provider info for quick lookup
	fingerprintToInfo := make(map[string]factory.ProviderInfo)
	for _, info := range factoryProviders {
		fingerprintToInfo[info.Fingerprint] = info
	}

	var summaries []ProviderSummary
	activeAlias := m.GetActiveProviderAlias()

	for _, provider := range allProviders {
		summary := ProviderSummary{
			Alias:    provider.Alias,
			Type:     provider.Type,
			IsActive: provider.Alias == activeAlias,
		}

		if provider.Type == "none" {
			// Special case for none provider
			summary.Fingerprint = "none-provider-fingerprint"
		} else {
			// Find matching factory provider by searching through all registered providers
			// Since we don't have a direct mapping, we need to match by type and other characteristics
			for fingerprint, info := range fingerprintToInfo {
				if info.Type == provider.Type {
					summary.Fingerprint = fingerprint
					break
				}
			}
		}

		summaries = append(summaries, summary)
	}

	return summaries
}

// ===== MULTIPART UPLOAD SUPPORT =====

// InitiateMultipartUpload creates a new multipart upload state
func (m *Manager) InitiateMultipartUpload(_ context.Context, uploadID, objectKey, bucketName string) error {
	m.uploadsMutex.Lock()
	defer m.uploadsMutex.Unlock()

	// Check if upload already exists
	if _, exists := m.multipartUploads[uploadID]; exists {
		return fmt.Errorf("multipart upload %s already exists", uploadID)
	}

	// Check if we're using the "none" provider
	if m.activeFingerprint == "none-provider-fingerprint" {
		// For "none" provider, create minimal state without encryption
		state := &MultipartUploadState{
			UploadID:         uploadID,
			ObjectKey:        objectKey,
			BucketName:       bucketName,
			KeyFingerprint:   m.activeFingerprint,
			PartETags:        make(map[int]string),
			PartSizes:        make(map[int]int64),
			ExpectedPartSize: 5242880, // 5MB standard part size
			Metadata:         nil,     // No metadata for none provider
			IsCompleted:      false,
			CompletionErr:    nil,
		}
		m.multipartUploads[uploadID] = state
		return nil
	}

	// For encrypted multipart uploads, always use AES-CTR (streaming-friendly)
	contentType := factory.ContentTypeMultipart

	// Get metadata prefix for consistent storage
	metadataPrefix := m.GetMetadataKeyPrefix()

	// Create envelope encryptor for this upload with prefix
	envelopeEncryptor, err := m.factory.CreateEnvelopeEncryptorWithPrefix(contentType, m.activeFingerprint, metadataPrefix)
	if err != nil {
		return fmt.Errorf("failed to create envelope encryptor for multipart upload: %w", err)
	}

	// For multipart uploads using streaming encryption (AES-CTR)
	// Generate a random 16-byte IV for the entire multipart upload
	iv := make([]byte, 16)
	if _, err := rand.Read(iv); err != nil {
		return fmt.Errorf("failed to generate IV for streaming encryption: %w", err)
	}

	// Generate a random 32-byte DEK for streaming encryption
	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		return fmt.Errorf("failed to generate DEK for streaming encryption: %w", err)
	}

	// Create streaming encryptor with the generated IV and DEK
	streamingEncryptor, err := dataencryption.NewAESCTRStreamingDataEncryptorWithIV(dek, iv, 0)
	if err != nil {
		return fmt.Errorf("failed to create streaming encryptor: %w", err)
	}

	// Create HMAC-enabled streaming encryptor if integrity verification is enabled
	var hmacStreamingEncryptor *dataencryption.AESCTRStreamingDataEncryptor
	hmacEnabled := m.config != nil && m.config.Encryption.IntegrityVerification
	if hmacEnabled {
		hmacStreamingEncryptor, err = dataencryption.NewAESCTRStreamingDataEncryptorWithHMAC(dek)
		if err != nil {
			return fmt.Errorf("failed to create HMAC streaming encryptor: %w", err)
		}
	}

	// Encrypt the DEK using the active key encryptor
	keyEncryptor, err := m.factory.GetKeyEncryptor(m.activeFingerprint)
	if err != nil {
		return fmt.Errorf("failed to get key encryptor: %w", err)
	}

	encryptedDEK, _, err := keyEncryptor.EncryptDEK(context.Background(), dek)
	if err != nil {
		return fmt.Errorf("failed to encrypt DEK: %w", err)
	}

	// Create metadata using envelope encryptor pattern with prefix
	metadata := map[string]string{
		metadataPrefix + "dek-algorithm":   "aes-256-ctr", // Always CTR for multipart
		metadataPrefix + "encrypted-dek":   base64.StdEncoding.EncodeToString(encryptedDEK),
		metadataPrefix + "aes-iv":          base64.StdEncoding.EncodeToString(iv),
		metadataPrefix + "kek-algorithm":   keyEncryptor.Name(),
		metadataPrefix + "kek-fingerprint": keyEncryptor.Fingerprint(),
	}

	// Add HMAC metadata if integrity verification is enabled
	var continuousHMACCalculator hash.Hash
	if hmacEnabled {
		// Initialize continuous HMAC calculator for the entire upload
		hmacKeyBytes, err := m.metadataManager.deriveHMACKey(dek)
		if err != nil {
			return fmt.Errorf("failed to derive HMAC key for continuous calculation: %w", err)
		}
		continuousHMACCalculator = hmac.New(sha256.New, hmacKeyBytes)

		logrus.WithFields(logrus.Fields{
			"uploadID":   uploadID,
			"objectKey":  objectKey,
		}).Info("✅ Continuous HMAC calculator initialized for multipart upload")
	}

	// Create multipart upload state
	state := &MultipartUploadState{
		UploadID:                 uploadID,
		ObjectKey:                objectKey,
		BucketName:               bucketName,
		KeyFingerprint:           m.activeFingerprint,
		ContentType:              contentType,
		EnvelopeEncryptor:        envelopeEncryptor,
		StreamingEncryptor:       streamingEncryptor,
		DEK:                      dek,
		PartETags:                make(map[int]string),
		PartSizes:                make(map[int]int64),
		ExpectedPartSize:         5242880, // 5MB standard part size for AWS S3
		Metadata:                 metadata,
		IsCompleted:              false,
		CompletionErr:            nil,
		HMACEnabled:              hmacEnabled,
		StreamingHMACEncryptor:   hmacStreamingEncryptor,
		ContinuousHMACCalculator: continuousHMACCalculator, // Use continuous HMAC instead of part hashes

		// Initialize sequential HMAC support
		PartDataBuffer:   make(map[int][]byte),
		NextExpectedPart: 1, // Start with part 1
	}

	m.multipartUploads[uploadID] = state

	return nil
}

// UploadPart encrypts and uploads a part of a multipart upload using streaming encryption
func (m *Manager) UploadPart(_ context.Context, uploadID string, partNumber int, data []byte) (*encryption.EncryptionResult, error) {
	m.uploadsMutex.RLock()
	state, exists := m.multipartUploads[uploadID]
	m.uploadsMutex.RUnlock()

	if !exists {
		return nil, fmt.Errorf("multipart upload %s not found", uploadID)
	}

	if state.IsCompleted {
		return nil, fmt.Errorf("multipart upload %s is already completed", uploadID)
	}

	// Thread-safe access to part state
	state.mutex.Lock()
	defer state.mutex.Unlock()

	// Store the actual part size for verification during completion
	state.PartSizes[partNumber] = int64(len(data))

	// Handle "none" provider - pass through without encryption
	if m.activeFingerprint == "none-provider-fingerprint" {
		result := &encryption.EncryptionResult{
			EncryptedData: data, // Pass through unencrypted
			EncryptedDEK:  nil,  // No DEK
			Metadata:      nil,  // No metadata
		}
		return result, nil
	}

	// Calculate the offset for this part based on part number and expected part size
	// This allows parallel part uploads without dependencies
	partOffset := (partNumber - 1) * int(state.ExpectedPartSize)
	if partOffset < 0 {
		return nil, fmt.Errorf("invalid part offset calculated: %d", partOffset)
	}
	offset := uint64(partOffset)

	// OPTIMIZATION: Use direct encryption with optional continuous HMAC calculation
	var encryptedData []byte
	var err error

	if state.HMACEnabled && state.ContinuousHMACCalculator != nil {
		// Buffer this part's data for sequential HMAC processing
		state.PartDataBuffer[partNumber] = make([]byte, len(data))
		copy(state.PartDataBuffer[partNumber], data)

		// Process parts sequentially for HMAC calculation
		m.processSequentialHMACParts(state)

		logrus.WithFields(logrus.Fields{
			"partNumber": partNumber,
			"dataSize":   len(data),
		}).Debug("🔒 Part data buffered for sequential HMAC processing")

		// Use standard encryption without HMAC (HMAC will be finalized during completion)
		encryptedData, err = dataencryption.EncryptPartAtOffset(state.DEK, state.StreamingEncryptor.GetIV(), data, offset)
	} else {
		// Use standard encryption without HMAC
		encryptedData, err = dataencryption.EncryptPartAtOffset(state.DEK, state.StreamingEncryptor.GetIV(), data, offset)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to encrypt part %d: %w", partNumber, err)
	}

	// OPTIMIZATION: Pre-computed encrypted DEK (avoid repeated Base64 decoding)
	var encryptedDEK []byte
	if state.precomputedEncryptedDEK == nil {
		metadataPrefix := m.GetMetadataKeyPrefix()
		encryptedDEKStr, exists := state.Metadata[metadataPrefix+"encrypted-dek"]
		if !exists {
			return nil, fmt.Errorf("encrypted DEK not found in state metadata")
		}
		encryptedDEK, err = base64.StdEncoding.DecodeString(encryptedDEKStr)
		if err != nil {
			return nil, fmt.Errorf("failed to decode encrypted DEK from state: %w", err)
		}
		state.precomputedEncryptedDEK = encryptedDEK // Cache for reuse
	} else {
		encryptedDEK = state.precomputedEncryptedDEK
	}

	// OPTIMIZATION: No metadata needed for parts - IV and part number handled at completion
	result := &encryption.EncryptionResult{
		EncryptedData: encryptedData,
		EncryptedDEK:  encryptedDEK,
		Metadata:      map[string]string{}, // Empty - all metadata added at completion
	}

	return result, nil
}

// processSequentialHMACParts processes buffered parts in sequential order for HMAC calculation
func (m *Manager) processSequentialHMACParts(state *MultipartUploadState) {
	// Process parts starting from the next expected part number
	for {
		partData, exists := state.PartDataBuffer[state.NextExpectedPart]
		if !exists {
			// Next expected part is not available yet, stop processing
			break
		}

		// Feed this part's data to the HMAC calculator
		_, hmacErr := state.ContinuousHMACCalculator.Write(partData)
		if hmacErr != nil {
			logrus.WithFields(logrus.Fields{
				"partNumber": state.NextExpectedPart,
				"error":      hmacErr,
			}).Error("❌ Failed to update HMAC calculator with sequential part data")
			break
		}

		logrus.WithFields(logrus.Fields{
			"partNumber": state.NextExpectedPart,
			"dataSize":   len(partData),
		}).Debug("#️⃣  Sequential HMAC updated with part data")

		// Remove processed part from buffer and advance to next part
		delete(state.PartDataBuffer, state.NextExpectedPart)
		state.NextExpectedPart++
	}
}

// UploadPartStreaming encrypts and uploads a part using improved memory management
// This reduces memory allocation by eliminating data accumulation where possible
func (m *Manager) UploadPartStreaming(_ context.Context, uploadID string, partNumber int, reader io.Reader) (*encryption.EncryptionResult, error) {
	m.uploadsMutex.RLock()
	state, exists := m.multipartUploads[uploadID]
	m.uploadsMutex.RUnlock()

	if !exists {
		return nil, fmt.Errorf("multipart upload %s not found", uploadID)
	}

	if state.IsCompleted {
		return nil, fmt.Errorf("multipart upload %s is already completed", uploadID)
	}

	// Thread-safe access to part state
	state.mutex.Lock()
	defer state.mutex.Unlock()

	// Handle "none" provider - pass through without encryption
	if m.activeFingerprint == "none-provider-fingerprint" {
		// Even for none provider, we need to read the data to get the size
		data, err := io.ReadAll(reader)
		if err != nil {
			return nil, fmt.Errorf("failed to read data for none provider: %w", err)
		}

		state.PartSizes[partNumber] = int64(len(data))
		result := &encryption.EncryptionResult{
			EncryptedData: data, // Pass through unencrypted
			EncryptedDEK:  nil,  // No DEK
			Metadata:      nil,  // No metadata
		}
		return result, nil
	}

	// Calculate the offset for this part
	partOffset := (partNumber - 1) * int(state.ExpectedPartSize)
	if partOffset < 0 {
		return nil, fmt.Errorf("invalid part offset calculated: %d", partOffset)
	}
	offset := uint64(partOffset)

	// Read all data from the reader first for sequential HMAC processing
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read streaming data: %w", err)
	}

	// Store the actual part size
	state.PartSizes[partNumber] = int64(len(data))

	// Handle HMAC calculation with sequential buffering
	if state.HMACEnabled && state.ContinuousHMACCalculator != nil {
		// Buffer this part's data for sequential HMAC processing
		state.PartDataBuffer[partNumber] = make([]byte, len(data))
		copy(state.PartDataBuffer[partNumber], data)

		// Process parts sequentially for HMAC calculation
		m.processSequentialHMACParts(state)
	}

	// Encrypt the data using offset-based encryption
	encryptedData, err := dataencryption.EncryptPartAtOffset(state.DEK, state.StreamingEncryptor.GetIV(), data, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt streaming part %d: %w", partNumber, err)
	}

	// Get pre-computed encrypted DEK (optimization to avoid repeated Base64 decoding)
	var encryptedDEK []byte
	if state.precomputedEncryptedDEK == nil {
		metadataPrefix := m.GetMetadataKeyPrefix()
		encryptedDEKStr, exists := state.Metadata[metadataPrefix+"encrypted-dek"]
		if !exists {
			return nil, fmt.Errorf("encrypted DEK not found in state metadata")
		}
		var err error
		encryptedDEK, err = base64.StdEncoding.DecodeString(encryptedDEKStr)
		if err != nil {
			return nil, fmt.Errorf("failed to decode encrypted DEK from state: %w", err)
		}
		state.precomputedEncryptedDEK = encryptedDEK // Cache for reuse
	} else {
		encryptedDEK = state.precomputedEncryptedDEK
	}

	result := &encryption.EncryptionResult{
		EncryptedData: encryptedData,
		EncryptedDEK:  encryptedDEK,
		Metadata:      map[string]string{}, // Empty - all metadata added at completion
	}

	return result, nil
}

// StorePartETag stores the ETag for an uploaded part after successful S3 upload
func (m *Manager) StorePartETag(uploadID string, partNumber int, etag string) error {
	m.uploadsMutex.Lock()
	defer m.uploadsMutex.Unlock()

	state, exists := m.multipartUploads[uploadID]
	if !exists {
		return fmt.Errorf("multipart upload %s not found", uploadID)
	}

	if state.IsCompleted {
		return fmt.Errorf("multipart upload %s is already completed", uploadID)
	}

	// Store the ETag for this part
	state.PartETags[partNumber] = etag
	return nil
}

// CompleteMultipartUpload completes a multipart upload
func (m *Manager) CompleteMultipartUpload(_ context.Context, uploadID string, parts map[int]string) (map[string]string, error) {
	m.uploadsMutex.Lock()
	defer m.uploadsMutex.Unlock()

	state, exists := m.multipartUploads[uploadID]
	if !exists {
		return nil, fmt.Errorf("multipart upload %s not found", uploadID)
	}

	if state.IsCompleted {
		// Upload is already completed - return existing metadata (idempotent operation)
		// Handle "none" provider case
		if m.activeFingerprint == "none-provider-fingerprint" {
			return nil, nil // No metadata for none provider
		}

		// Return the original metadata without modification
		// The metadata was properly generated during initiation
		return state.Metadata, nil
	}

	// Use stored ETags if parts parameter is empty, otherwise use provided ones
	var finalParts map[int]string
	if len(parts) == 0 {
		finalParts = state.PartETags
	} else {
		// Store any additional part ETags provided
		for partNumber, etag := range parts {
			state.PartETags[partNumber] = etag
		}
		finalParts = state.PartETags
	}

	if len(finalParts) == 0 {
		return nil, fmt.Errorf("no parts found for multipart upload %s (stored: %d, provided: %d)", uploadID, len(state.PartETags), len(parts))
	}

	// Mark as completed
	state.IsCompleted = true

	// Finalize HMAC if enabled - use continuous HMAC calculator
	if state.HMACEnabled && state.ContinuousHMACCalculator != nil {
		// Process any remaining buffered parts for sequential HMAC calculation
		m.processSequentialHMACParts(state)

		// Verify all parts have been processed
		if len(state.PartDataBuffer) > 0 {
			logrus.WithFields(logrus.Fields{
				"uploadID":          uploadID,
				"remainingParts":    len(state.PartDataBuffer),
				"nextExpectedPart":  state.NextExpectedPart,
			}).Warn("⚠️  Some parts were not processed for HMAC calculation")
		}

		// Finalize the continuous HMAC calculation
		finalHMAC := state.ContinuousHMACCalculator.Sum(nil)
		hmacMetadataKey := m.metadataManager.GetHMACMetadataKey()
		state.Metadata[hmacMetadataKey] = base64.StdEncoding.EncodeToString(finalHMAC)

		logrus.WithFields(logrus.Fields{
			"uploadID":     uploadID,
			"hmacLength":   len(finalHMAC),
			"hmacBase64":   base64.StdEncoding.EncodeToString(finalHMAC),
		}).Info("✅ Continuous HMAC finalized for multipart upload")
	}

	// Handle "none" provider - return no metadata for pure pass-through
	if m.activeFingerprint == "none-provider-fingerprint" {
		return nil, nil // No metadata at all
	}

	// Return the metadata - no part sizes needed for continuous streaming
	finalMetadata := make(map[string]string)

	// Copy existing metadata
	for key, value := range state.Metadata {
		finalMetadata[key] = value
	}

	// Return the complete metadata (AES-CTR stream cipher enables continuous decryption)
	return finalMetadata, nil
}

// AbortMultipartUpload aborts a multipart upload and cleans up state
func (m *Manager) AbortMultipartUpload(_ context.Context, uploadID string) error {
	m.uploadsMutex.Lock()
	defer m.uploadsMutex.Unlock()

	state, exists := m.multipartUploads[uploadID]
	if !exists {
		return fmt.Errorf("multipart upload %s not found", uploadID)
	}

	// Mark as completed with error
	state.IsCompleted = true
	state.CompletionErr = fmt.Errorf("upload aborted")

	// Remove from active uploads
	delete(m.multipartUploads, uploadID)

	return nil
}

// CleanupMultipartUpload removes multipart upload state from memory (resource management)
// This is a separate concern from business logic completion
func (m *Manager) CleanupMultipartUpload(uploadID string) error {
	m.uploadsMutex.Lock()
	defer m.uploadsMutex.Unlock()

	state, exists := m.multipartUploads[uploadID]
	if exists {
		// Clear sensitive data from memory before cleanup
		if state.DEK != nil {
			for i := range state.DEK {
				state.DEK[i] = 0
			}
		}

		// Clear part data buffers to prevent memory leaks
		for partNum := range state.PartDataBuffer {
			delete(state.PartDataBuffer, partNum)
		}
	}

	// Always succeeds - idempotent cleanup operation
	delete(m.multipartUploads, uploadID)
	return nil
}

// GetMultipartUploadState returns the state of a multipart upload (for monitoring/debugging)
func (m *Manager) GetMultipartUploadState(uploadID string) (*MultipartUploadState, error) {
	m.uploadsMutex.RLock()
	defer m.uploadsMutex.RUnlock()

	state, exists := m.multipartUploads[uploadID]
	if !exists {
		return nil, fmt.Errorf("multipart upload %s not found", uploadID)
	}

	return state, nil
}

// DecryptMultipartData decrypts data that was encrypted as part of a multipart upload
//
// DEPRECATED: This method does not support proper HMAC verification for multipart objects
// because it decrypts each part independently. For proper HMAC verification, use the new
// session-based API:
//   1. InitiateMultipartDecryption()
//   2. DecryptMultipartDataWithSession() for each part (in sequential order)
//   3. CompleteMultipartDecryption()
//
// This method is kept for backward compatibility but should not be used for new code
// when HMAC verification is required.
func (m *Manager) DecryptMultipartData(ctx context.Context, encryptedData, encryptedDEK []byte, metadata map[string]string, objectKey string, partNumber int) ([]byte, error) {
	// LEGACY WARNING: This method decrypts parts independently which breaks HMAC verification
	logrus.WithFields(logrus.Fields{
		"objectKey":  objectKey,
		"partNumber": partNumber,
		"method":     "DecryptMultipartData",
	}).Warn("⚠️  DEPRECATED: Using legacy multipart decryption - HMAC verification not supported")

	// For multipart uploads, we need to handle streaming AES-CTR decryption with offsets

	// Extract IV from metadata
	metadataPrefix := m.GetMetadataKeyPrefix()
	ivBase64, exists := metadata[metadataPrefix+"aes-iv"]
	if !exists {
		return nil, fmt.Errorf("missing IV in multipart metadata")
	}

	iv, err := base64.StdEncoding.DecodeString(ivBase64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode IV: %w", err)
	}

	// Validate that we have the correct KEK before attempting decryption
	requiredFingerprint := m.extractRequiredFingerprint(metadata)
	if requiredFingerprint != "" && !m.hasKeyEncryptor(requiredFingerprint) {
		return nil, m.createMissingKEKError(objectKey, requiredFingerprint, metadata)
	}

	// Use the required fingerprint if available, otherwise use active fingerprint
	fingerprintToUse := m.activeFingerprint
	if requiredFingerprint != "" {
		fingerprintToUse = requiredFingerprint
	}

	// Decrypt the DEK using the key encryptor
	keyEncryptor, err := m.factory.GetKeyEncryptor(fingerprintToUse)
	if err != nil {
		return nil, fmt.Errorf("failed to get key encryptor for fingerprint '%s': %w", fingerprintToUse, err)
	}

	dek, err := keyEncryptor.DecryptDEK(ctx, encryptedDEK, fingerprintToUse)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt DEK: %w", err)
	}

	// Calculate the offset for this part (same logic as in UploadPart)
	expectedPartSize := int64(5242880) // 5MB standard part size
	partOffset := (partNumber - 1) * int(expectedPartSize)
	if partOffset < 0 {
		return nil, fmt.Errorf("invalid part offset calculated: %d", partOffset)
	}
	offset := uint64(partOffset)

	// Create a streaming decryptor with the correct offset for this part
	partDecryptor, err := dataencryption.NewAESCTRStreamingDecryptor(dek, iv, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to create part decryptor for part %d: %w", partNumber, err)
	}

	// Decrypt the part using the part-specific decryptor
	decryptedData := partDecryptor.DecryptPart(encryptedData)

	return decryptedData, nil
}

// InitiateMultipartDecryption creates a new multipart decryption state for sequential HMAC verification
func (m *Manager) InitiateMultipartDecryption(ctx context.Context, decryptionID, objectKey, bucketName string, encryptedDEK []byte, metadata map[string]string) error {
	m.decryptionsMutex.Lock()
	defer m.decryptionsMutex.Unlock()

	// Check if decryption session already exists
	if _, exists := m.multipartDecryptions[decryptionID]; exists {
		return fmt.Errorf("multipart decryption session %s already exists", decryptionID)
	}

	// Check if we're using the "none" provider
	if m.activeFingerprint == "none-provider-fingerprint" {
		// For "none" provider, create minimal state without HMAC
		state := &MultipartDecryptionState{
			DecryptionID:     decryptionID,
			ObjectKey:        objectKey,
			BucketName:       bucketName,
			KeyFingerprint:   m.activeFingerprint,
			Metadata:         metadata,
			HMACEnabled:      false,
			NextPartNumber:   1,
			IsCompleted:      false,
			ExpectedPartSize: 5242880, // 5MB standard part size
		}
		m.multipartDecryptions[decryptionID] = state
		return nil
	}

	// Extract IV from metadata
	metadataPrefix := m.GetMetadataKeyPrefix()
	ivBase64, exists := metadata[metadataPrefix+"aes-iv"]
	if !exists {
		return fmt.Errorf("missing IV in multipart metadata for decryption session %s", decryptionID)
	}

	iv, err := base64.StdEncoding.DecodeString(ivBase64)
	if err != nil {
		return fmt.Errorf("failed to decode IV for decryption session %s: %w", decryptionID, err)
	}

	// Validate that we have the correct KEK before attempting decryption
	requiredFingerprint := m.extractRequiredFingerprint(metadata)
	if requiredFingerprint != "" && !m.hasKeyEncryptor(requiredFingerprint) {
		return m.createMissingKEKError(objectKey, requiredFingerprint, metadata)
	}

	// Use the required fingerprint if available, otherwise use active fingerprint
	fingerprintToUse := m.activeFingerprint
	if requiredFingerprint != "" {
		fingerprintToUse = requiredFingerprint
	}

	// Decrypt the DEK using the key encryptor
	keyEncryptor, err := m.factory.GetKeyEncryptor(fingerprintToUse)
	if err != nil {
		return fmt.Errorf("failed to get key encryptor for fingerprint '%s': %w", fingerprintToUse, err)
	}

	dek, err := keyEncryptor.DecryptDEK(ctx, encryptedDEK, fingerprintToUse)
	if err != nil {
		return fmt.Errorf("failed to decrypt DEK for decryption session %s: %w", decryptionID, err)
	}

	// Check if HMAC verification is enabled
	hmacEnabled := m.config != nil && m.config.Encryption.IntegrityVerification
	var hmacCalculator hash.Hash
	var expectedHMAC []byte

	if hmacEnabled {
		// Look for HMAC in metadata
		hmacKey := m.metadataManager.GetHMACMetadataKey()
		hmacBase64, hasHMAC := metadata[hmacKey]
		if hasHMAC {
			expectedHMAC, err = base64.StdEncoding.DecodeString(hmacBase64)
			if err != nil {
				return fmt.Errorf("failed to decode expected HMAC for session %s: %w", decryptionID, err)
			}

			// Create HMAC using HKDF-derived key
			hmacKeyBytes, err := m.metadataManager.deriveHMACKey(dek)
			if err != nil {
				return fmt.Errorf("failed to derive HMAC key for session %s: %w", decryptionID, err)
			}

			hmacCalculator = hmac.New(sha256.New, hmacKeyBytes)

			logrus.WithFields(logrus.Fields{
				"decryptionID": decryptionID,
				"objectKey":    objectKey,
				"hmacEnabled":  true,
			}).Info("✅ HMAC verification initialized for multipart decryption")
		}
	}

	// Create multipart decryption state
	state := &MultipartDecryptionState{
		DecryptionID:     decryptionID,
		ObjectKey:        objectKey,
		BucketName:       bucketName,
		KeyFingerprint:   fingerprintToUse,
		DEK:              dek,
		IV:               iv,
		ExpectedPartSize: 5242880, // 5MB standard part size for AWS S3
		Metadata:         metadata,
		HMACEnabled:      hmacEnabled && hmacCalculator != nil,
		HMACCalculator:   hmacCalculator,
		ExpectedHMAC:     expectedHMAC,
		HMACVerified:     false,
		NextPartNumber:   1, // Start with part 1
		TotalBytesRead:   0,
		IsCompleted:      false,
		CompletionErr:    nil,
	}

	m.multipartDecryptions[decryptionID] = state

	logrus.WithFields(logrus.Fields{
		"decryptionID":   decryptionID,
		"objectKey":      objectKey,
		"hmacEnabled":    hmacEnabled,
		"keyFingerprint": fingerprintToUse,
	}).Info("🔓 Multipart decryption session initiated")

	return nil
}

// DecryptMultipartDataWithSession decrypts data as part of a multipart decryption session with sequential HMAC verification
func (m *Manager) DecryptMultipartDataWithSession(ctx context.Context, decryptionID string, partNumber int, encryptedData []byte) ([]byte, error) {
	m.decryptionsMutex.RLock()
	state, exists := m.multipartDecryptions[decryptionID]
	m.decryptionsMutex.RUnlock()

	if !exists {
		return nil, fmt.Errorf("multipart decryption session %s not found", decryptionID)
	}

	if state.IsCompleted {
		return nil, fmt.Errorf("multipart decryption session %s is already completed", decryptionID)
	}

	// Thread-safe access to decryption state
	state.mutex.Lock()
	defer state.mutex.Unlock()

	// Handle "none" provider - pass through without decryption
	if m.activeFingerprint == "none-provider-fingerprint" {
		// For none provider, just return the data as-is
		state.TotalBytesRead += int64(len(encryptedData))
		return encryptedData, nil
	}

	// Verify sequential part processing for HMAC integrity
	if state.HMACEnabled && partNumber != state.NextPartNumber {
		return nil, fmt.Errorf("parts must be processed sequentially for HMAC verification: expected part %d, got part %d", state.NextPartNumber, partNumber)
	}

	// Calculate the offset for this part (same logic as in UploadPart)
	partOffset := (partNumber - 1) * int(state.ExpectedPartSize)
	if partOffset < 0 {
		return nil, fmt.Errorf("invalid part offset calculated: %d", partOffset)
	}
	offset := uint64(partOffset)

	// Create a streaming decryptor with the correct offset for this part
	partDecryptor, err := dataencryption.NewAESCTRStreamingDecryptor(state.DEK, state.IV, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to create part decryptor for part %d: %w", partNumber, err)
	}

	// Decrypt the part using the part-specific decryptor
	decryptedData := partDecryptor.DecryptPart(encryptedData)

	// Update HMAC with decrypted data if enabled (sequential processing!)
	if state.HMACEnabled && state.HMACCalculator != nil {
		state.HMACCalculator.Write(decryptedData)
		state.TotalBytesRead += int64(len(decryptedData))
		state.NextPartNumber = partNumber + 1 // Ready for next part

		logrus.WithFields(logrus.Fields{
			"decryptionID":    decryptionID,
			"partNumber":      partNumber,
			"nextPartNumber":  state.NextPartNumber,
			"decryptedBytes":  len(decryptedData),
			"totalBytesRead":  state.TotalBytesRead,
		}).Debug("🔒 HMAC updated sequentially with decrypted part data")
	}

	return decryptedData, nil
}

// CompleteMultipartDecryption completes a multipart decryption session and performs final HMAC verification
func (m *Manager) CompleteMultipartDecryption(ctx context.Context, decryptionID string) error {
	m.decryptionsMutex.Lock()
	defer m.decryptionsMutex.Unlock()

	state, exists := m.multipartDecryptions[decryptionID]
	if !exists {
		return fmt.Errorf("multipart decryption session %s not found", decryptionID)
	}

	if state.IsCompleted {
		// Session is already completed - return existing result (idempotent operation)
		return state.CompletionErr
	}

	// Thread-safe access to decryption state
	state.mutex.Lock()
	defer state.mutex.Unlock()

	// Mark as completed
	state.IsCompleted = true

	// Handle "none" provider - no HMAC verification needed
	if m.activeFingerprint == "none-provider-fingerprint" {
		logrus.WithFields(logrus.Fields{
			"decryptionID": decryptionID,
			"objectKey":    state.ObjectKey,
			"totalBytes":   state.TotalBytesRead,
		}).Info("✅ Multipart decryption completed (none provider)")
		return nil
	}

	// Perform final HMAC verification if enabled
	if state.HMACEnabled && state.HMACCalculator != nil && len(state.ExpectedHMAC) > 0 {
		// Calculate final HMAC
		calculatedHMAC := state.HMACCalculator.Sum(nil)

		// Verify HMAC using constant-time comparison
		if !hmac.Equal(calculatedHMAC, state.ExpectedHMAC) {
			// HMAC verification failed
			state.CompletionErr = fmt.Errorf("HMAC verification failed: data integrity compromised (read %d bytes)", state.TotalBytesRead)

			logrus.WithFields(logrus.Fields{
				"decryptionID":     decryptionID,
				"objectKey":        state.ObjectKey,
				"totalBytesRead":   state.TotalBytesRead,
				"calculatedHMAC":   fmt.Sprintf("%x", calculatedHMAC),
				"expectedHMAC":     fmt.Sprintf("%x", state.ExpectedHMAC),
			}).Error("❌ HMAC verification failed for multipart decryption")

			return state.CompletionErr
		}

		state.HMACVerified = true
		logrus.WithFields(logrus.Fields{
			"decryptionID": decryptionID,
			"objectKey":    state.ObjectKey,
			"totalBytes":   state.TotalBytesRead,
		}).Info("✅ HMAC verification successful for multipart decryption")
	}

	// Clear sensitive data from memory
	if state.DEK != nil {
		for i := range state.DEK {
			state.DEK[i] = 0
		}
		state.DEK = nil
	}

	logrus.WithFields(logrus.Fields{
		"decryptionID": decryptionID,
		"objectKey":    state.ObjectKey,
		"totalBytes":   state.TotalBytesRead,
		"hmacEnabled":  state.HMACEnabled,
		"hmacVerified": state.HMACVerified,
	}).Info("✅ Multipart decryption session completed successfully")

	return nil
}

// AbortMultipartDecryption aborts a multipart decryption session and cleans up state
func (m *Manager) AbortMultipartDecryption(ctx context.Context, decryptionID string) error {
	m.decryptionsMutex.Lock()
	defer m.decryptionsMutex.Unlock()

	state, exists := m.multipartDecryptions[decryptionID]
	if !exists {
		return fmt.Errorf("multipart decryption session %s not found", decryptionID)
	}

	// Thread-safe access to decryption state
	state.mutex.Lock()
	defer state.mutex.Unlock()

	// Mark as completed with error
	state.IsCompleted = true
	state.CompletionErr = fmt.Errorf("decryption aborted")

	// Clear sensitive data from memory
	if state.DEK != nil {
		for i := range state.DEK {
			state.DEK[i] = 0
		}
		state.DEK = nil
	}

	// Remove from active decryptions
	delete(m.multipartDecryptions, decryptionID)

	logrus.WithFields(logrus.Fields{
		"decryptionID": decryptionID,
		"objectKey":    state.ObjectKey,
	}).Info("🚫 Multipart decryption session aborted")

	return nil
}

// CleanupMultipartDecryption removes multipart decryption state from memory (resource management)
func (m *Manager) CleanupMultipartDecryption(decryptionID string) error {
	m.decryptionsMutex.Lock()
	defer m.decryptionsMutex.Unlock()

	state, exists := m.multipartDecryptions[decryptionID]
	if exists {
		// Clear sensitive data from memory before cleanup
		if state.DEK != nil {
			for i := range state.DEK {
				state.DEK[i] = 0
			}
		}
	}

	// Always succeeds - idempotent cleanup operation
	delete(m.multipartDecryptions, decryptionID)
	return nil
}

// GetMultipartDecryptionState returns the state of a multipart decryption session (for monitoring/debugging)
func (m *Manager) GetMultipartDecryptionState(decryptionID string) (*MultipartDecryptionState, error) {
	m.decryptionsMutex.RLock()
	defer m.decryptionsMutex.RUnlock()

	state, exists := m.multipartDecryptions[decryptionID]
	if !exists {
		return nil, fmt.Errorf("multipart decryption session %s not found", decryptionID)
	}

	return state, nil
}

// CreateStreamingDecryptionReader creates a streaming decryption reader for large objects
func (m *Manager) CreateStreamingDecryptionReader(ctx context.Context, encryptedReader io.ReadCloser, encryptedDEK []byte, metadata map[string]string, objectKey string, providerAlias string) (io.ReadCloser, error) {
	return m.CreateStreamingDecryptionReaderWithSize(ctx, encryptedReader, encryptedDEK, metadata, objectKey, providerAlias, -1)
}

// CreateStreamingDecryptionReaderWithSize creates a streaming decryption reader with size hint for optimal buffer sizing
func (m *Manager) CreateStreamingDecryptionReaderWithSize(ctx context.Context, encryptedReader io.ReadCloser, encryptedDEK []byte, metadata map[string]string, objectKey string, providerAlias string, expectedSize int64) (io.ReadCloser, error) {
	// Check if this is actually a streaming multipart object by looking for IV metadata
	// Only streaming multipart objects have IV stored in metadata
	metadataPrefix := m.GetMetadataKeyPrefix()
	ivBase64, hasIVWithPrefix := metadata[metadataPrefix+"aes-iv"]

	// If there's no IV in metadata, this is not a streaming multipart object
	// Fall back to regular decryption
	if !hasIVWithPrefix {
		// Read all data and use normal decryption
		encryptedData, err := io.ReadAll(encryptedReader)
		if err != nil {
			return nil, fmt.Errorf("failed to read encrypted data for non-streaming decryption: %w", err)
		}
		_ = encryptedReader.Close()

		// Use normal decryption path
		decryptedData, err := m.DecryptDataWithMetadata(ctx, encryptedData, encryptedDEK, metadata, objectKey, providerAlias)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt non-streaming object: %w", err)
		}

		// Return the decrypted data as a reader
		return io.NopCloser(bytes.NewReader(decryptedData)), nil
	}

	// This is a real streaming multipart object - proceed with streaming decryption
	iv, err := base64.StdEncoding.DecodeString(ivBase64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode IV: %w", err)
	}

	// Validate that we have the correct KEK before attempting decryption
	requiredFingerprint := m.extractRequiredFingerprint(metadata)
	if requiredFingerprint != "" && !m.hasKeyEncryptor(requiredFingerprint) {
		return nil, m.createMissingKEKError(objectKey, requiredFingerprint, metadata)
	}

	// Use the required fingerprint if available, otherwise use active fingerprint
	fingerprintToUse := m.activeFingerprint
	if requiredFingerprint != "" {
		fingerprintToUse = requiredFingerprint
	}

	// Decrypt the DEK using the key encryptor
	keyEncryptor, err := m.factory.GetKeyEncryptor(fingerprintToUse)
	if err != nil {
		return nil, fmt.Errorf("failed to get key encryptor for fingerprint '%s': %w", fingerprintToUse, err)
	}

	dek, err := keyEncryptor.DecryptDEK(ctx, encryptedDEK, fingerprintToUse)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt DEK: %w", err)
	}

	// Create streaming decryption reader with adaptive buffer sizing
	bufferSize := m.getAdaptiveBufferSize(expectedSize)

	// Check if HMAC verification is enabled
	hmacEnabled := m.config != nil && m.config.Encryption.IntegrityVerification
	var hmacHash hash.Hash
	var expectedHMAC []byte

	if hmacEnabled {
		// Look for HMAC in metadata
		hmacBase64, hasHMAC := metadata[metadataPrefix+"hmac"]
		if hasHMAC {
			var err error
			expectedHMAC, err = base64.StdEncoding.DecodeString(hmacBase64)
			if err != nil {
				return nil, fmt.Errorf("failed to decode expected HMAC: %w", err)
			}

			// Create HMAC using HKDF-derived key
			hmacKey, err := m.deriveHMACKey(dek)
			if err != nil {
				return nil, fmt.Errorf("failed to derive HMAC key: %w", err)
			}

			hmacHash = hmac.New(sha256.New, hmacKey)

			logrus.WithFields(logrus.Fields{
				"objectKey":   objectKey,
				"hmacEnabled": true,
			}).Info("✅ HMAC verification initialized for streaming decryption")
		}
	}

	reader := &streamingDecryptionReader{
		encryptedReader: encryptedReader,
		dek:             dek,
		iv:              iv,
		offset:          0,
		buffer:          make([]byte, bufferSize), // Adaptive buffer for optimal performance
		bufferPos:       0,
		bufferLen:       0,

		// HMAC verification fields
		hmacEnabled:     hmacEnabled && hmacHash != nil,
		hmac:            hmacHash,
		expectedHMAC:    expectedHMAC,
		totalBytesRead:  0,
		hmacVerified:    false,
		objectKey:       objectKey,
	}

	return reader, nil
}

// deriveHMACKey derives an HMAC key from the DEK using HKDF
func (m *Manager) deriveHMACKey(dek []byte) ([]byte, error) {
	// Use HKDF to derive HMAC key from DEK
	salt := []byte("s3-proxy-integrity-v1")
	info := []byte("file-hmac-key")

	reader := hkdf.New(sha256.New, dek, salt, info)
	hmacKey := make([]byte, 32) // 32 bytes for HMAC-SHA256

	_, err := io.ReadFull(reader, hmacKey)
	if err != nil {
		return nil, fmt.Errorf("failed to derive HMAC key: %w", err)
	}

	return hmacKey, nil
}

// streamingDecryptionReader provides streaming decryption for AES-CTR encrypted data
type streamingDecryptionReader struct {
	encryptedReader io.ReadCloser
	dek             []byte
	iv              []byte
	offset          uint64
	buffer          []byte
	bufferPos       int
	bufferLen       int
	decryptor       *dataencryption.AESCTRStreamingDataEncryptor

	// HMAC verification support
	hmacEnabled     bool
	hmac            hash.Hash
	expectedHMAC    []byte
	totalBytesRead  int64
	hmacVerified    bool
	objectKey       string // For logging purposes
}

// GetObjectKey returns the object key for this streaming reader
func (r *streamingDecryptionReader) GetObjectKey() string {
	return r.objectKey
}

func (r *streamingDecryptionReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	totalRead := 0

	for totalRead < len(p) {
		// If buffer is empty, fill it
		if r.bufferPos >= r.bufferLen {
			err := r.fillBuffer()
			if err != nil {
				if err == io.EOF && totalRead > 0 {
					return totalRead, nil
				}
				return totalRead, err
			}
		}

		// Copy from buffer to output
		available := r.bufferLen - r.bufferPos
		needed := len(p) - totalRead
		toCopy := available
		if needed < available {
			toCopy = needed
		}

		copy(p[totalRead:], r.buffer[r.bufferPos:r.bufferPos+toCopy])

		// Update HMAC with decrypted data if enabled
		if r.hmacEnabled && r.hmac != nil {
			r.hmac.Write(p[totalRead:totalRead+toCopy])
			r.totalBytesRead += int64(toCopy)
		}

		r.bufferPos += toCopy
		totalRead += toCopy
	}

	return totalRead, nil
}

func (r *streamingDecryptionReader) fillBuffer() error {
	// Read encrypted data
	n, err := r.encryptedReader.Read(r.buffer)
	if err != nil && err != io.EOF {
		return err
	}
	if n == 0 {
		return io.EOF
	}

	// Create decryptor only once on first use at offset 0
	// The streaming decryptor manages its own internal offset state
	if r.decryptor == nil {
		var createErr error
		r.decryptor, createErr = dataencryption.NewAESCTRStreamingDataEncryptorWithIV(r.dek, r.iv, 0)
		if createErr != nil {
			return fmt.Errorf("failed to create decryptor: %w", createErr)
		}
	}

	// Decrypt the chunk (AES-CTR decryption is same as encryption)
	// The streaming decryptor maintains internal state, so we just call EncryptPart sequentially
	decryptedData, decryptErr := r.decryptor.EncryptPart(r.buffer[:n])
	if decryptErr != nil {
		return fmt.Errorf("failed to decrypt chunk: %w", decryptErr)
	}

	// Copy decrypted data back to buffer
	copy(r.buffer, decryptedData)
	r.bufferLen = len(decryptedData)
	r.bufferPos = 0

	return nil
}

func (r *streamingDecryptionReader) Close() error {
	// Perform final HMAC verification if enabled
	if r.hmacEnabled && r.hmac != nil && !r.hmacVerified && len(r.expectedHMAC) > 0 {
		// Calculate final HMAC
		calculatedHMAC := r.hmac.Sum(nil)

		// Verify HMAC using constant-time comparison
		if !hmac.Equal(calculatedHMAC, r.expectedHMAC) {
			// HMAC verification failed
			logrus.WithFields(logrus.Fields{
				"objectKey":        r.objectKey,
				"totalBytesRead":   r.totalBytesRead,
				"calculatedHMAC":   fmt.Sprintf("%x", calculatedHMAC),
				"expectedHMAC":     fmt.Sprintf("%x", r.expectedHMAC),
			}).Error("❌ HMAC verification failed during Close()")

			return fmt.Errorf("HMAC verification failed: data integrity compromised (read %d bytes)", r.totalBytesRead)
		}

		r.hmacVerified = true
		logrus.WithFields(logrus.Fields{
			"objectKey":    r.objectKey,
			"totalBytes":   r.totalBytesRead,
		}).Info("✅ HMAC verification successful during Close()")
	}

	return r.encryptedReader.Close()
}

// encryptWithNoneProvider handles "none" provider - no encryption, no metadata
func (m *Manager) encryptWithNoneProvider(_ context.Context, data []byte, _ string) (*encryption.EncryptionResult, error) {
	// "none" provider: return data as-is without any encryption or metadata
	result := &encryption.EncryptionResult{
		EncryptedData: data, // Pass through unencrypted
		EncryptedDEK:  nil,  // No DEK
		Metadata:      nil,  // No metadata at all
	}

	return result, nil
}

// decryptWithNoneProvider handles decryption with the "none" provider
func (m *Manager) decryptWithNoneProvider(_ context.Context, encryptedData, _ []byte, _ string) ([]byte, error) {
	// "none" provider: data is stored unencrypted, simply return it as-is
	return encryptedData, nil
}

// isNoneProvider checks if the given provider alias is a "none" provider
func (m *Manager) isNoneProvider(providerAlias string) bool {
	allProviders := m.config.GetAllProviders()
	for _, provider := range allProviders {
		if provider.Alias == providerAlias && provider.Type == "none" {
			return true
		}
	}
	return false
}

// extractRequiredFingerprint extracts the required KEK fingerprint from metadata
func (m *Manager) extractRequiredFingerprint(metadata map[string]string) string {
	if metadata == nil {
		return ""
	}

	// Try various metadata keys where the fingerprint might be stored
	fingerprintKeys := []string{
		"kek-fingerprint",
		"s3ep-kek-fingerprint",
		"s3ep-key-id",
		"encryption-kek-fingerprint",
	}

	for _, key := range fingerprintKeys {
		if fingerprint, exists := metadata[key]; exists && fingerprint != "" {
			return fingerprint
		}
	}

	return ""
}

// hasKeyEncryptor checks if we have the specified key encryptor in our factory
func (m *Manager) hasKeyEncryptor(fingerprint string) bool {
	_, err := m.factory.GetKeyEncryptor(fingerprint)
	return err == nil
}

// createMissingKEKError creates a detailed error message when the required KEK is not available
func (m *Manager) createMissingKEKError(objectKey, requiredFingerprint string, metadata map[string]string) error {
	// Determine the KEK type from metadata or fingerprint pattern
	kekType := "unknown"

	if metadata != nil {
		if kekAlg, exists := metadata["kek-algorithm"]; exists {
			kekType = kekAlg
		}
	}

	return fmt.Errorf("❌ KEK_MISSING: Object '%s' requires KEK fingerprint '%s' (type: %s) this is unknown",
		objectKey, requiredFingerprint, kekType)
}

// tryDecryptWithFingerprint attempts decryption with a specific KEK fingerprint
func (m *Manager) tryDecryptWithFingerprint(ctx context.Context, encryptedData, encryptedDEK []byte, associatedData []byte, fingerprint string) ([]byte, error) {
	algorithms := []string{"aes-256-gcm", "aes-256-ctr"}

	for _, algorithm := range algorithms {
		factoryMetadata := map[string]string{
			"kek-fingerprint": fingerprint,
			"dek-algorithm":   algorithm,
		}

		plaintext, err := m.factory.DecryptData(ctx, encryptedData, encryptedDEK, factoryMetadata, associatedData)
		if err == nil {
			return plaintext, nil
		}
	}

	return nil, fmt.Errorf("failed to decrypt data with KEK fingerprint '%s'", fingerprint)
}

// tryDecryptWithAllKEKs attempts decryption with all available KEKs
func (m *Manager) tryDecryptWithAllKEKs(ctx context.Context, encryptedData, encryptedDEK []byte, associatedData []byte, objectKey string) ([]byte, error) {
	availableKEKs := m.factory.GetRegisteredKeyEncryptors()
	algorithms := []string{"aes-256-gcm", "aes-256-ctr"}

	// Try current active fingerprint first
	for _, algorithm := range algorithms {
		factoryMetadata := map[string]string{
			"kek-fingerprint": m.activeFingerprint,
			"dek-algorithm":   algorithm,
		}

		plaintext, err := m.factory.DecryptData(ctx, encryptedData, encryptedDEK, factoryMetadata, associatedData)
		if err == nil {
			return plaintext, nil
		}
	}

	// Try all other available KEKs
	for _, fingerprint := range availableKEKs {
		if fingerprint == m.activeFingerprint {
			continue // Already tried above
		}

		for _, algorithm := range algorithms {
			factoryMetadata := map[string]string{
				"kek-fingerprint": fingerprint,
				"dek-algorithm":   algorithm,
			}

			plaintext, err := m.factory.DecryptData(ctx, encryptedData, encryptedDEK, factoryMetadata, associatedData)
			if err == nil {
				return plaintext, nil
			}
		}
	}

	return nil, fmt.Errorf("❌ DECRYPTION_FAILED: Object '%s' could not be decrypted with any of the %d available KEKs: %v",
		objectKey, len(availableKEKs), availableKEKs)
}

// GetMetadataKeyPrefix returns the metadata key prefix from the encryption config
func (m *Manager) GetMetadataKeyPrefix() string {
	// Read from top-level encryption configuration
	if m.config.Encryption.MetadataKeyPrefix != nil {
		// Key is explicitly set in config - use its value (even if empty)
		return *m.config.Encryption.MetadataKeyPrefix
	}

	return "s3ep-" // default when not set in config
}

// getStreamingBufferSize returns the configured streaming buffer size or default if not set
func (m *Manager) getStreamingBufferSize() int {
	if m.config.Optimizations.StreamingBufferSize > 0 {
		return m.config.Optimizations.StreamingBufferSize
	}
	// Default to 64KB if not configured
	return 64 * 1024
}

// getAdaptiveBufferSize returns an optimal buffer size based on expected object size and system load
func (m *Manager) getAdaptiveBufferSize(expectedSize int64) int {
	// If adaptive buffering is disabled, use standard buffer size
	if !m.config.Optimizations.EnableAdaptiveBuffering {
		return m.getStreamingBufferSize()
	}

	// Define buffer size tiers based on object size
	const (
		// Tier 1: Small files (< 1MB) - use smaller buffers to reduce memory
		tier1Threshold  = 1 * 1024 * 1024 // 1MB
		tier1BufferSize = 16 * 1024       // 16KB

		// Tier 2: Medium files (1MB - 50MB) - balanced approach
		tier2Threshold  = 50 * 1024 * 1024 // 50MB
		tier2BufferSize = 64 * 1024        // 64KB

		// Tier 3: Large files (50MB - 500MB) - larger buffers for better throughput
		tier3Threshold  = 500 * 1024 * 1024 // 500MB
		tier3BufferSize = 256 * 1024        // 256KB

		// Tier 4: Very large files (> 500MB) - maximum buffer size
		tier4BufferSize = 512 * 1024 // 512KB
	)

	// Get base buffer size from configuration
	baseBufferSize := m.getStreamingBufferSize()

	// If no size hint available, use base buffer
	if expectedSize <= 0 {
		return baseBufferSize
	}

	// Apply adaptive sizing based on expected object size
	var adaptiveSize int
	switch {
	case expectedSize < tier1Threshold:
		adaptiveSize = tier1BufferSize
	case expectedSize < tier2Threshold:
		adaptiveSize = tier2BufferSize
	case expectedSize < tier3Threshold:
		adaptiveSize = tier3BufferSize
	default:
		adaptiveSize = tier4BufferSize
	}

	// Respect configured limits (4KB minimum, 2MB maximum)
	const (
		minBufferSize = 4 * 1024        // 4KB minimum
		maxBufferSize = 2 * 1024 * 1024 // 2MB maximum
	)

	if adaptiveSize < minBufferSize {
		adaptiveSize = minBufferSize
	}
	if adaptiveSize > maxBufferSize {
		adaptiveSize = maxBufferSize
	}

	// Don't go below configured buffer size if it's larger
	if adaptiveSize < baseBufferSize && baseBufferSize <= maxBufferSize {
		return baseBufferSize
	}

	return adaptiveSize
}

// verifyHMACWithDEK verifies HMAC using the DEK from encryptedDEK
func (m *Manager) verifyHMACWithDEK(ctx context.Context, metadata map[string]string, decryptedData, encryptedDEK []byte, requiredFingerprint string) error {
	// Skip if no metadata
	if metadata == nil {
		return nil
	}

	// Skip if HMAC not present (backward compatibility)
	hmacKey := m.metadataManager.GetHMACMetadataKey()
	if _, exists := metadata[hmacKey]; !exists {
		return nil
	}

	// Use the required fingerprint to get the right key encryptor
	fingerprint := requiredFingerprint
	if fingerprint == "" {
		fingerprint = m.activeFingerprint
	}

	// Get key encryptor
	keyEncryptor, err := m.factory.GetKeyEncryptor(fingerprint)
	if err != nil {
		return fmt.Errorf("failed to get key encryptor for HMAC verification: %w", err)
	}

	// Decrypt the DEK
	dek, err := keyEncryptor.DecryptDEK(ctx, encryptedDEK, fingerprint)
	if err != nil {
		return fmt.Errorf("failed to decrypt DEK for HMAC verification: %w", err)
	}
	defer func() {
		// Clear DEK from memory
		for i := range dek {
			dek[i] = 0
		}
	}()

	// Verify HMAC
	isValid, err := m.metadataManager.VerifyHMACFromMetadata(metadata, decryptedData, dek, true)
	if err != nil {
		return err
	}

	if !isValid {
		return fmt.Errorf("HMAC verification failed: data integrity compromised")
	}

	return nil
}
