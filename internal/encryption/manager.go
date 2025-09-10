package encryption

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/guided-traffic/s3-encryption-proxy/internal/config"
	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption"
	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption/dataencryption"
	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption/factory"
)

// MultipartUploadState holds state for an ongoing multipart upload
type MultipartUploadState struct {
	UploadID           string                                          // S3 Upload ID
	ObjectKey          string                                          // S3 Object Key
	BucketName         string                                          // S3 bucket name
	KeyFingerprint     string                                          // Fingerprint of key encryptor used
	ContentType        factory.ContentType                             // Content type for algorithm selection
	EnvelopeEncryptor  encryption.EnvelopeEncryptor                    // Shared encryptor for all parts
	StreamingEncryptor *dataencryption.AESCTRStreamingDataEncryptor    // Streaming encryptor for CTR mode
	DEK                []byte                                          // The Data Encryption Key for this upload
	PartETags          map[int]string                                  // ETags for each uploaded part
	PartSizes          map[int]int64                                   // Sizes for each uploaded part (for verification)
	ExpectedPartSize   int64                                           // Standard part size for offset calculation
	Metadata           map[string]string                               // Additional metadata
	IsCompleted        bool                                            // Whether the upload is completed
	CompletionErr      error                                           // Error from completion, if any
	mutex              sync.RWMutex                                    // Thread-safe access

	// OPTIMIZATION: Cache frequently used values to avoid repeated processing
	precomputedEncryptedDEK []byte                                     // Cached encrypted DEK bytes (avoid repeated Base64 decoding)
}

// Manager handles encryption operations using the new Factory-based approach
type Manager struct {
	factory           *factory.Factory
	activeFingerprint string // Fingerprint of the active key encryptor
	config            *config.Config
	// Multipart upload state management
	multipartUploads map[string]*MultipartUploadState // Keyed by uploadID
	uploadsMutex     sync.RWMutex                     // Thread-safe access to uploads map
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

	return &Manager{
		factory:           factoryInstance,
		activeFingerprint: activeFingerprint,
		config:            cfg,
		multipartUploads:  make(map[string]*MultipartUploadState),
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

	// Create envelope encryptor with the active key fingerprint
	envelopeEncryptor, err := m.factory.CreateEnvelopeEncryptor(contentType, m.activeFingerprint)
	if err != nil {
		return nil, fmt.Errorf("failed to create envelope encryptor: %w", err)
	}

	// Encrypt data
	encryptedData, encryptedDEK, metadata, err := envelopeEncryptor.EncryptData(ctx, data, associatedData)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt data: %w", err)
	}

	// Create encryption result
	encResult := &encryption.EncryptionResult{
		EncryptedData: encryptedData,
		EncryptedDEK:  encryptedDEK,
		Metadata:      metadata,
	}

	// Add additional metadata
	if encResult.Metadata == nil {
		encResult.Metadata = make(map[string]string)
	}

	// Add KEK name for identification
	keyEncryptor, err := m.factory.GetKeyEncryptor(m.activeFingerprint)
	if err == nil {
		encResult.Metadata["kek-algorithm"] = keyEncryptor.Name()
	}

	// Add content type information
	encResult.Metadata["content-type"] = string(contentType)

	return encResult, nil
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

	// Check if this is a streaming AES-CTR multipart object
	if metadata != nil {
		algorithm := metadata["data-algorithm"]

		if algorithm == "aes-256-ctr" {
			// This is a streaming AES-CTR multipart object
			return m.decryptStreamingMultipartObject(ctx, encryptedData, encryptedDEK, metadata, objectKey)
		}
	}

	// Use object key as associated data for regular decryption
	associatedData := []byte(objectKey)

	// STEP 2: Try decryption with all available KEKs if no specific fingerprint found
	if requiredFingerprint != "" {
		// We know which KEK to use, try it directly
		return m.tryDecryptWithFingerprint(ctx, encryptedData, encryptedDEK, associatedData, requiredFingerprint)
	}

	// STEP 3: Legacy fallback - try all available KEKs
	return m.tryDecryptWithAllKEKs(ctx, encryptedData, encryptedDEK, associatedData, objectKey)
}

// decryptStreamingMultipartObject decrypts a completed multipart object that was encrypted with streaming AES-CTR
func (m *Manager) decryptStreamingMultipartObject(ctx context.Context, encryptedData, encryptedDEK []byte, metadata map[string]string, objectKey string) ([]byte, error) {
	// Extract IV from metadata
	ivBase64, exists := metadata["encryption-iv"]
	if !exists {
		return nil, fmt.Errorf("missing IV in streaming multipart metadata")
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

	// For multipart uploads, the encrypted data is concatenated encrypted parts
	// We need to decrypt each part with the correct offset in the stream
	// Default part size is 5MB (5242880 bytes)
	const defaultPartSize = 5242880

	var decryptedParts [][]byte
	offset := uint64(0)
	partNum := 1

	for len(encryptedData) > 0 {
		// Determine part size (last part might be smaller)
		partSize := defaultPartSize
		if len(encryptedData) < partSize {
			partSize = len(encryptedData)
		}

		// Extract this part's encrypted data
		partData := encryptedData[:partSize]
		encryptedData = encryptedData[partSize:]

		// Create decryptor with the correct offset for this part
		partDecryptor, err := dataencryption.NewAESCTRStreamingDataEncryptorWithIV(dek, iv, offset)
		if err != nil {
			return nil, fmt.Errorf("failed to create decryptor for part %d: %w", partNum, err)
		}

		// Decrypt this part
		decryptedPart, err := partDecryptor.EncryptPart(partData) // AES-CTR decryption is the same as encryption
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt part %d: %w", partNum, err)
		}

		decryptedParts = append(decryptedParts, decryptedPart)
		if partSize > 0 { // Ensure positive value before conversion
			offset += uint64(partSize)
		}
		partNum++
	}

	// Concatenate all decrypted parts
	totalSize := 0
	for _, part := range decryptedParts {
		totalSize += len(part)
	}

	plaintext := make([]byte, totalSize)
	pos := 0
	for _, part := range decryptedParts {
		copy(plaintext[pos:], part)
		pos += len(part)
	}

	return plaintext, nil
}

// RotateKEK is not supported in the new Factory-based approach
// Key rotation should be handled externally by updating the configuration
func (m *Manager) RotateKEK(ctx context.Context) error {
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
func (m *Manager) GetProvider(alias string) (encryption.EncryptionProvider, bool) {
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
func (m *Manager) InitiateMultipartUpload(ctx context.Context, uploadID, objectKey, bucketName string) error {
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
			Metadata:         nil,      // No metadata for none provider
			IsCompleted:      false,
			CompletionErr:    nil,
		}
		m.multipartUploads[uploadID] = state
		return nil
	}

	// For encrypted multipart uploads, always use AES-CTR (streaming-friendly)
	contentType := factory.ContentTypeMultipart

	// Create envelope encryptor for this upload
	envelopeEncryptor, err := m.factory.CreateEnvelopeEncryptor(contentType, m.activeFingerprint)
	if err != nil {
		return fmt.Errorf("failed to create envelope encryptor for multipart upload: %w", err)
	}

	// Create multipart upload state
	state := &MultipartUploadState{
		UploadID:          uploadID,
		ObjectKey:         objectKey,
		BucketName:        bucketName,
		KeyFingerprint:    m.activeFingerprint,
		ContentType:       contentType,
		EnvelopeEncryptor: envelopeEncryptor,
		PartETags:         make(map[int]string),
		PartSizes:         make(map[int]int64),
		ExpectedPartSize:  5242880, // 5MB standard part size for AWS S3
		Metadata: map[string]string{
			"kek-fingerprint":      m.activeFingerprint,
			"data-algorithm":       "aes-256-ctr", // Always CTR for multipart
		},
		IsCompleted:   false,
		CompletionErr: nil,
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

	state.StreamingEncryptor = streamingEncryptor
	state.DEK = dek

	// Encrypt the DEK using the active key encryptor
	keyEncryptor, err := m.factory.GetKeyEncryptor(m.activeFingerprint)
	if err != nil {
		return fmt.Errorf("failed to get key encryptor: %w", err)
	}

	encryptedDEK, _, err := keyEncryptor.EncryptDEK(context.Background(), dek)
	if err != nil {
		return fmt.Errorf("failed to encrypt DEK: %w", err)
	}

	// Store encryption metadata
	state.Metadata["encryption-dek"] = base64.StdEncoding.EncodeToString(encryptedDEK)
	state.Metadata["encryption-iv"] = base64.StdEncoding.EncodeToString(iv)

	// Add KEK name for identification
	keyEncryptor, keyErr := m.factory.GetKeyEncryptor(m.activeFingerprint)
	if keyErr == nil {
		state.Metadata["kek-algorithm"] = keyEncryptor.Name()
	}

	m.multipartUploads[uploadID] = state

	return nil
}

// UploadPart encrypts and uploads a part of a multipart upload using streaming encryption
func (m *Manager) UploadPart(ctx context.Context, uploadID string, partNumber int, data []byte) (*encryption.EncryptionResult, error) {
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

	// OPTIMIZATION: Use direct encryption without creating encryptor instances
	// This eliminates the major performance bottleneck
	encryptedData, err := dataencryption.EncryptPartAtOffset(state.DEK, state.StreamingEncryptor.GetIV(), data, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt part %d with optimized encryption: %w", partNumber, err)
	}

	// OPTIMIZATION: Pre-computed encrypted DEK (avoid repeated Base64 decoding)
	var encryptedDEK []byte
	if state.precomputedEncryptedDEK == nil {
		encryptedDEK, err = base64.StdEncoding.DecodeString(state.Metadata["encryption-dek"])
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
func (m *Manager) CompleteMultipartUpload(ctx context.Context, uploadID string, parts map[int]string) (map[string]string, error) {
	m.uploadsMutex.Lock()
	defer m.uploadsMutex.Unlock()

	state, exists := m.multipartUploads[uploadID]
	if !exists {
		return nil, fmt.Errorf("multipart upload %s not found", uploadID)
	}

	if state.IsCompleted {
		return nil, fmt.Errorf("multipart upload %s is already completed", uploadID)
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

	// Handle "none" provider - return no metadata for pure pass-through
	if m.activeFingerprint == "none-provider-fingerprint" {
		return nil, nil // No metadata at all
	}

	// Return final metadata for the object - include standard S3EP fields
	finalMetadata := make(map[string]string)
	for k, v := range state.Metadata {
		finalMetadata[k] = v
	}

	// Add standard S3EP metadata fields expected by decryption logic
	finalMetadata["s3ep-algorithm"] = "envelope-aes-256-ctr" // Use CTR for multipart
	finalMetadata["s3ep-data-algorithm"] = "aes-256-ctr"
	finalMetadata["s3ep-content-type"] = "multipart"
	finalMetadata["s3ep-provider"] = "aes-streaming"
	finalMetadata["s3ep-version"] = "1.0"

	// Copy the DEK from our custom metadata to standard field
	if dekValue, exists := state.Metadata["encryption-dek"]; exists {
		finalMetadata["s3ep-dek"] = dekValue
	}

	// Add legacy fields for compatibility
	finalMetadata["total-parts"] = fmt.Sprintf("%d", len(finalParts))
	finalMetadata["kek-fingerprint"] = state.KeyFingerprint
	finalMetadata["s3ep-kek-fingerprint"] = state.KeyFingerprint
	finalMetadata["s3ep-key-id"] = state.KeyFingerprint

	return finalMetadata, nil
}

// AbortMultipartUpload aborts a multipart upload and cleans up state
func (m *Manager) AbortMultipartUpload(ctx context.Context, uploadID string) error {
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
func (m *Manager) DecryptMultipartData(ctx context.Context, encryptedData, encryptedDEK []byte, metadata map[string]string, objectKey string, partNumber int) ([]byte, error) {
	// For multipart uploads, we need to handle streaming AES-CTR decryption with offsets

	// Extract IV from metadata
	ivBase64, exists := metadata["encryption-iv"]
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

// CreateStreamingDecryptionReader creates a streaming decryption reader for large objects
func (m *Manager) CreateStreamingDecryptionReader(ctx context.Context, encryptedReader io.ReadCloser, encryptedDEK []byte, metadata map[string]string, objectKey string, providerAlias string) (io.ReadCloser, error) {
	// Extract IV from metadata
	ivBase64, exists := metadata["encryption-iv"]
	if !exists {
		return nil, fmt.Errorf("missing IV in streaming multipart metadata")
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

	// Create streaming decryption reader
	reader := &streamingDecryptionReader{
		encryptedReader: encryptedReader,
		dek:             dek,
		iv:              iv,
		offset:          0,
		buffer:          make([]byte, 32*1024), // 32KB buffer for optimal performance
		bufferPos:       0,
		bufferLen:       0,
	}

	return reader, nil
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

	// Create decryptor only once on first use
	if r.decryptor == nil {
		r.decryptor, err = dataencryption.NewAESCTRStreamingDataEncryptorWithIV(r.dek, r.iv, r.offset)
		if err != nil {
			return fmt.Errorf("failed to create decryptor: %w", err)
		}
	}

	// Decrypt the chunk (AES-CTR decryption is same as encryption)
	// AES-CTR maintains internal state, so we can just call EncryptPart sequentially
	decryptedData, err := r.decryptor.EncryptPart(r.buffer[:n])
	if err != nil {
		return fmt.Errorf("failed to decrypt chunk: %w", err)
	}

	// Copy decrypted data back to buffer
	copy(r.buffer, decryptedData)
	r.bufferLen = len(decryptedData)
	r.bufferPos = 0
	if n > 0 { // Ensure positive value before conversion
		r.offset += uint64(n)
	}

	if err == io.EOF {
		return io.EOF
	}

	return nil
}

func (r *streamingDecryptionReader) Close() error {
	return r.encryptedReader.Close()
}

// encryptWithNoneProvider handles "none" provider - no encryption, no metadata
func (m *Manager) encryptWithNoneProvider(ctx context.Context, data []byte, objectKey string) (*encryption.EncryptionResult, error) {
	// "none" provider: return data as-is without any encryption or metadata
	result := &encryption.EncryptionResult{
		EncryptedData: data, // Pass through unencrypted
		EncryptedDEK:  nil,  // No DEK
		Metadata:      nil,  // No metadata at all
	}

	return result, nil
}

// decryptWithNoneProvider handles decryption with the "none" provider
func (m *Manager) decryptWithNoneProvider(ctx context.Context, encryptedData, encryptedDEK []byte, objectKey string) ([]byte, error) {
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
	algorithm := ""

	if metadata != nil {
		if kekAlg, exists := metadata["kek-algorithm"]; exists {
			algorithm = kekAlg
		}
		if dataAlg, exists := metadata["data-algorithm"]; exists && algorithm == "" {
			algorithm = dataAlg
		}

		// Infer KEK type from algorithm or other metadata
		if strings.Contains(algorithm, "aes") || strings.Contains(strings.ToLower(algorithm), "aes") {
			kekType = "aes"
		} else if strings.Contains(algorithm, "rsa") || strings.Contains(strings.ToLower(algorithm), "rsa") {
			kekType = "rsa"
		}
	}

	// List available KEK fingerprints for comparison
	availableKEKs := m.factory.GetRegisteredKeyEncryptors()

	return fmt.Errorf("❌ KEK_MISSING: Object '%s' requires KEK fingerprint '%s' (type: %s) but this KEK is not available in current keystore. Required: [%s], Available: %v. Algorithm: %s",
		objectKey, requiredFingerprint, kekType, requiredFingerprint, availableKEKs, algorithm)
}

// tryDecryptWithFingerprint attempts decryption with a specific KEK fingerprint
func (m *Manager) tryDecryptWithFingerprint(ctx context.Context, encryptedData, encryptedDEK []byte, associatedData []byte, fingerprint string) ([]byte, error) {
	algorithms := []string{"aes-256-gcm", "aes-256-ctr"}

	for _, algorithm := range algorithms {
		factoryMetadata := map[string]string{
			"kek-fingerprint": fingerprint,
			"data-algorithm":  algorithm,
		}

		plaintext, err := m.factory.DecryptData(ctx, encryptedData, encryptedDEK, factoryMetadata, associatedData)
		if err == nil {
			return plaintext, nil
		}
	}

	return nil, fmt.Errorf("failed to decrypt data with KEK fingerprint '%s'", fingerprint)
}

// tryDecryptWithAllKEKs attempts decryption with all available KEKs (legacy fallback)
func (m *Manager) tryDecryptWithAllKEKs(ctx context.Context, encryptedData, encryptedDEK []byte, associatedData []byte, objectKey string) ([]byte, error) {
	availableKEKs := m.factory.GetRegisteredKeyEncryptors()
	algorithms := []string{"aes-256-gcm", "aes-256-ctr"}

	// Try current active fingerprint first
	for _, algorithm := range algorithms {
		factoryMetadata := map[string]string{
			"kek-fingerprint": m.activeFingerprint,
			"data-algorithm":  algorithm,
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
				"data-algorithm":  algorithm,
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
