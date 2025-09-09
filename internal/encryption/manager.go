package encryption

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
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
	Metadata           map[string]string                               // Additional metadata
	IsCompleted        bool                                            // Whether the upload is completed
	CompletionErr      error                                           // Error from completion, if any
	mutex              sync.RWMutex                                    // Thread-safe access
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
		// Map old provider types to new key encryption types
		var keyType factory.KeyEncryptionType
		switch provider.Type {
		case "aes-gcm", "aes-ctr":
			keyType = factory.KeyEncryptionTypeAES
		case "rsa":
			keyType = factory.KeyEncryptionTypeRSA
		case "none":
			// Skip "none" provider for now - it doesn't use key encryption
			continue
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

	// Add provider information for backward compatibility
	activeProvider, err := m.config.GetActiveProvider()
	if err == nil {
		encResult.Metadata["provider_alias"] = activeProvider.Alias
	}

	// Add content type information
	encResult.Metadata["content_type"] = string(contentType)

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
	// Check if this is a streaming AES-CTR multipart object
	if metadata != nil {
		if algorithm, exists := metadata["data_algorithm"]; exists && algorithm == "aes-256-ctr" {
			if encMode, hasMode := metadata["encryption_mode"]; hasMode && encMode == "multipart" {
				// This is a streaming AES-CTR multipart object
				return m.decryptStreamingMultipartObject(ctx, encryptedData, encryptedDEK, metadata, objectKey)
			}
		}
	}

	// Use object key as associated data for regular decryption
	associatedData := []byte(objectKey)

	// Try both algorithms since we don't have the metadata from encryption
	algorithms := []string{"aes-256-gcm", "aes-256-ctr"}

	for _, algorithm := range algorithms {
		factoryMetadata := map[string]string{
			"kek_fingerprint": m.activeFingerprint,
			"data_algorithm":  algorithm,
		}

		// Try to decrypt using the factory's DecryptData method
		plaintext, err := m.factory.DecryptData(ctx, encryptedData, encryptedDEK, factoryMetadata, associatedData)
		if err == nil {
			return plaintext, nil
		}
	}

	return nil, fmt.Errorf("failed to decrypt data with any algorithm")
}

// decryptStreamingMultipartObject decrypts a completed multipart object that was encrypted with streaming AES-CTR
func (m *Manager) decryptStreamingMultipartObject(ctx context.Context, encryptedData, encryptedDEK []byte, metadata map[string]string, objectKey string) ([]byte, error) {
	// Extract IV from metadata
	ivBase64, exists := metadata["x-amz-meta-encryption-iv"]
	if !exists {
		return nil, fmt.Errorf("missing IV in streaming multipart metadata")
	}

	iv, err := base64.StdEncoding.DecodeString(ivBase64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode IV: %w", err)
	}

	// Decrypt the DEK using the key encryptor
	keyEncryptor, err := m.factory.GetKeyEncryptor(m.activeFingerprint)
	if err != nil {
		return nil, fmt.Errorf("failed to get key encryptor: %w", err)
	}

	dek, err := keyEncryptor.DecryptDEK(ctx, encryptedDEK, m.activeFingerprint)
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
		offset += uint64(partSize)
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

// ===== MULTIPART UPLOAD SUPPORT =====

// InitiateMultipartUpload creates a new multipart upload state
func (m *Manager) InitiateMultipartUpload(ctx context.Context, uploadID, objectKey, bucketName string) error {
	m.uploadsMutex.Lock()
	defer m.uploadsMutex.Unlock()

	// Check if upload already exists
	if _, exists := m.multipartUploads[uploadID]; exists {
		return fmt.Errorf("multipart upload %s already exists", uploadID)
	}

	// For multipart uploads, always use AES-CTR (streaming-friendly)
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
		Metadata: map[string]string{
			"kek_fingerprint":      m.activeFingerprint,
			"data_algorithm":       "aes-256-ctr", // Always CTR for multipart
			"encryption_mode":      "multipart",
			"upload_id":           uploadID,
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

	fmt.Printf("DEBUG: CreateMultipartUpload - IV: %x, DEK: %x\n", iv, dek)

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
	state.Metadata["x-amz-meta-encryption-dek"] = base64.StdEncoding.EncodeToString(encryptedDEK)
	state.Metadata["x-amz-meta-encryption-iv"] = base64.StdEncoding.EncodeToString(iv)

	// Add provider alias for backward compatibility
	activeProvider, err := m.config.GetActiveProvider()
	if err == nil {
		state.Metadata["provider_alias"] = activeProvider.Alias
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

	// Add debug output for IV
	fmt.Printf("DEBUG: UploadPart - upload %s IV hex: %x\n", uploadID, state.StreamingEncryptor.GetIV())

	// Use streaming encryptor to encrypt the part with continuous counter state
	state.mutex.Lock()
	defer state.mutex.Unlock()

	// Calculate the offset for this part based on total data processed so far
	// This ensures we don't have issues with multiple calls to the same part
	totalProcessed := uint64(0)
	for i := 1; i < partNumber; i++ {
		// Assume each part (except possibly the last) is 5MB
		// This is a simplification - in a real system you'd track actual part sizes
		totalProcessed += 5242880 // 5MB standard part size
	}

	// Create a new streaming encryptor for this specific part with the correct offset
	partEncryptor, err := dataencryption.NewAESCTRStreamingDataEncryptorWithIV(state.DEK, state.StreamingEncryptor.GetIV(), totalProcessed)
	if err != nil {
		return nil, fmt.Errorf("failed to create part encryptor for part %d: %w", partNumber, err)
	}

	// Encrypt the part using the part-specific encryptor
	encryptedData, err := partEncryptor.EncryptPart(data)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt part %d with streaming encryption: %w", partNumber, err)
	}

	fmt.Printf("DEBUG: Encrypted part %d: %d -> %d bytes with offset %d\n", partNumber, len(data), len(encryptedData), totalProcessed)

	// Add debug for first 32 bytes of encrypted output
	fmt.Printf("DEBUG: UploadPart - part %d encrypted first 32 bytes: %x\n", partNumber, encryptedData[:min(32, len(encryptedData))])

	// Create encryption result - use the pre-computed encrypted DEK from state
	encryptedDEK, err := base64.StdEncoding.DecodeString(state.Metadata["x-amz-meta-encryption-dek"])
	if err != nil {
		return nil, fmt.Errorf("failed to decode encrypted DEK from state: %w", err)
	}

	result := &encryption.EncryptionResult{
		EncryptedData: encryptedData,
		EncryptedDEK:  encryptedDEK,
		Metadata:      make(map[string]string),
	}

	// For the first part, include all the metadata needed for decryption
	if partNumber == 1 {
		// Copy metadata from upload state to the first part
		for k, v := range state.Metadata {
			result.Metadata[k] = v
		}
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
	finalParts := parts
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

	// Clean up the upload state from memory to prevent memory leaks
	defer func() {
		delete(m.multipartUploads, uploadID)
	}()

	// Return final metadata for the object - include standard S3EP fields
	finalMetadata := make(map[string]string)
	for k, v := range state.Metadata {
		finalMetadata[k] = v
	}

	// Add standard S3EP metadata fields expected by decryption logic
	finalMetadata["s3ep-algorithm"] = "envelope-aes-256-ctr" // Use CTR for multipart
	finalMetadata["s3ep-data_algorithm"] = "aes-256-ctr"
	finalMetadata["s3ep-content_type"] = "multipart"
	finalMetadata["s3ep-provider"] = "aes-streaming"
	finalMetadata["s3ep-version"] = "1.0"

	// Copy the DEK from our custom metadata to standard field
	if dekValue, exists := state.Metadata["x-amz-meta-encryption-dek"]; exists {
		finalMetadata["s3ep-dek"] = dekValue
	}

	// Add legacy fields for compatibility
	finalMetadata["encryption_mode"] = "multipart_completed"
	finalMetadata["total_parts"] = fmt.Sprintf("%d", len(finalParts))
	finalMetadata["kek_fingerprint"] = state.KeyFingerprint
	finalMetadata["s3ep-kek_fingerprint"] = state.KeyFingerprint
	finalMetadata["s3ep-key_id"] = state.KeyFingerprint

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
	// Extract upload ID and create associated data to match encryption
	uploadID, exists := metadata["upload_id"]
	if !exists {
		return nil, fmt.Errorf("missing upload_id in metadata for multipart decryption")
	}

	// Recreate the same associated data used during encryption
	associatedData := []byte(fmt.Sprintf("%s:part-%d:upload-%s", objectKey, partNumber, uploadID))

	// Use factory for decryption with proper metadata
	plaintext, err := m.factory.DecryptData(ctx, encryptedData, encryptedDEK, metadata, associatedData)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt multipart data: %w", err)
	}

	return plaintext, nil
}
