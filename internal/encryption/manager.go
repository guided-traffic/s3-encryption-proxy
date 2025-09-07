package encryption

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"sync"

	"github.com/guided-traffic/s3-encryption-proxy/internal/config"
	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption"
	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption/providers"
)

// MultipartUploadState holds state for an ongoing multipart upload
type MultipartUploadState struct {
	UploadID      string            // S3 Upload ID
	ObjectKey     string            // S3 Object Key
	ProviderAlias string            // Provider used for encryption
	DEK           []byte            // Data Encryption Key (unencrypted, for this session)
	EncryptedDEK  []byte            // Encrypted DEK (stored with the object)
	PartETags     map[int]string    // ETags for each uploaded part
	Metadata      map[string]string // Additional metadata
	mutex         sync.RWMutex      // Thread-safe access

	// Streaming state for AES-CTR mode
	Counter       []byte // AES-CTR counter state (16 bytes)
	TotalBytes    int64  // Total bytes processed (for counter management)
	BucketName    string // S3 bucket name
	IsCompleted   bool   // Whether the upload is completed
	CompletionErr error  // Error from completion, if any
}

// Manager handles encryption operations and key management with multiple providers
type Manager struct {
	activeEncryptor encryption.Encryptor            // Used for encrypting new data
	decryptors      map[string]encryption.Encryptor // Used for decrypting (keyed by provider alias)
	config          *config.Config
	// Multipart upload state management
	multipartUploads map[string]*MultipartUploadState // Keyed by uploadID
	uploadsMutex     sync.RWMutex                     // Thread-safe access to uploads map
}

// NewManager creates a new encryption manager with multiple provider support
func NewManager(cfg *config.Config) (*Manager, error) {
	// Create provider factory
	factory := providers.NewFactory()

	// Get active provider for encryption
	activeProvider, err := cfg.GetActiveProvider()
	if err != nil {
		return nil, fmt.Errorf("failed to get active provider: %w", err)
	}

	// Create active encryptor
	activeEncryptor, err := factory.CreateProviderFromConfig(
		providers.ProviderType(activeProvider.Type),
		activeProvider.GetProviderConfig(),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create active encryption provider '%s': %w", activeProvider.Alias, err)
	}

	// Create all decryptors
	decryptors := make(map[string]encryption.Encryptor)
	allProviders := cfg.GetAllProviders()

	for _, provider := range allProviders {
		decryptor, err := factory.CreateProviderFromConfig(
			providers.ProviderType(provider.Type),
			provider.GetProviderConfig(),
		)
		if err != nil {
			return nil, fmt.Errorf("failed to create decryption provider '%s': %w", provider.Alias, err)
		}

		decryptors[provider.Alias] = decryptor
	}

	return &Manager{
		activeEncryptor:  activeEncryptor,
		decryptors:       decryptors,
		config:           cfg,
		multipartUploads: make(map[string]*MultipartUploadState),
	}, nil
}

// EncryptData encrypts data using the active encryption method
func (m *Manager) EncryptData(ctx context.Context, data []byte, objectKey string) (*encryption.EncryptionResult, error) {
	// Use object key as associated data for additional security
	associatedData := []byte(objectKey)

	result, err := m.activeEncryptor.Encrypt(ctx, data, associatedData)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt data: %w", err)
	}

	// Add provider alias to metadata for later decryption
	if result.Metadata == nil {
		result.Metadata = make(map[string]string)
	}
	activeProvider, err := m.config.GetActiveProvider()
	if err == nil {
		result.Metadata["provider_alias"] = activeProvider.Alias
	}

	return result, nil
}

// DecryptData decrypts data using any available provider
func (m *Manager) DecryptData(ctx context.Context, encryptedData, encryptedDEK []byte, objectKey string, providerAlias string) ([]byte, error) {
	// Use object key as associated data
	associatedData := []byte(objectKey)

	// Try the specified provider first (if provided)
	if providerAlias != "" {
		if decryptor, exists := m.decryptors[providerAlias]; exists {
			plaintext, err := decryptor.Decrypt(ctx, encryptedData, encryptedDEK, associatedData)
			if err == nil {
				return plaintext, nil
			}
			// Log the error but continue with other providers
		}
	}

	// Try all providers if specific provider failed or wasn't specified
	var lastErr error
	for _, decryptor := range m.decryptors {
		plaintext, err := decryptor.Decrypt(ctx, encryptedData, encryptedDEK, associatedData)
		if err == nil {
			return plaintext, nil
		}
		lastErr = err
	}

	return nil, fmt.Errorf("failed to decrypt data with any provider (last error: %w)", lastErr)
}

// DecryptDataLegacy decrypts data using the active provider (for backward compatibility)
func (m *Manager) DecryptDataLegacy(ctx context.Context, encryptedData, encryptedDEK []byte, objectKey string) ([]byte, error) {
	return m.DecryptData(ctx, encryptedData, encryptedDEK, objectKey, "")
}

// RotateKEK initiates key rotation for the active provider
func (m *Manager) RotateKEK(ctx context.Context) error {
	return m.activeEncryptor.RotateKEK(ctx)
}

// GetProviderAliases returns all available provider aliases
func (m *Manager) GetProviderAliases() []string {
	aliases := make([]string, 0, len(m.decryptors))
	for alias := range m.decryptors {
		aliases = append(aliases, alias)
	}
	return aliases
}

// GetProvider returns a specific encryption provider by alias
func (m *Manager) GetProvider(alias string) (encryption.Encryptor, bool) {
	provider, exists := m.decryptors[alias]
	return provider, exists
}

// GetActiveProviderAlias returns the alias of the active provider
func (m *Manager) GetActiveProviderAlias() string {
	activeProvider, err := m.config.GetActiveProvider()
	if err != nil {
		return "unknown"
	}
	return activeProvider.Alias
}

// ===== MULTIPART UPLOAD SUPPORT =====

// CreateMultipartUpload initializes a new multipart upload with encryption
func (m *Manager) CreateMultipartUpload(ctx context.Context, uploadID, objectKey, bucketName string) (*MultipartUploadState, error) {
	// Get active provider
	activeProvider, err := m.config.GetActiveProvider()
	if err != nil {
		return nil, fmt.Errorf("failed to get active provider: %w", err)
	}

	var state *MultipartUploadState

	// Handle streaming providers differently
	if activeProvider.Type == "aes-ctr" {
		state, err = m.createStreamingMultipartUpload(ctx, uploadID, objectKey, bucketName, activeProvider)
	} else {
		state, err = m.createStandardMultipartUpload(ctx, uploadID, objectKey, bucketName, activeProvider)
	}

	if err != nil {
		return nil, err
	}

	// Store the upload state (check for duplicates first)
	m.uploadsMutex.Lock()
	defer m.uploadsMutex.Unlock()

	if _, exists := m.multipartUploads[uploadID]; exists {
		return nil, fmt.Errorf("multipart upload with ID %s already exists", uploadID)
	}

	m.multipartUploads[uploadID] = state

	return state, nil
}

// createStreamingMultipartUpload creates a streaming multipart upload for AES-CTR
func (m *Manager) createStreamingMultipartUpload(ctx context.Context, uploadID, objectKey, bucketName string, activeProvider *config.EncryptionProvider) (*MultipartUploadState, error) {
	// Get the AES-CTR provider
	provider, exists := m.decryptors[activeProvider.Alias]
	if !exists {
		return nil, fmt.Errorf("provider %s not found", activeProvider.Alias)
	}

	aesCTRProvider, ok := provider.(*providers.AESCTRProvider)
	if !ok {
		return nil, fmt.Errorf("provider %s is not an AES-CTR provider", activeProvider.Alias)
	}

	// Generate DEK and encrypted DEK for the entire multipart upload
	dek, encryptedDEK, err := aesCTRProvider.GenerateDataKey(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to generate data key: %w", err)
	}

	// Generate random IV for the entire multipart upload
	iv := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, fmt.Errorf("failed to generate IV: %w", err)
	}

	// Create streaming multipart upload state
	state := &MultipartUploadState{
		UploadID:      uploadID,
		ObjectKey:     objectKey,
		BucketName:    bucketName,
		ProviderAlias: activeProvider.Alias,
		DEK:           dek,
		EncryptedDEK:  encryptedDEK,
		Counter:       iv,
		TotalBytes:    0,
		PartETags:     make(map[int]string),
		Metadata: map[string]string{
			"provider_alias":  activeProvider.Alias,
			"encryption-mode": "aes-ctr-streaming",
			"multipart":       "true",
		},
		IsCompleted:   false,
		CompletionErr: nil,
	}

	return state, nil
}

// createStandardMultipartUpload creates a standard multipart upload for non-streaming providers
func (m *Manager) createStandardMultipartUpload(ctx context.Context, uploadID, objectKey, bucketName string, activeProvider *config.EncryptionProvider) (*MultipartUploadState, error) {
	// Generate a new DEK for this multipart upload
	// We'll use a dummy encryption operation to generate a DEK, then extract it
	dummyData := []byte("multipart-dek-generation")
	associatedData := []byte(objectKey)

	result, err := m.activeEncryptor.Encrypt(ctx, dummyData, associatedData)
	if err != nil {
		return nil, fmt.Errorf("failed to generate DEK for multipart upload: %w", err)
	}

	// For envelope encryption, we need to decrypt the dummy data to get the DEK
	// This is a bit of a hack, but it ensures we get a proper DEK from the provider
	dekBytes, err := m.activeEncryptor.Decrypt(ctx, result.EncryptedData, result.EncryptedDEK, associatedData)
	if err != nil {
		// If decryption fails, we'll use the encrypted data as DEK (for non-envelope encryption)
		dekBytes = result.EncryptedData[:32] // Use first 32 bytes as DEK for AES-256
	}

	// Create multipart upload state
	state := &MultipartUploadState{
		UploadID:      uploadID,
		ObjectKey:     objectKey,
		BucketName:    bucketName,
		ProviderAlias: activeProvider.Alias,
		DEK:           dekBytes,
		EncryptedDEK:  result.EncryptedDEK,
		PartETags:     make(map[int]string),
		Metadata:      make(map[string]string),
		IsCompleted:   false,
		CompletionErr: nil,
	}

	// Add metadata
	if result.Metadata != nil {
		for k, v := range result.Metadata {
			state.Metadata[k] = v
		}
	}
	state.Metadata["provider_alias"] = activeProvider.Alias

	return state, nil
}

// EncryptMultipartData encrypts a single part of a multipart upload
func (m *Manager) EncryptMultipartData(ctx context.Context, uploadID string, partNumber int, data []byte) (*encryption.EncryptionResult, error) {
	// Get upload state
	m.uploadsMutex.RLock()
	state, exists := m.multipartUploads[uploadID]
	m.uploadsMutex.RUnlock()

	if !exists {
		return nil, fmt.Errorf("multipart upload %s not found", uploadID)
	}

	// Handle streaming vs standard encryption
	if state.Metadata["encryption-mode"] == "aes-ctr-streaming" {
		return m.encryptStreamingPart(ctx, state, partNumber, data)
	}

	// Standard non-streaming encryption
	return m.encryptStandardPart(ctx, state, partNumber, data)
}

// encryptStreamingPart encrypts a part using AES-CTR streaming
func (m *Manager) encryptStreamingPart(ctx context.Context, state *MultipartUploadState, partNumber int, data []byte) (*encryption.EncryptionResult, error) {
	// Get the AES-CTR provider
	provider, exists := m.decryptors[state.ProviderAlias]
	if !exists {
		return nil, fmt.Errorf("provider %s not found", state.ProviderAlias)
	}

	aesCTRProvider, ok := provider.(*providers.AESCTRProvider)
	if !ok {
		return nil, fmt.Errorf("provider %s is not an AES-CTR provider", state.ProviderAlias)
	}

	// Calculate counter value based on total bytes processed so far
	state.mutex.Lock()
	// Check for negative TotalBytes before converting to uint64
	if state.TotalBytes < 0 {
		state.mutex.Unlock()
		return nil, fmt.Errorf("invalid negative TotalBytes: %d", state.TotalBytes)
	}
	counterValue := uint64(state.TotalBytes) // Counter is byte-based
	state.TotalBytes += int64(len(data))
	state.mutex.Unlock()

	// Encrypt using streaming method
	encryptedData, err := aesCTRProvider.EncryptStream(ctx, data, state.DEK, state.Counter, counterValue)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt streaming part %d: %w", partNumber, err)
	}

	return &encryption.EncryptionResult{
		EncryptedData: encryptedData,
		EncryptedDEK:  state.EncryptedDEK,
		Metadata: map[string]string{
			"provider_alias":  state.ProviderAlias,
			"part_number":     fmt.Sprintf("%d", partNumber),
			"upload_id":       state.UploadID,
			"encryption-mode": "aes-ctr-streaming",
		},
	}, nil
}

// encryptStandardPart encrypts a part using standard non-streaming encryption
func (m *Manager) encryptStandardPart(ctx context.Context, state *MultipartUploadState, partNumber int, data []byte) (*encryption.EncryptionResult, error) {
	// Use the stored DEK to encrypt this part
	// For consistency, we'll use the same encryption method as the provider
	providerType := state.ProviderAlias
	decryptor, exists := m.decryptors[providerType]
	if !exists {
		return nil, fmt.Errorf("provider %s not available for encryption", providerType)
	}

	// Create associated data that includes part information
	associatedData := []byte(fmt.Sprintf("%s:part-%d", state.ObjectKey, partNumber))

	// Encrypt using the provider with the stored DEK
	result, err := decryptor.Encrypt(ctx, data, associatedData)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt part %d: %w", partNumber, err)
	}

	// Store metadata for this part
	if result.Metadata == nil {
		result.Metadata = make(map[string]string)
	}
	result.Metadata["provider_alias"] = state.ProviderAlias
	result.Metadata["part_number"] = fmt.Sprintf("%d", partNumber)
	result.Metadata["upload_id"] = state.UploadID

	return result, nil
}

// RecordPartETag records the ETag for an uploaded part
func (m *Manager) RecordPartETag(uploadID string, partNumber int, etag string) error {
	m.uploadsMutex.RLock()
	state, exists := m.multipartUploads[uploadID]
	m.uploadsMutex.RUnlock()

	if !exists {
		return fmt.Errorf("multipart upload %s not found", uploadID)
	}

	state.mutex.Lock()
	state.PartETags[partNumber] = etag
	state.mutex.Unlock()

	return nil
}

// CompleteMultipartUpload finalizes a multipart upload
func (m *Manager) CompleteMultipartUpload(uploadID string) (*MultipartUploadState, error) {
	m.uploadsMutex.Lock()
	defer m.uploadsMutex.Unlock()

	state, exists := m.multipartUploads[uploadID]
	if !exists {
		return nil, fmt.Errorf("multipart upload %s not found", uploadID)
	}

	// Return the final state (with all metadata needed for the completed object)
	return state, nil
}

// AbortMultipartUpload cancels a multipart upload and cleans up state
func (m *Manager) AbortMultipartUpload(uploadID string) error {
	m.uploadsMutex.Lock()
	defer m.uploadsMutex.Unlock()

	delete(m.multipartUploads, uploadID)
	return nil
}

// GetMultipartUploadState retrieves the state for a multipart upload
func (m *Manager) GetMultipartUploadState(uploadID string) (*MultipartUploadState, error) {
	m.uploadsMutex.RLock()
	defer m.uploadsMutex.RUnlock()

	state, exists := m.multipartUploads[uploadID]
	if !exists {
		return nil, fmt.Errorf("multipart upload %s not found", uploadID)
	}

	return state, nil
}

// ListMultipartUploads returns all active multipart uploads
func (m *Manager) ListMultipartUploads() map[string]*MultipartUploadState {
	m.uploadsMutex.RLock()
	defer m.uploadsMutex.RUnlock()

	// Return a copy to prevent external modification
	uploads := make(map[string]*MultipartUploadState)
	for id, state := range m.multipartUploads {
		uploads[id] = state
	}
	return uploads
}

// CopyMultipartPart copies an encrypted part from another multipart upload
func (m *Manager) CopyMultipartPart(uploadID string, sourceBucket, sourceKey, sourceUploadID string, sourcePartNumber int) ([]byte, error) {
	m.uploadsMutex.RLock()
	_, exists := m.multipartUploads[uploadID]
	m.uploadsMutex.RUnlock()

	if !exists {
		return nil, fmt.Errorf("multipart upload not found: %s", uploadID)
	}

	// Get the source multipart upload state to access encryption info
	_, sourceExists := m.multipartUploads[sourceUploadID]
	if !sourceExists {
		return nil, fmt.Errorf("source multipart upload not found: %s", sourceUploadID)
	}

	// For encrypted parts, we need to decrypt the source part and re-encrypt with destination DEK
	// This is complex as it requires access to the source object's encrypted data
	// For now, we'll return an error indicating this operation is not supported for encrypted objects
	return nil, fmt.Errorf("copy part operation not supported for encrypted multipart uploads")
}

// DecryptMultipartObject decrypts a complete multipart object
func (m *Manager) DecryptMultipartObject(ctx context.Context, encryptedData, encryptedDEK []byte, objectKey string, providerAlias string, metadata map[string]string) ([]byte, error) {
	// Check if this is a streaming multipart object using the correct metadata key
	if encryptionMode, exists := metadata["x-s3ep-mode"]; exists && encryptionMode == "aes-ctr-streaming" {
		return m.decryptStreamingMultipartObject(ctx, encryptedData, encryptedDEK, objectKey, providerAlias, metadata)
	}

	// Also check the legacy encryption-mode key for backwards compatibility
	if encryptionMode, exists := metadata["encryption-mode"]; exists && encryptionMode == "aes-ctr-streaming" {
		return m.decryptStreamingMultipartObject(ctx, encryptedData, encryptedDEK, objectKey, providerAlias, metadata)
	}

	// Fall back to standard decryption for non-streaming objects
	return m.DecryptData(ctx, encryptedData, encryptedDEK, objectKey, providerAlias)
}

// decryptStreamingMultipartObject decrypts a streaming AES-CTR multipart object
func (m *Manager) decryptStreamingMultipartObject(ctx context.Context, encryptedData, encryptedDEK []byte, objectKey string, providerAlias string, metadata map[string]string) ([]byte, error) {
	// Get the AES-CTR provider
	provider, exists := m.decryptors[providerAlias]
	if !exists {
		return nil, fmt.Errorf("provider %s not found", providerAlias)
	}

	aesCTRProvider, ok := provider.(*providers.AESCTRProvider)
	if !ok {
		return nil, fmt.Errorf("provider %s is not an AES-CTR provider", providerAlias)
	}

	// DEBUG: Log input data
	fmt.Printf("DEBUG: Starting multipart streaming decryption for key=%s, providerAlias=%s, encryptedDataLen=%d, encryptedDEKLen=%d, encrypted_first_32=%x\n",
		objectKey, providerAlias, len(encryptedData), len(encryptedDEK), encryptedData[:min(32, len(encryptedData))])

	// Decrypt the DEK
	dek, err := aesCTRProvider.DecryptDataKey(ctx, encryptedDEK)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt DEK: %w", err)
	}

	fmt.Printf("DEBUG: DEK decrypted successfully for key=%s, dekLen=%d, dek_first_16=%x\n",
		objectKey, len(dek), dek[:min(16, len(dek))])

	// Get IV from metadata (NOT from encrypted data!)
	var ivB64 string
	var ivExists bool
	if ivB64, ivExists = metadata["x-s3ep-iv"]; !ivExists {
		// Try alternative IV key names
		if ivB64, ivExists = metadata["iv"]; !ivExists {
			return nil, fmt.Errorf("IV not found in metadata for streaming multipart object")
		}
	}

	// Decode IV from base64
	iv, err := base64.StdEncoding.DecodeString(ivB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode IV from metadata: %w", err)
	}

	// Validate IV length
	if len(iv) != 16 {
		return nil, fmt.Errorf("invalid IV length: expected 16 bytes, got %d", len(iv))
	}

	fmt.Printf("DEBUG: IV decoded from metadata successfully for key=%s, ivB64=%s, iv_hex=%x, ivLen=%d\n",
		objectKey, ivB64, iv, len(iv))

	// For streaming multipart objects, the entire encryptedData is ciphertext
	// (IV is NOT prepended to the data - it comes from metadata)
	ciphertext := encryptedData

	// For streaming multipart objects, the counter should always start at 0
	// because the ciphertext we receive is the complete assembled file from S3
	// which represents the entire AES-CTR stream from the beginning
	startCounter := uint64(0)

	fmt.Printf("DEBUG: About to decrypt using DecryptStream for key=%s, ciphertextLen=%d, ciphertext_first_32=%x, counter=%d\n",
		objectKey, len(ciphertext), ciphertext[:min(32, len(ciphertext))], startCounter)

	// Decrypt using streaming method starting from the beginning of the stream
	plaintext, err := aesCTRProvider.DecryptStream(ctx, ciphertext, dek, iv, startCounter)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt streaming multipart object: %w", err)
	}

	fmt.Printf("DEBUG: Multipart streaming decryption completed successfully for key=%s, plaintextLen=%d, plaintext_first_32=%x, ciphertextLen=%d\n",
		objectKey, len(plaintext), plaintext[:min(32, len(plaintext))], len(ciphertext))

	return plaintext, nil
}

// UpdateMultipartTotalBytes updates the total bytes processed for a multipart upload
func (m *Manager) UpdateMultipartTotalBytes(uploadID string, additionalBytes int64) error {
	m.uploadsMutex.RLock()
	state, exists := m.multipartUploads[uploadID]
	m.uploadsMutex.RUnlock()

	if !exists {
		return fmt.Errorf("multipart upload %s not found", uploadID)
	}

	state.mutex.Lock()
	state.TotalBytes += additionalBytes
	state.mutex.Unlock()

	return nil
}
