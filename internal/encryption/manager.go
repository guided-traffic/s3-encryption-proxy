package encryption

import (
	"context"
	"fmt"
	"sync"

	"github.com/guided-traffic/s3-encryption-proxy/internal/config"
	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption"
	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption/factory"
)

// MultipartUploadState holds state for an ongoing multipart upload
type MultipartUploadState struct {
	UploadID         string                       // S3 Upload ID
	ObjectKey        string                       // S3 Object Key
	BucketName       string                       // S3 bucket name
	KeyFingerprint   string                       // Fingerprint of key encryptor used
	ContentType      factory.ContentType          // Content type for algorithm selection
	EnvelopeEncryptor encryption.EnvelopeEncryptor // Shared encryptor for all parts
	PartETags        map[int]string               // ETags for each uploaded part
	Metadata         map[string]string            // Additional metadata
	IsCompleted      bool                         // Whether the upload is completed
	CompletionErr    error                        // Error from completion, if any
	mutex            sync.RWMutex                 // Thread-safe access
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
	// Use object key as associated data
	associatedData := []byte(objectKey)

	// Try both algorithms since we don't have the metadata from encryption
	algorithms := []string{"aes-256-gcm", "aes-256-ctr"}

	for _, algorithm := range algorithms {
		metadata := map[string]string{
			"kek_fingerprint": m.activeFingerprint,
			"data_algorithm":  algorithm,
		}

		// Try to decrypt using the factory's DecryptData method
		plaintext, err := m.factory.DecryptData(ctx, encryptedData, encryptedDEK, metadata, associatedData)
		if err == nil {
			return plaintext, nil
		}
	}

	return nil, fmt.Errorf("failed to decrypt data with any algorithm")
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

	// Add provider alias for backward compatibility
	activeProvider, err := m.config.GetActiveProvider()
	if err == nil {
		state.Metadata["provider_alias"] = activeProvider.Alias
	}

	m.multipartUploads[uploadID] = state

	return nil
}

// UploadPart encrypts and uploads a part of a multipart upload
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

	// Create associated data that includes part information for additional security
	associatedData := []byte(fmt.Sprintf("%s:part-%d:upload-%s", state.ObjectKey, partNumber, uploadID))

	// Encrypt the part using the shared envelope encryptor
	encryptedData, encryptedDEK, metadata, err := state.EnvelopeEncryptor.EncryptData(ctx, data, associatedData)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt part %d: %w", partNumber, err)
	}

	// Create encryption result
	result := &encryption.EncryptionResult{
		EncryptedData: encryptedData,
		EncryptedDEK:  encryptedDEK,
		Metadata:      make(map[string]string),
	}

	// Merge metadata from encryption
	for k, v := range metadata {
		result.Metadata[k] = v
	}

	// Add part-specific metadata
	result.Metadata["part_number"] = fmt.Sprintf("%d", partNumber)
	result.Metadata["upload_id"] = uploadID
	result.Metadata["encryption_mode"] = "multipart_part"

	// Copy upload metadata
	for k, v := range state.Metadata {
		if k != "encryption_mode" { // Don't overwrite part-specific mode
			result.Metadata[k] = v
		}
	}

	return result, nil
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

	// Store part ETags
	for partNumber, etag := range parts {
		state.PartETags[partNumber] = etag
	}

	// Mark as completed
	state.IsCompleted = true

	// Return final metadata for the object
	finalMetadata := make(map[string]string)
	for k, v := range state.Metadata {
		finalMetadata[k] = v
	}
	finalMetadata["encryption_mode"] = "multipart_completed"
	finalMetadata["total_parts"] = fmt.Sprintf("%d", len(parts))

	// Add fingerprint for decryption
	finalMetadata["kek_fingerprint"] = state.KeyFingerprint
	finalMetadata["envelope_fingerprint"] = state.EnvelopeEncryptor.Fingerprint()

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
