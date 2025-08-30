package encryption

import (
	"context"
	"fmt"

	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/keyset"
	"github.com/guided-traffic/s3-encryption-proxy/pkg/envelope"
)

// Manager handles encryption operations and key management
type Manager struct {
	encryptor envelope.Encryptor
	config    *Config
}

// Config holds encryption configuration
type Config struct {
	KEKUri          string
	CredentialsPath string
	Algorithm       string
	KeyRotationDays int
}

// NewManager creates a new encryption manager
func NewManager(cfg *Config) (*Manager, error) {
	// Load KEK handle (this would typically come from a KMS)
	kekHandle, err := loadKEKHandle(cfg.KEKUri, cfg.CredentialsPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load KEK handle: %w", err)
	}

	// Create encryptor
	encryptor, err := envelope.NewTinkEncryptor(kekHandle, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create encryptor: %w", err)
	}

	return &Manager{
		encryptor: encryptor,
		config:    cfg,
	}, nil
}

// EncryptData encrypts data using envelope encryption
func (m *Manager) EncryptData(ctx context.Context, data []byte, objectKey string) (*envelope.EncryptionResult, error) {
	// Use object key as associated data for additional security
	associatedData := []byte(objectKey)

	result, err := m.encryptor.Encrypt(ctx, data, associatedData)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt data: %w", err)
	}

	return result, nil
}

// DecryptData decrypts data using envelope encryption
func (m *Manager) DecryptData(ctx context.Context, encryptedData, encryptedDEK []byte, objectKey string) ([]byte, error) {
	// Use object key as associated data
	associatedData := []byte(objectKey)

	plaintext, err := m.encryptor.Decrypt(ctx, encryptedData, encryptedDEK, associatedData)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data: %w", err)
	}

	return plaintext, nil
}

// RotateKEK initiates key rotation
func (m *Manager) RotateKEK(ctx context.Context) error {
	return m.encryptor.RotateKEK(ctx)
}

// loadKEKHandle loads the Key Encryption Key handle from the specified URI
func loadKEKHandle(kekUri, credentialsPath string) (*keyset.Handle, error) {
	// This is a simplified implementation
	// In a real scenario, this would:
	// 1. Parse the KEK URI to determine the KMS provider (AWS KMS, GCP KMS, etc.)
	// 2. Initialize the appropriate KMS client
	// 3. Load the KEK from the KMS

	// For now, we'll create a local handle for testing
	// In production, this should use a proper KMS
	handle, err := keyset.NewHandle(aead.AES256GCMKeyTemplate())
	if err != nil {
		return nil, fmt.Errorf("failed to create local KEK handle: %w", err)
	}

	return handle, nil
}
