package factory

import (
	"fmt"

	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption"
	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption/keyencryption"
)

// KeyEncryptionType represents the type of key encryption to use
type KeyEncryptionType string

const (
	KeyEncryptionTypeAES  KeyEncryptionType = "aes"
	KeyEncryptionTypeExit KeyEncryptionType = "exit"
)

// Factory creates encryption providers based on configuration
type Factory struct {
	keyEncryptors map[string]encryption.KeyEncryptor // Keyed by fingerprint
}

// NewFactory creates a new provider factory
func NewFactory() *Factory {
	return &Factory{
		keyEncryptors: make(map[string]encryption.KeyEncryptor),
	}
}

// RegisterKeyEncryptor registers a key encryptor for use in envelope encryption
func (f *Factory) RegisterKeyEncryptor(keyEncryptor encryption.KeyEncryptor) {
	fingerprint := keyEncryptor.Fingerprint()
	f.keyEncryptors[fingerprint] = keyEncryptor
}

// GetKeyEncryptor retrieves a registered key encryptor by fingerprint
func (f *Factory) GetKeyEncryptor(fingerprint string) (encryption.KeyEncryptor, error) {
	keyEncryptor, exists := f.keyEncryptors[fingerprint]
	if !exists {
		return nil, fmt.Errorf("key encryptor with fingerprint '%s' not found", fingerprint)
	}
	return keyEncryptor, nil
}

// CreateKeyEncryptorFromConfig creates a key encryptor from configuration
func (f *Factory) CreateKeyEncryptorFromConfig(keyType KeyEncryptionType, config map[string]interface{}) (encryption.KeyEncryptor, error) {
	switch keyType {
	case KeyEncryptionTypeAES:
		return f.createAESKeyEncryptor(config)
	case KeyEncryptionTypeExit:
		return f.createExitKeyEncryptor(config)
	default:
		return nil, fmt.Errorf("unsupported key encryption type: %s", keyType)
	}
}

// Helper methods for creating key encryptors

func (f *Factory) createAESKeyEncryptor(config map[string]interface{}) (encryption.KeyEncryptor, error) {
	// aes_key is the only key this provider reads, and since 5.0.0 the loader
	// refuses a config block that carries anything else. A caller holding raw key
	// bytes calls keyencryption.NewAESKeyEncryptor directly.
	return keyencryption.NewAESProvider(config)
}

func (f *Factory) createExitKeyEncryptor(config map[string]interface{}) (encryption.KeyEncryptor, error) {
	// The exit provider takes no configuration.
	return keyencryption.NewExitProvider(config)
}
