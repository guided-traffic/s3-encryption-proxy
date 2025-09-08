package factory

import (
    "context"
    "fmt"

    "github.com/guided-traffic/s3-encryption-proxy/pkg/encryption"
    "github.com/guided-traffic/s3-encryption-proxy/pkg/encryption/dataencryption"
    "github.com/guided-traffic/s3-encryption-proxy/pkg/encryption/envelope"
    "github.com/guided-traffic/s3-encryption-proxy/pkg/encryption/keyencryption"
)

// ContentType represents how the client sends data to us
type ContentType string

const (
    ContentTypeMultipart ContentType = "multipart" // Client sends chunks/multipart -> use AES-CTR
    ContentTypeWhole     ContentType = "whole"     // Client sends whole files -> use AES-GCM
)

// KeyEncryptionType represents the type of key encryption to use
type KeyEncryptionType string

const (
    KeyEncryptionTypeAES KeyEncryptionType = "aes"
    KeyEncryptionTypeRSA KeyEncryptionType = "rsa"
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

// CreateEnvelopeEncryptor creates an envelope encryptor based on content type and key encryption type
func (f *Factory) CreateEnvelopeEncryptor(contentType ContentType, keyFingerprint string) (encryption.EnvelopeEncryptor, error) {
    // Find the key encryptor by fingerprint
    keyEncryptor, exists := f.keyEncryptors[keyFingerprint]
    if !exists {
        return nil, fmt.Errorf("key encryptor with fingerprint %s not found", keyFingerprint)
    }

    // Choose data encryptor based on content type
    var dataEncryptor encryption.DataEncryptor
    switch contentType {
    case ContentTypeMultipart:
        // For multipart/chunks, use AES-CTR (stream-friendly)
        dataEncryptor = dataencryption.NewAESCTRDataEncryptor()
    case ContentTypeWhole:
        // For whole files, use AES-GCM (authenticated encryption)
        dataEncryptor = dataencryption.NewAESGCMDataEncryptor()
    default:
        return nil, fmt.Errorf("unsupported content type: %s", contentType)
    }

    // Create envelope encryptor
    return envelope.NewEnvelopeEncryptor(keyEncryptor, dataEncryptor), nil
}

// CreateKeyEncryptorFromConfig creates a key encryptor from configuration
func (f *Factory) CreateKeyEncryptorFromConfig(keyType KeyEncryptionType, config map[string]interface{}) (encryption.KeyEncryptor, error) {
    switch keyType {
    case KeyEncryptionTypeAES:
        return f.createAESKeyEncryptor(config)
    case KeyEncryptionTypeRSA:
        return f.createRSAKeyEncryptor(config)
    default:
        return nil, fmt.Errorf("unsupported key encryption type: %s", keyType)
    }
}

// DecryptData decrypts data using metadata to find the correct encryptors
func (f *Factory) DecryptData(ctx context.Context, encryptedData []byte, encryptedDEK []byte, metadata map[string]string, associatedData []byte) ([]byte, error) {
    // Extract metadata
    keyFingerprint, exists := metadata["kek_fingerprint"]
    if !exists {
        return nil, fmt.Errorf("missing kek_fingerprint in metadata")
    }

    dataAlgorithm, exists := metadata["data_algorithm"]
    if !exists {
        return nil, fmt.Errorf("missing data_algorithm in metadata")
    }

    // Find key encryptor
    keyEncryptor, exists := f.keyEncryptors[keyFingerprint]
    if !exists {
        return nil, fmt.Errorf("key encryptor with fingerprint %s not found", keyFingerprint)
    }

	// Create data encryptor based on algorithm
	var dataEncryptor encryption.DataEncryptor
	switch dataAlgorithm {
	case "aes-ctr", "aes-256-ctr":
		dataEncryptor = dataencryption.NewAESCTRDataEncryptor()
	case "aes-gcm", "aes-256-gcm":
		dataEncryptor = dataencryption.NewAESGCMDataEncryptor()
	default:
		return nil, fmt.Errorf("unsupported data algorithm: %s", dataAlgorithm)
	}    // Create envelope encryptor for decryption
    envelopeEncryptor := envelope.NewEnvelopeEncryptor(keyEncryptor, dataEncryptor)

    // Decrypt the data
    return envelopeEncryptor.DecryptData(ctx, encryptedData, encryptedDEK, associatedData)
}

// Helper methods for creating key encryptors

func (f *Factory) createAESKeyEncryptor(config map[string]interface{}) (encryption.KeyEncryptor, error) {
    // Check for direct KEK provision
    if kekInterface, exists := config["kek"]; exists {
        kekBytes, ok := kekInterface.([]byte)
        if !ok {
            return nil, fmt.Errorf("kek must be []byte for AES key encryptor")
        }
        return keyencryption.NewAESKeyEncryptor(kekBytes)
    }

    // Check for config-based creation with key name translation
    // The configuration uses "aes_key", but NewAESProvider expects "key"
    configCopy := make(map[string]interface{})
    for k, v := range config {
        configCopy[k] = v
    }

    // Translate "aes_key" to "key" for the provider
    if aesKey, exists := config["aes_key"]; exists {
        configCopy["key"] = aesKey
        delete(configCopy, "aes_key") // Remove the old key to avoid confusion
    }

    return keyencryption.NewAESProvider(configCopy)
}

func (f *Factory) createRSAKeyEncryptor(config map[string]interface{}) (encryption.KeyEncryptor, error) {
    // Extract public and private key PEMs
    publicKeyPEM, exists := config["public_key_pem"]
    if !exists {
        return nil, fmt.Errorf("public_key_pem is required for RSA key encryptor")
    }

    privateKeyPEM, exists := config["private_key_pem"]
    if !exists {
        return nil, fmt.Errorf("private_key_pem is required for RSA key encryptor")
    }

    publicKeyPEMStr, ok := publicKeyPEM.(string)
    if !ok {
        return nil, fmt.Errorf("public_key_pem must be a string")
    }

    privateKeyPEMStr, ok := privateKeyPEM.(string)
    if !ok {
        return nil, fmt.Errorf("private_key_pem must be a string")
    }

    return keyencryption.NewRSAProviderFromPEM(publicKeyPEMStr, privateKeyPEMStr)
}

// GetRegisteredKeyEncryptors returns a list of all registered key encryptor fingerprints
func (f *Factory) GetRegisteredKeyEncryptors() []string {
    fingerprints := make([]string, 0, len(f.keyEncryptors))
    for fingerprint := range f.keyEncryptors {
        fingerprints = append(fingerprints, fingerprint)
    }
    return fingerprints
}
