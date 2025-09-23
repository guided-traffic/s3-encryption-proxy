package factory

import (
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

// Special Content-Type values for forcing specific encryption modes
const (
	// Force AES-GCM envelope encryption (small overhead, authenticated encryption)
	ForceAESGCMContentType = "application/x-s3ep-force-aes-gcm"

	// Force AES-CTR streaming encryption (no overhead, streaming-friendly)
	ForceAESCTRContentType = "application/x-s3ep-force-aes-ctr"
)

// KeyEncryptionType represents the type of key encryption to use
type KeyEncryptionType string

const (
	KeyEncryptionTypeAES  KeyEncryptionType = "aes"
	KeyEncryptionTypeRSA  KeyEncryptionType = "rsa"
	KeyEncryptionTypeTink KeyEncryptionType = "tink"
	KeyEncryptionTypeNone KeyEncryptionType = "none"
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
// Now all operations use the unified streaming DataEncryptor interface
func (f *Factory) CreateEnvelopeEncryptor(contentType ContentType, keyFingerprint string) (encryption.EnvelopeEncryptor, error) {
	// Find the key encryptor by fingerprint
	keyEncryptor, exists := f.keyEncryptors[keyFingerprint]
	if !exists {
		return nil, fmt.Errorf("key encryptor with fingerprint %s not found", keyFingerprint)
	}

	// Choose data encryptor based on content type - all using unified streaming interface
	switch contentType {
	case ContentTypeMultipart:
		// For multipart/chunks, use AES-CTR (streaming optimized)
		dataEncryptor := dataencryption.NewAESCTRDataEncryptor()
		return envelope.NewEnvelopeEncryptor(keyEncryptor, dataEncryptor), nil
	case ContentTypeWhole:
		// For whole files, use AES-GCM (authenticated encryption with streaming support)
		dataEncryptor := dataencryption.NewAESGCMDataEncryptor()
		return envelope.NewEnvelopeEncryptor(keyEncryptor, dataEncryptor), nil
	default:
		return nil, fmt.Errorf("unsupported content type: %s", contentType)
	}
}

// CreateEnvelopeEncryptorWithPrefix creates an envelope encryptor with custom metadata prefix
// Now all operations use the unified streaming DataEncryptor interface
func (f *Factory) CreateEnvelopeEncryptorWithPrefix(contentType ContentType, keyFingerprint string, metadataPrefix string) (encryption.EnvelopeEncryptor, error) {
	// Find the key encryptor by fingerprint
	keyEncryptor, exists := f.keyEncryptors[keyFingerprint]
	if !exists {
		return nil, fmt.Errorf("key encryptor with fingerprint %s not found", keyFingerprint)
	}

	// Choose data encryptor based on content type - all using unified streaming interface
	switch contentType {
	case ContentTypeMultipart:
		// For multipart/chunks, use AES-CTR (streaming optimized)
		dataEncryptor := dataencryption.NewAESCTRDataEncryptor()
		return envelope.NewEnvelopeEncryptorWithPrefix(keyEncryptor, dataEncryptor, metadataPrefix), nil
	case ContentTypeWhole:
		// For whole files, use AES-GCM (authenticated encryption with streaming support)
		dataEncryptor := dataencryption.NewAESGCMDataEncryptor()
		return envelope.NewEnvelopeEncryptorWithPrefix(keyEncryptor, dataEncryptor, metadataPrefix), nil
	default:
		return nil, fmt.Errorf("unsupported content type: %s", contentType)
	}
}

// CreateKeyEncryptorFromConfig creates a key encryptor from configuration
func (f *Factory) CreateKeyEncryptorFromConfig(keyType KeyEncryptionType, config map[string]interface{}) (encryption.KeyEncryptor, error) {
	switch keyType {
	case KeyEncryptionTypeAES:
		return f.createAESKeyEncryptor(config)
	case KeyEncryptionTypeRSA:
		return f.createRSAKeyEncryptor(config)
	case KeyEncryptionTypeTink:
		return nil, fmt.Errorf("tink key encryption is not yet implemented with the new KeyEncryptor interface")
	case KeyEncryptionTypeNone:
		return f.createNoneKeyEncryptor(config)
	default:
		return nil, fmt.Errorf("unsupported key encryption type: %s", keyType)
	}
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

	// Use configuration directly - no translation needed anymore
	return keyencryption.NewAESProvider(config)
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

func (f *Factory) createNoneKeyEncryptor(config map[string]interface{}) (encryption.KeyEncryptor, error) {
	// None provider requires no configuration - just return a new instance
	return keyencryption.NewNoneProvider(config)
}

// GetRegisteredKeyEncryptors returns a list of all registered key encryptor fingerprints
// ProviderInfo holds information about a registered provider
type ProviderInfo struct {
	Fingerprint string
	Type        string
}

func (f *Factory) GetRegisteredKeyEncryptors() []string {
	fingerprints := make([]string, 0, len(f.keyEncryptors))
	for fingerprint := range f.keyEncryptors {
		fingerprints = append(fingerprints, fingerprint)
	}
	return fingerprints
}

// GetRegisteredProviderInfo returns detailed information about all registered key encryptors
func (f *Factory) GetRegisteredProviderInfo() []ProviderInfo {
	providers := make([]ProviderInfo, 0, len(f.keyEncryptors))
	for fingerprint, keyEncryptor := range f.keyEncryptors {
		// Determine provider type based on the encryptor type
		var providerType string
		switch keyEncryptor.(type) {
		case *keyencryption.AESProvider:
			providerType = "aes"
		case *keyencryption.RSAProvider:
			providerType = "rsa"
		case *keyencryption.NoneProvider:
			providerType = "none"
		default:
			providerType = "unknown"
		}

		providers = append(providers, ProviderInfo{
			Fingerprint: fingerprint,
			Type:        providerType,
		})
	}
	return providers
}

// DetermineContentTypeFromHTTPContentType determines the encryption ContentType based on HTTP Content-Type header
// This allows clients to force specific encryption modes via Content-Type headers
// streamingThreshold: files larger than this size use streaming encryption (AES-CTR), smaller files use envelope encryption (AES-GCM)
func DetermineContentTypeFromHTTPContentType(httpContentType string, contentLength int64, isMultipart bool, streamingThreshold int64) ContentType {
	// Check for explicit forcing via special Content-Types
	switch httpContentType {
	case ForceAESGCMContentType:
		return ContentTypeWhole
	case ForceAESCTRContentType:
		return ContentTypeMultipart
	}

	// If no forcing is specified, use automatic logic
	if isMultipart {
		// Multipart uploads always use streaming encryption (AES-CTR)
		return ContentTypeMultipart
	}

	// For single-part uploads, decide based on size
	// Small files use AES-GCM (envelope encryption with small overhead)
	// Large files automatically switch to AES-CTR (streaming encryption, no overhead)
	// Use configurable threshold instead of hardcoded value

	if contentLength >= 0 && contentLength >= streamingThreshold {
		return ContentTypeMultipart // Use streaming encryption for large files
	}

	return ContentTypeWhole // Use envelope encryption for small/medium files
}
