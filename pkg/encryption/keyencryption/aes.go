package keyencryption

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"

	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption"
)

// AESProvider implements encryption.KeyEncryptor using AES-CTR for encrypting Data Encryption Keys (DEKs)
// This handles ONLY DEK encryption/decryption with the master KEK - no data encryption
type AESProvider struct {
	cipher cipher.Block
	kek    []byte // Key Encryption Key
}

// NewAESKeyEncryptor creates a new AES key encryptor from a provided KEK
func NewAESKeyEncryptor(kek []byte) (encryption.KeyEncryptor, error) {
	if len(kek) != 32 {
		return nil, fmt.Errorf("AES-256 key must be exactly 32 bytes, got %d", len(kek))
	}

	// Create cipher to validate key
	aesCipher, err := aes.NewCipher(kek)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	return &AESProvider{
		cipher: aesCipher,
		kek:    kek,
	}, nil
}

// NewAESProvider creates a new AES key encryption provider implementing encryption.KeyEncryptor
func NewAESProvider(config map[string]interface{}) (encryption.KeyEncryptor, error) {
	keyInterface, exists := config["key"]
	if !exists {
		return nil, fmt.Errorf("missing 'key' in configuration")
	}

	keyStr, ok := keyInterface.(string)
	if !ok {
		return nil, fmt.Errorf("key must be a string")
	}

	if keyStr == "" {
		return nil, fmt.Errorf("key cannot be empty")
	}

	var kek []byte
	var err error

	// Try base64 decoding first, fallback to direct bytes
	if decoded, decodeErr := base64.StdEncoding.DecodeString(keyStr); decodeErr == nil && len(decoded) == 32 {
		kek = decoded
	} else {
		kek = []byte(keyStr)
	}

	if len(kek) != 32 {
		return nil, fmt.Errorf("AES-256 key must be exactly 32 bytes, got %d", len(kek))
	}

	// Create cipher to validate key
	aesCipher, err := aes.NewCipher(kek)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	return &AESProvider{
		cipher: aesCipher,
		kek:    kek,
	}, nil
}

// NewAESProviderFromBase64 creates a new AES key encryptor from base64-encoded KEK
func NewAESProviderFromBase64(base64KEK string) (encryption.KeyEncryptor, error) {
	kek, err := base64.StdEncoding.DecodeString(base64KEK)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64 KEK: %w", err)
	}

	if len(kek) != 32 {
		return nil, fmt.Errorf("AES-256 key must be exactly 32 bytes, got %d", len(kek))
	}

	// Create cipher to validate key
	aesCipher, err := aes.NewCipher(kek)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	return &AESProvider{
		cipher: aesCipher,
		kek:    kek,
	}, nil
}

// EncryptDEK encrypts a Data Encryption Key with the Key Encryption Key using AES-CTR
func (p *AESProvider) EncryptDEK(ctx context.Context, dek []byte) ([]byte, string, error) {
	// Generate random IV for DEK encryption
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, "", fmt.Errorf("failed to generate IV for DEK: %w", err)
	}

	// Create CTR mode cipher with KEK
	// #nosec G407 - IV is randomly generated, not hardcoded
	stream := cipher.NewCTR(p.cipher, iv)

	// Encrypt the DEK
	encryptedDEK := make([]byte, len(dek))
	stream.XORKeyStream(encryptedDEK, dek)

	// Prepend IV to encrypted DEK
	result := make([]byte, len(iv)+len(encryptedDEK))
	copy(result, iv)
	copy(result[len(iv):], encryptedDEK)

	return result, p.Fingerprint(), nil
}

// DecryptDEK decrypts a Data Encryption Key using the Key Encryption Key
func (p *AESProvider) DecryptDEK(ctx context.Context, encryptedDEK []byte, keyID string) ([]byte, error) {
	// Verify key ID matches our fingerprint
	if keyID != p.Fingerprint() {
		return nil, fmt.Errorf("key ID mismatch: expected %s, got %s", p.Fingerprint(), keyID)
	}

	if len(encryptedDEK) < aes.BlockSize {
		return nil, fmt.Errorf("encrypted DEK too short: expected at least %d bytes, got %d", aes.BlockSize, len(encryptedDEK))
	}

	// Extract IV and ciphertext
	iv := encryptedDEK[:aes.BlockSize]
	ciphertext := encryptedDEK[aes.BlockSize:]

	// Create CTR mode cipher with KEK
	// #nosec G407 - IV is extracted from encrypted data, not hardcoded
	stream := cipher.NewCTR(p.cipher, iv)

	// Decrypt the DEK
	dek := make([]byte, len(ciphertext))
	stream.XORKeyStream(dek, ciphertext)

	return dek, nil
}

// Name returns the short unique name for this KeyEncryptor type
func (p *AESProvider) Name() string {
	return "aes"
}

// Fingerprint returns a SHA-256 fingerprint of the AES KEK
// This allows identification of the correct KEK provider during decryption
func (p *AESProvider) Fingerprint() string {
	hash := sha256.Sum256(p.kek)
	return hex.EncodeToString(hash[:])
}

// RotateKEK is not implemented for AES key encryptor - requires external key management
func (p *AESProvider) RotateKEK(ctx context.Context) error {
	return fmt.Errorf("AES key rotation is not implemented - requires external key management")
}
