package providers

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"

	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption"
)

// AESCTRConfig holds configuration specific to AES-CTR encryption
type AESCTRConfig struct {
	AESKey string `json:"aes_key" mapstructure:"aes_key"` // Base64-encoded AES-256 key
}

// Validate validates the AES-CTR configuration
func (c *AESCTRConfig) Validate() error {
	if c.AESKey == "" {
		return fmt.Errorf("aes_key is required for AES-CTR provider")
	}

	// Try to decode the key to validate it
	key, err := base64.StdEncoding.DecodeString(c.AESKey)
	if err != nil {
		return fmt.Errorf("invalid base64 in aes_key: %w", err)
	}

	if len(key) != 32 {
		return fmt.Errorf("AES-256 key must be exactly 32 bytes, got %d", len(key))
	}

	// Validate key by creating a cipher
	if _, err := aes.NewCipher(key); err != nil {
		return fmt.Errorf("invalid AES key: %w", err)
	}

	return nil
}

// NewProviderFromConfig creates a new AES-CTR provider from config
func NewAESCTRProviderFromConfig(config *AESCTRConfig) (*AESCTRProvider, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}

	return NewAESCTRProviderFromBase64(config.AESKey)
}

// NewAESCTRProviderFromBase64 creates a new AES-CTR provider from a base64-encoded key
func NewAESCTRProviderFromBase64(keyB64 string) (*AESCTRProvider, error) {
	key, err := base64.StdEncoding.DecodeString(keyB64)
	if err != nil {
		return nil, fmt.Errorf("invalid base64 in AES key: %w", err)
	}

	return NewAESCTRProvider(key)
}

// NewAESCTRProvider creates a new AES-CTR encryption provider
func NewAESCTRProvider(key []byte) (*AESCTRProvider, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("AES-256 key must be exactly 32 bytes, got %d", len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	return &AESCTRProvider{
		cipher: block,
	}, nil
}

// AESCTRProvider implements AES-CTR encryption/decryption
type AESCTRProvider struct {
	cipher cipher.Block
}

// Encrypt encrypts data using AES-CTR mode with envelope encryption pattern
func (p *AESCTRProvider) Encrypt(ctx context.Context, plaintext []byte, associatedData []byte) (*encryption.EncryptionResult, error) {
	// Generate random DEK for this object
	dek := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		return nil, fmt.Errorf("failed to generate data key: %w", err)
	}

	// Encrypt DEK with master key
	encryptedDEK, err := p.encryptDEK(ctx, dek)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt data key: %w", err)
	}

	// Generate random IV (16 bytes for AES)
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, fmt.Errorf("failed to generate IV: %w", err)
	}

	// Create DEK cipher
	dekBlock, err := aes.NewCipher(dek)
	if err != nil {
		return nil, fmt.Errorf("failed to create DEK cipher: %w", err)
	}

	// Create CTR mode cipher with DEK
	stream := cipher.NewCTR(dekBlock, iv)

	// Encrypt the data
	ciphertext := make([]byte, len(plaintext))
	stream.XORKeyStream(ciphertext, plaintext)

	// Prepend IV to ciphertext
	result := make([]byte, len(iv)+len(ciphertext))
	copy(result, iv)
	copy(result[len(iv):], ciphertext)

	return &encryption.EncryptionResult{
		EncryptedData: result,
		EncryptedDEK:  encryptedDEK,
		Metadata: map[string]string{
			"encryption-mode": "aes-ctr",
		},
	}, nil
}

// Decrypt decrypts data using AES-CTR mode with envelope encryption pattern
func (p *AESCTRProvider) Decrypt(ctx context.Context, ciphertext []byte, encryptedDEK []byte, associatedData []byte) ([]byte, error) {
	if len(ciphertext) < aes.BlockSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	// Decrypt DEK with master key
	dek, err := p.decryptDEK(ctx, encryptedDEK)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data key: %w", err)
	}

	// Extract IV from the beginning
	iv := ciphertext[:aes.BlockSize]
	data := ciphertext[aes.BlockSize:]

	// Create DEK cipher
	dekBlock, err := aes.NewCipher(dek)
	if err != nil {
		return nil, fmt.Errorf("failed to create DEK cipher: %w", err)
	}

	// Create CTR mode cipher
	stream := cipher.NewCTR(dekBlock, iv)

	// Decrypt the data
	plaintext := make([]byte, len(data))
	stream.XORKeyStream(plaintext, data)

	return plaintext, nil
}

// RotateKEK rotates the Key Encryption Key (not supported for direct key provider)
func (p *AESCTRProvider) RotateKEK(ctx context.Context) error {
	return fmt.Errorf("key rotation is not supported for direct AES-CTR provider")
}

// encryptDEK encrypts a data encryption key with the master key
func (p *AESCTRProvider) encryptDEK(ctx context.Context, dek []byte) ([]byte, error) {
	// Generate random IV for DEK encryption
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, fmt.Errorf("failed to generate IV for DEK: %w", err)
	}

	// Create CTR mode cipher with master key
	stream := cipher.NewCTR(p.cipher, iv)

	// Encrypt the DEK
	encryptedDEK := make([]byte, len(dek))
	stream.XORKeyStream(encryptedDEK, dek)

	// Prepend IV to encrypted DEK
	result := make([]byte, len(iv)+len(encryptedDEK))
	copy(result, iv)
	copy(result[len(iv):], encryptedDEK)

	return result, nil
}

// decryptDEK decrypts a data encryption key with the master key
func (p *AESCTRProvider) decryptDEK(ctx context.Context, encryptedDEK []byte) ([]byte, error) {
	if len(encryptedDEK) < aes.BlockSize {
		return nil, fmt.Errorf("encrypted DEK too short")
	}

	// Extract IV from the beginning
	iv := encryptedDEK[:aes.BlockSize]
	data := encryptedDEK[aes.BlockSize:]

	// Create CTR mode cipher with master key
	stream := cipher.NewCTR(p.cipher, iv)

	// Decrypt the DEK
	dek := make([]byte, len(data))
	stream.XORKeyStream(dek, data)

	return dek, nil
}

// EncryptStream encrypts a stream of data using AES-CTR mode with given IV/counter
func (p *AESCTRProvider) EncryptStream(ctx context.Context, plaintext []byte, dek []byte, iv []byte, counter uint64) ([]byte, error) {
	if len(iv) != aes.BlockSize {
		return nil, fmt.Errorf("IV must be %d bytes, got %d", aes.BlockSize, len(iv))
	}

	// Create counter block from IV and counter value
	counterBlock := make([]byte, aes.BlockSize)
	copy(counterBlock, iv)

	// Set counter in the last 8 bytes (big-endian)
	for i := 0; i < 8; i++ {
		counterBlock[aes.BlockSize-1-i] = byte(counter >> (i * 8))
	}

	// Create DEK cipher
	dekBlock, err := aes.NewCipher(dek)
	if err != nil {
		return nil, fmt.Errorf("failed to create DEK cipher: %w", err)
	}

	// Create CTR mode cipher
	stream := cipher.NewCTR(dekBlock, counterBlock)

	// Encrypt the data
	ciphertext := make([]byte, len(plaintext))
	stream.XORKeyStream(ciphertext, plaintext)

	return ciphertext, nil
}

// DecryptStream decrypts a stream of data using AES-CTR mode with given IV/counter
func (p *AESCTRProvider) DecryptStream(ctx context.Context, ciphertext []byte, dek []byte, iv []byte, counter uint64) ([]byte, error) {
	// CTR mode encryption and decryption are identical operations
	return p.EncryptStream(ctx, ciphertext, dek, iv, counter)
}

// GenerateDataKey generates a new data encryption key and encrypts it
func (p *AESCTRProvider) GenerateDataKey(ctx context.Context) ([]byte, []byte, error) {
	// Generate a new random data key
	dataKey := make([]byte, 32) // 256-bit key
	if _, err := io.ReadFull(rand.Reader, dataKey); err != nil {
		return nil, nil, fmt.Errorf("failed to generate data key: %w", err)
	}

	// Encrypt the data key with the master key
	encryptedKey, err := p.encryptDEK(ctx, dataKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encrypt data key: %w", err)
	}

	return dataKey, encryptedKey, nil
}

// DecryptDataKey decrypts a data encryption key
func (p *AESCTRProvider) DecryptDataKey(ctx context.Context, encryptedKey []byte) ([]byte, error) {
	return p.decryptDEK(ctx, encryptedKey)
}

// GetProviderType returns the provider type
func (p *AESCTRProvider) GetProviderType() string {
	return "aes-ctr"
}
