package keyencryption

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

// AESProvider implements key encryption using AES-CTR for encrypting Data Encryption Keys (DEKs)
type AESProvider struct {
	cipher cipher.Block
	kek    []byte // Key Encryption Key
}

// NewAESProvider creates a new AES key encryption provider
func NewAESProvider(config map[string]interface{}) (*AESProvider, error) {
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

// Encrypt encrypts data using AES envelope encryption
func (p *AESProvider) Encrypt(ctx context.Context, data []byte, associatedData []byte) (*encryption.EncryptionResult, error) {
	// Generate a random DEK (32 bytes for AES-256)
	dek := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		return nil, fmt.Errorf("failed to generate DEK: %w", err)
	}
	defer func() {
		// Clear DEK from memory
		for i := range dek {
			dek[i] = 0
		}
	}()

	// Encrypt the data with AES-GCM using the DEK
	encryptedData, err := p.encryptDataWithDEK(data, dek, associatedData)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt data with DEK: %w", err)
	}

	// Encrypt the DEK with the KEK using AES-CTR
	encryptedDEK, err := p.encryptDEK(dek)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt DEK: %w", err)
	}

	return &encryption.EncryptionResult{
		EncryptedData: encryptedData,
		EncryptedDEK:  encryptedDEK,
		Metadata: map[string]string{
			"algorithm": "aes-envelope",
		},
	}, nil
}

// Decrypt decrypts data using AES envelope encryption
func (p *AESProvider) Decrypt(ctx context.Context, encryptedData []byte, encryptedDEK []byte, associatedData []byte) ([]byte, error) {
	// Decrypt the DEK using the KEK
	dek, err := p.decryptDEK(encryptedDEK)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt DEK: %w", err)
	}
	defer func() {
		// Clear DEK from memory
		for i := range dek {
			dek[i] = 0
		}
	}()

	// Decrypt the data using the DEK
	data, err := p.decryptDataWithDEK(encryptedData, dek, associatedData)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data with DEK: %w", err)
	}

	return data, nil
}

// RotateKEK rotates the Key Encryption Key (generates a new random key)
func (p *AESProvider) RotateKEK(ctx context.Context) error {
	// Generate new random KEK
	newKEK := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, newKEK); err != nil {
		return fmt.Errorf("failed to generate new KEK: %w", err)
	}

	return p.rotateKEKWithKey(ctx, newKEK)
}

// rotateKEKWithKey rotates the Key Encryption Key to a specific key
func (p *AESProvider) rotateKEKWithKey(ctx context.Context, newKEK []byte) error {
	if len(newKEK) != 32 {
		return fmt.Errorf("new KEK must be exactly 32 bytes, got %d", len(newKEK))
	}

	cipher, err := aes.NewCipher(newKEK)
	if err != nil {
		return fmt.Errorf("failed to create cipher with new KEK: %w", err)
	}

	p.cipher = cipher
	p.kek = make([]byte, len(newKEK))
	copy(p.kek, newKEK)

	return nil
}

// encryptDataWithDEK encrypts data using AES-GCM with the given DEK
func (p *AESProvider) encryptDataWithDEK(data []byte, dek []byte, associatedData []byte) ([]byte, error) {
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Generate random nonce
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt the data
	ciphertext := aesGCM.Seal(nonce, nonce, data, associatedData)
	return ciphertext, nil
}

// decryptDataWithDEK decrypts data using AES-GCM with the given DEK
func (p *AESProvider) decryptDataWithDEK(encryptedData []byte, dek []byte, associatedData []byte) ([]byte, error) {
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonceSize := aesGCM.NonceSize()
	if len(encryptedData) < nonceSize {
		return nil, fmt.Errorf("encrypted data too short")
	}

	nonce, ciphertext := encryptedData[:nonceSize], encryptedData[nonceSize:]
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, associatedData)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data: %w", err)
	}

	return plaintext, nil
}

// encryptDEK encrypts a data key using AES-CTR with the master key
func (p *AESProvider) encryptDEK(dek []byte) ([]byte, error) {
	// Generate random IV for DEK encryption
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, fmt.Errorf("failed to generate IV for DEK: %w", err)
	}

	// Create CTR mode cipher with master key
	stream := cipher.NewCTR(p.cipher, iv)

	// Encrypt the DEK
	ciphertext := make([]byte, len(dek))
	stream.XORKeyStream(ciphertext, dek)

	// Prepend IV to encrypted DEK
	result := make([]byte, len(iv)+len(ciphertext))
	copy(result, iv)
	copy(result[len(iv):], ciphertext)

	return result, nil
}

// decryptDEK decrypts a data key using AES-CTR with the master key
func (p *AESProvider) decryptDEK(encryptedDEK []byte) ([]byte, error) {
	if len(encryptedDEK) < aes.BlockSize {
		return nil, fmt.Errorf("encrypted DEK too short")
	}

	// Extract IV and data
	iv := encryptedDEK[:aes.BlockSize]
	data := encryptedDEK[aes.BlockSize:]

	// Create CTR mode cipher with master key
	stream := cipher.NewCTR(p.cipher, iv)

	// Decrypt the DEK
	dek := make([]byte, len(data))
	stream.XORKeyStream(dek, data)

	return dek, nil
}
