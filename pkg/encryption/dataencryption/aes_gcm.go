package dataencryption

import (
	"bufio"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"sync"

	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption"
)

// AESGCMDataEncryptor implements streaming aes-gcm encryption/decryption
// This implements the unified DataEncryptor interface for both small and large data through streaming
// It also implements IVProvider for metadata
type AESGCMDataEncryptor struct {
	lastNonce []byte // Store the last used nonce for metadata (GCM uses nonce, not IV)
	mutex     sync.Mutex
}

// NewAESGCMDataEncryptor creates a new streaming AES-GCM data encryptor
func NewAESGCMDataEncryptor() encryption.DataEncryptor {
	return &AESGCMDataEncryptor{
		lastNonce: nil,
	}
}

// EncryptStream encrypts data from a reader using aes-gcm
// Note: AES-GCM requires all data to calculate the authentication tag,
// so we buffer the data internally for authentication
func (e *AESGCMDataEncryptor) EncryptStream(_ context.Context, reader *bufio.Reader, dek []byte, associatedData []byte) (*bufio.Reader, error) {
	if len(dek) != 32 {
		return nil, fmt.Errorf("invalid DEK size: expected 32 bytes, got %d", len(dek))
	}

	// Create AES cipher with DEK
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Generate random nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Store the nonce for metadata (IVProvider interface - GCM uses nonce as IV)
	e.mutex.Lock()
	e.lastNonce = append([]byte(nil), nonce...) // Copy the nonce
	e.mutex.Unlock()

	// Read all data into memory (required for GCM authentication)
	// For very large files, this might not be ideal, but GCM requires all data for auth tag
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read data for GCM encryption: %w", err)
	}

	// Encrypt data
	ciphertext := gcm.Seal(nil, nonce, data, associatedData)

	// Prepend nonce to ciphertext
	result := make([]byte, len(nonce)+len(ciphertext))
	copy(result[:len(nonce)], nonce)
	copy(result[len(nonce):], ciphertext)

	// Return as streaming reader
	return bufio.NewReader(bytes.NewReader(result)), nil
}

// DecryptStream decrypts data from an encrypted reader using aes-gcm
// iv parameter contains the nonce for GCM decryption
func (e *AESGCMDataEncryptor) DecryptStream(_ context.Context, encryptedReader *bufio.Reader, dek []byte, iv []byte, associatedData []byte) (*bufio.Reader, error) {
	if len(dek) != 32 {
		return nil, fmt.Errorf("invalid DEK size: expected 32 bytes, got %d", len(dek))
	}

	// Create AES cipher with DEK
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Read all encrypted data (GCM needs all data for authentication verification)
	encryptedData, err := io.ReadAll(encryptedReader)
	if err != nil {
		return nil, fmt.Errorf("failed to read encrypted data for GCM decryption: %w", err)
	}

	var nonce []byte
	var ciphertext []byte

	// If IV is provided (from metadata), use it as nonce
	if iv != nil {
		if len(iv) != gcm.NonceSize() {
			return nil, fmt.Errorf("invalid nonce size: expected %d bytes, got %d", gcm.NonceSize(), len(iv))
		}
		nonce = iv
		ciphertext = encryptedData
	} else {
		// Extract nonce from the beginning of encrypted data (legacy format)
		nonceSize := gcm.NonceSize()
		if len(encryptedData) < nonceSize {
			return nil, fmt.Errorf("encrypted data too short: expected at least %d bytes, got %d", nonceSize, len(encryptedData))
		}
		nonce = encryptedData[:nonceSize]
		ciphertext = encryptedData[nonceSize:]
	}

	// Decrypt data
	plaintext, err := gcm.Open(nil, nonce, ciphertext, associatedData)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data: %w", err)
	}

	// Return as streaming reader
	return bufio.NewReader(bytes.NewReader(plaintext)), nil
}

// GenerateDEK generates a new 256-bit AES key
func (e *AESGCMDataEncryptor) GenerateDEK(_ context.Context) ([]byte, error) {
	dek := make([]byte, 32) // 256-bit key
	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		return nil, fmt.Errorf("failed to generate DEK: %w", err)
	}
	return dek, nil
}

// Algorithm returns the algorithm identifier
func (e *AESGCMDataEncryptor) Algorithm() string {
	return "aes-gcm"
}

// GetLastIV returns the nonce used in the last encryption operation
// This implements the IVProvider interface for metadata storage
func (e *AESGCMDataEncryptor) GetLastIV() []byte {
	e.mutex.Lock()
	defer e.mutex.Unlock()
	if e.lastNonce == nil {
		return nil
	}
	// Return a copy to prevent modification
	result := make([]byte, len(e.lastNonce))
	copy(result, e.lastNonce)
	return result
}
