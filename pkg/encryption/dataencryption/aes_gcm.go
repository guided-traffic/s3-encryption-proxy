package dataencryption

import (
	"bufio"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"sync"

	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption"
)

// AESGCMDataEncryptor implements streaming AES-256-GCM encryption/decryption
// This implements the unified DataEncryptor interface for both small and large data through streaming
// It also implements IVProvider and HMACProvider for metadata and integrity verification
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

// EncryptStream encrypts data from a reader using AES-256-GCM
// Note: AES-GCM requires all data to calculate the authentication tag,
// so we buffer the data internally for authentication
func (e *AESGCMDataEncryptor) EncryptStream(ctx context.Context, reader *bufio.Reader, dek []byte, associatedData []byte) (*bufio.Reader, error) {
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

// DecryptStream decrypts data from an encrypted reader using AES-256-GCM
// iv parameter contains the nonce for GCM decryption
func (e *AESGCMDataEncryptor) DecryptStream(ctx context.Context, encryptedReader *bufio.Reader, dek []byte, iv []byte, associatedData []byte) (*bufio.Reader, error) {
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
	return "aes-256-gcm"
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

// EncryptStreamWithHMAC encrypts data from a reader and calculates HMAC in parallel for integrity verification
// This implements the HMACProvider interface for optional integrity verification
func (e *AESGCMDataEncryptor) EncryptStreamWithHMAC(ctx context.Context, reader *bufio.Reader, dek []byte, hmacKey []byte, associatedData []byte) (*bufio.Reader, func() []byte, error) {
	if len(dek) != 32 {
		return nil, nil, fmt.Errorf("invalid DEK size: expected 32 bytes, got %d", len(dek))
	}

	if len(hmacKey) != 32 {
		return nil, nil, fmt.Errorf("invalid HMAC key size: expected 32 bytes, got %d", len(hmacKey))
	}

	// Read all data for HMAC calculation and GCM encryption
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read data for HMAC+GCM encryption: %w", err)
	}

	// Step 1: Calculate HMAC over the original (unencrypted) data
	h := hmac.New(sha256.New, hmacKey)
	h.Write(data)
	calculatedHMAC := h.Sum(nil)

	// Step 2: Encrypt data using standard AES-GCM process
	encryptedReader, err := e.EncryptStream(ctx, bufio.NewReader(bytes.NewReader(data)), dek, associatedData)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encrypt data: %w", err)
	}

	// Return encrypted reader and HMAC finalizer function
	hmacFinalizer := func() []byte {
		// Return a copy of the calculated HMAC
		result := make([]byte, len(calculatedHMAC))
		copy(result, calculatedHMAC)
		return result
	}

	return encryptedReader, hmacFinalizer, nil
}

// DecryptStreamWithHMAC decrypts data from an encrypted reader and verifies HMAC for integrity verification
// This implements the HMACProvider interface for optional integrity verification
func (e *AESGCMDataEncryptor) DecryptStreamWithHMAC(ctx context.Context, encryptedReader *bufio.Reader, dek []byte, hmacKey []byte, expectedHMAC []byte, associatedData []byte) (*bufio.Reader, error) {
	if len(dek) != 32 {
		return nil, fmt.Errorf("invalid DEK size: expected 32 bytes, got %d", len(dek))
	}

	if len(hmacKey) != 32 {
		return nil, fmt.Errorf("invalid HMAC key size: expected 32 bytes, got %d", len(hmacKey))
	}

	// Step 1: Decrypt data using standard AES-GCM process
	// Note: We need to pass nil for IV since GCM extracts nonce from encrypted data
	decryptedReader, err := e.DecryptStream(ctx, encryptedReader, dek, nil, associatedData)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data: %w", err)
	}

	// Step 2: Read decrypted data for HMAC verification
	decryptedData, err := io.ReadAll(decryptedReader)
	if err != nil {
		return nil, fmt.Errorf("failed to read decrypted data for HMAC verification: %w", err)
	}

	// Step 3: Calculate HMAC over the decrypted data
	h := hmac.New(sha256.New, hmacKey)
	h.Write(decryptedData)
	calculatedHMAC := h.Sum(nil)

	// Step 4: Verify HMAC matches expected value
	if !hmac.Equal(calculatedHMAC, expectedHMAC) {
		return nil, fmt.Errorf("HMAC verification failed: integrity check failed")
	}

	// Return verified decrypted data as reader
	return bufio.NewReader(bytes.NewReader(decryptedData)), nil
}
