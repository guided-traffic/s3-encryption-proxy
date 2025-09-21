package dataencryption

import (
	"bufio"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"sync"

	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption"
)

// AESCTRDataEncryptor implements streaming aes-ctr encryption/decryption
// This implements the unified DataEncryptor interface for high-performance streaming encryption
// It also implements IVProvider for metadata
type AESCTRDataEncryptor struct {
	lastIV []byte // Store the last used IV for metadata
	mutex  sync.Mutex
}

// NewAESCTRDataEncryptor creates a new streaming AES-CTR data encryptor
// Returns the unified DataEncryptor interface
func NewAESCTRDataEncryptor() encryption.DataEncryptor {
	return &AESCTRDataEncryptor{
		lastIV: nil,
	}
}

// EncryptStream encrypts data from a reader using aes-ctr
func (e *AESCTRDataEncryptor) EncryptStream(ctx context.Context, reader *bufio.Reader, dek []byte, associatedData []byte) (*bufio.Reader, error) {
	if len(dek) != 32 {
		return nil, fmt.Errorf("invalid DEK size: expected 32 bytes, got %d", len(dek))
	}

	// Create AES cipher with DEK
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	// Generate random IV (16 bytes for AES)
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, fmt.Errorf("failed to generate IV: %w", err)
	}

	// Store the IV for metadata (IVProvider interface)
	e.mutex.Lock()
	e.lastIV = append([]byte(nil), iv...) // Copy the IV
	e.mutex.Unlock()

	// Create CTR mode cipher
	// #nosec G407 - IV is randomly generated, not hardcoded
	stream := cipher.NewCTR(block, iv)

	// Create streaming encryptor reader
	encryptedReader := &ctrStreamReader{
		reader: reader,
		stream: stream,
	}

	return bufio.NewReader(encryptedReader), nil
}

// DecryptStreamWithIV decrypts data from an encrypted reader using aes-ctr with known IV
func (e *AESCTRDataEncryptor) DecryptStream(ctx context.Context, encryptedReader *bufio.Reader, dek []byte, iv []byte, associatedData []byte) (*bufio.Reader, error) {
	if len(dek) != 32 {
		return nil, fmt.Errorf("invalid DEK size: expected 32 bytes, got %d", len(dek))
	}
	if len(iv) != aes.BlockSize {
		return nil, fmt.Errorf("invalid IV size: expected %d bytes, got %d", aes.BlockSize, len(iv))
	}

	// Create AES cipher with DEK
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	// Create CTR mode cipher with the provided IV
	// #nosec G407 - IV comes from trusted metadata
	stream := cipher.NewCTR(block, iv)

	// Create streaming decryptor reader
	decryptedReader := &ctrStreamReader{
		reader: encryptedReader,
		stream: stream,
	}

	return bufio.NewReader(decryptedReader), nil
}

// GenerateDEK generates a new 256-bit AES key
func (e *AESCTRDataEncryptor) GenerateDEK(_ context.Context) ([]byte, error) {
	dek := make([]byte, 32) // 256-bit key
	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		return nil, fmt.Errorf("failed to generate DEK: %w", err)
	}
	return dek, nil
}

// Algorithm returns the algorithm identifier
func (e *AESCTRDataEncryptor) Algorithm() string {
	return "aes-ctr"
}

// GetLastIV implements the IVProvider interface
// Returns the IV used in the last encryption operation for metadata storage
func (e *AESCTRDataEncryptor) GetLastIV() []byte {
	e.mutex.Lock()
	defer e.mutex.Unlock()

	if e.lastIV == nil {
		return nil
	}
	// Return a copy to prevent external modification
	return append([]byte(nil), e.lastIV...)
}

// ctrStreamReader implements io.Reader for AES-CTR streaming encryption/decryption
type ctrStreamReader struct {
	reader io.Reader
	stream cipher.Stream
}

func (r *ctrStreamReader) Read(p []byte) (n int, err error) {
	n, err = r.reader.Read(p)
	if n > 0 {
		// Encrypt/decrypt in place
		r.stream.XORKeyStream(p[:n], p[:n])
	}
	return n, err
}

// AESCTRStatefulEncryptor provides stateful AES-CTR encryption for multipart uploads
// This maintains cipher stream state across multiple operations, making it suitable
// for scenarios like multipart uploads where data is processed in multiple chunks
type AESCTRStatefulEncryptor struct {
	dek    []byte
	iv     []byte
	stream cipher.Stream
	mutex  sync.Mutex
}

// NewAESCTRStatefulEncryptor creates a new stateful AES-CTR encryptor
func NewAESCTRStatefulEncryptor(dek []byte) (*AESCTRStatefulEncryptor, error) {
	if len(dek) != 32 {
		return nil, fmt.Errorf("invalid DEK size: expected 32 bytes, got %d", len(dek))
	}

	// Create AES cipher with DEK
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	// Generate random IV (16 bytes for AES)
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, fmt.Errorf("failed to generate IV: %w", err)
	}

	// Create CTR mode cipher
	stream := cipher.NewCTR(block, iv)

	return &AESCTRStatefulEncryptor{
		dek:    append([]byte(nil), dek...), // Copy DEK
		iv:     append([]byte(nil), iv...),  // Copy IV
		stream: stream,
	}, nil
}

// NewAESCTRStatefulEncryptorWithIV creates a stateful encryptor with existing IV
func NewAESCTRStatefulEncryptorWithIV(dek, iv []byte) (*AESCTRStatefulEncryptor, error) {
	if len(dek) != 32 {
		return nil, fmt.Errorf("invalid DEK size: expected 32 bytes, got %d", len(dek))
	}
	if len(iv) != aes.BlockSize {
		return nil, fmt.Errorf("invalid IV size: expected %d bytes, got %d", aes.BlockSize, len(iv))
	}

	// Create AES cipher with DEK
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	// Create CTR mode cipher with the provided IV
	stream := cipher.NewCTR(block, iv)

	return &AESCTRStatefulEncryptor{
		dek:    append([]byte(nil), dek...), // Copy DEK
		iv:     append([]byte(nil), iv...),  // Copy IV
		stream: stream,
	}, nil
}

// EncryptPart encrypts a part of data using the maintained cipher stream
func (e *AESCTRStatefulEncryptor) EncryptPart(data []byte) ([]byte, error) {
	e.mutex.Lock()
	defer e.mutex.Unlock()

	// Encrypt the data
	encrypted := make([]byte, len(data))
	copy(encrypted, data)
	e.stream.XORKeyStream(encrypted, encrypted)

	return encrypted, nil
}

// DecryptPart decrypts a part of data using the maintained cipher stream
func (e *AESCTRStatefulEncryptor) DecryptPart(data []byte) ([]byte, error) {
	e.mutex.Lock()
	defer e.mutex.Unlock()

	// Decrypt the data (AES-CTR decryption is the same as encryption)
	decrypted := make([]byte, len(data))
	copy(decrypted, data)
	e.stream.XORKeyStream(decrypted, decrypted)

	return decrypted, nil
}

// GetIV returns the IV used by this encryptor
func (e *AESCTRStatefulEncryptor) GetIV() []byte {
	return append([]byte(nil), e.iv...) // Return a copy
}

// Algorithm returns the algorithm identifier
func (e *AESCTRStatefulEncryptor) Algorithm() string {
	return "aes-ctr"
}

// Cleanup securely clears sensitive data from memory
func (e *AESCTRStatefulEncryptor) Cleanup() {
	e.mutex.Lock()
	defer e.mutex.Unlock()

	// Clear DEK from memory
	if e.dek != nil {
		for i := range e.dek {
			e.dek[i] = 0
		}
		e.dek = nil
	}

	// Clear IV from memory
	if e.iv != nil {
		for i := range e.iv {
			e.iv[i] = 0
		}
		e.iv = nil
	}

	// Note: cipher.Stream doesn't have a cleanup method, but clearing the key material is sufficient
	e.stream = nil
}
