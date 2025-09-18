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

// AESCTRDataEncryptor implements streaming AES-256-CTR encryption/decryption
// This implements DataEncryptorStreaming interface for high-performance streaming encryption
// It also implements IVProvider for metadata
type AESCTRDataEncryptor struct {
	lastIV []byte // Store the last used IV for metadata
	mutex  sync.Mutex
}

// NewAESCTRDataEncryptor creates a new streaming AES-CTR data encryptor
// Returns DataEncryptorStreaming interface for streaming-only encryption
func NewAESCTRDataEncryptor() encryption.DataEncryptorStreaming {
	return &AESCTRDataEncryptor{
		lastIV: nil,
	}
}

// EncryptStream encrypts data from a reader using AES-256-CTR
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

// DecryptStreamWithIV decrypts data from an encrypted reader using AES-256-CTR with known IV
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
	return "aes-256-ctr"
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

// Compatibility functions for the old streaming API (eliminated backward compatibility)
// These functions provide the specific API that the encryption manager expects

// AESCTRStreamingDataEncryptor is a compatibility type for the old streaming API
type AESCTRStreamingDataEncryptor struct {
	dek    []byte
	iv     []byte
	stream cipher.Stream
	offset uint64
	mutex  sync.Mutex
}

// NewAESCTRStreamingDataEncryptor creates a new streaming AES-CTR data encryptor
func NewAESCTRStreamingDataEncryptor(dek []byte) (*AESCTRStreamingDataEncryptor, error) {
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

	return &AESCTRStreamingDataEncryptor{
		dek:    append([]byte(nil), dek...), // Copy DEK
		iv:     append([]byte(nil), iv...),  // Copy IV
		stream: stream,
		offset: 0,
	}, nil
}

// NewAESCTRStreamingDataEncryptorWithIV creates a streaming encryptor with existing IV
// This provides the specific API that the current encryption manager expects
func NewAESCTRStreamingDataEncryptorWithIV(dek, iv []byte, offset uint64) (*AESCTRStreamingDataEncryptor, error) {
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

	// If we have an offset, we need to advance the stream
	if offset > 0 {
		dummy := make([]byte, offset)
		stream.XORKeyStream(dummy, dummy)
	}

	return &AESCTRStreamingDataEncryptor{
		dek:    append([]byte(nil), dek...), // Copy DEK
		iv:     append([]byte(nil), iv...),  // Copy IV
		stream: stream,
		offset: offset,
	}, nil
}

// EncryptPart encrypts a part of data using the configured cipher stream
func (e *AESCTRStreamingDataEncryptor) EncryptPart(data []byte) ([]byte, error) {
	e.mutex.Lock()
	defer e.mutex.Unlock()

	// Encrypt the data in place (AES-CTR is symmetric)
	encrypted := make([]byte, len(data))
	copy(encrypted, data)
	e.stream.XORKeyStream(encrypted, encrypted)

	// Update offset
	e.offset += uint64(len(data))

	return encrypted, nil
}

// DecryptPart decrypts a part of data using the configured cipher stream
func (e *AESCTRStreamingDataEncryptor) DecryptPart(data []byte) ([]byte, error) {
	e.mutex.Lock()
	defer e.mutex.Unlock()

	// Decrypt the data (AES-CTR decryption is the same as encryption)
	decrypted := make([]byte, len(data))
	copy(decrypted, data)
	e.stream.XORKeyStream(decrypted, decrypted)

	// Update offset
	e.offset += uint64(len(data))

	return decrypted, nil
}

// GetIV returns the IV used by this encryptor
func (e *AESCTRStreamingDataEncryptor) GetIV() []byte {
	return append([]byte(nil), e.iv...) // Return a copy
}

// GetOffset returns the current byte offset in the stream
func (e *AESCTRStreamingDataEncryptor) GetOffset() uint64 {
	e.mutex.Lock()
	defer e.mutex.Unlock()
	return e.offset
}

// Algorithm returns the algorithm identifier
func (e *AESCTRStreamingDataEncryptor) Algorithm() string {
	return "aes-256-ctr"
}
