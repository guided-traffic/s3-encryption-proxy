package dataencryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"sync"
)

// AESCTRStreamingDataEncryptor implements streaming AES-CTR encryption for multipart uploads
// It maintains counter state between parts to ensure continuous encryption
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
		dek:    append([]byte(nil), dek...),  // Copy DEK
		iv:     append([]byte(nil), iv...),   // Copy IV
		stream: stream,
		offset: 0,
	}, nil
}

// NewAESCTRStreamingDataEncryptorWithIV creates a streaming encryptor with existing IV
// Used for decryption where IV is known
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
		dek:    append([]byte(nil), dek...),  // Copy DEK
		iv:     append([]byte(nil), iv...),   // Copy IV
		stream: stream,
		offset: offset,
	}, nil
}

// EncryptPart encrypts a part while maintaining counter state
func (e *AESCTRStreamingDataEncryptor) EncryptPart(data []byte) ([]byte, error) {
	e.mutex.Lock()
	defer e.mutex.Unlock()

	// Encrypt the data
	ciphertext := make([]byte, len(data))
	e.stream.XORKeyStream(ciphertext, data)

	// Update offset
	e.offset += uint64(len(data))

	return ciphertext, nil
}

// GetIV returns the IV used for this encryption session
func (e *AESCTRStreamingDataEncryptor) GetIV() []byte {
	return e.iv
}

// GetOffset returns the current offset in the stream
func (e *AESCTRStreamingDataEncryptor) GetOffset() uint64 {
	e.mutex.Lock()
	defer e.mutex.Unlock()
	return e.offset
}

// AESCTRStreamingDecryptor handles decryption of streaming AES-CTR data
type AESCTRStreamingDecryptor struct {
	stream cipher.Stream
	offset uint64
}

// NewAESCTRStreamingDecryptor creates a new streaming decryptor
func NewAESCTRStreamingDecryptor(dek, iv []byte, startOffset uint64) (*AESCTRStreamingDecryptor, error) {
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

	// Advance the stream to the start offset
	if startOffset > 0 {
		dummy := make([]byte, startOffset)
		stream.XORKeyStream(dummy, dummy)
	}

	return &AESCTRStreamingDecryptor{
		stream: stream,
		offset: startOffset,
	}, nil
}

// DecryptPart decrypts a part of the stream
func (d *AESCTRStreamingDecryptor) DecryptPart(encryptedData []byte) []byte {
	plaintext := make([]byte, len(encryptedData))
	d.stream.XORKeyStream(plaintext, encryptedData)
	d.offset += uint64(len(encryptedData))
	return plaintext
}
