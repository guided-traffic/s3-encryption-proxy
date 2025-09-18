package dataencryption

import (
	"bufio"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"hash"
	"io"
	"sync"

	"github.com/guided-traffic/s3-encryption-proxy/internal/crypto"
	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption"
)

// AESCTRDataEncryptor implements streaming AES-256-CTR encryption/decryption
// This implements DataEncryptorStreaming interface for high-performance streaming encryption
// It also implements IVProvider and HMACProviderStreaming for metadata and integrity
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

// DecryptStream decrypts data from an encrypted reader using AES-256-CTR
func (e *AESCTRDataEncryptor) DecryptStream(ctx context.Context, encryptedReader *bufio.Reader, dek []byte, associatedData []byte) (*bufio.Reader, error) {
	return nil, fmt.Errorf("AES-CTR decryption requires IV from metadata - use DecryptStreamWithIV instead")
}

// DecryptStreamWithIV decrypts data from an encrypted reader using AES-256-CTR with known IV
func (e *AESCTRDataEncryptor) DecryptStreamWithIV(ctx context.Context, encryptedReader *bufio.Reader, dek []byte, iv []byte, associatedData []byte) (*bufio.Reader, error) {
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

// EncryptStreamWithHMAC implements the HMACProviderStreaming interface for AES-CTR
func (e *AESCTRDataEncryptor) EncryptStreamWithHMAC(ctx context.Context, reader *bufio.Reader, dek []byte, hmacKey []byte, associatedData []byte) (*bufio.Reader, func() []byte, error) {
	if len(dek) != 32 {
		return nil, nil, fmt.Errorf("invalid DEK size: expected 32 bytes, got %d", len(dek))
	}

	// Use provided HMAC key or derive from DEK if not provided
	var actualHMACKey []byte
	if hmacKey != nil {
		actualHMACKey = hmacKey
	} else {
		// Derive HMAC key from DEK using HKDF
		var err error
		actualHMACKey, err = crypto.DeriveIntegrityKey(dek)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to derive HMAC key: %w", err)
		}
	}

	// Create AES cipher with DEK
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	// Generate random IV (16 bytes for AES)
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, nil, fmt.Errorf("failed to generate IV: %w", err)
	}

	// Store the IV for metadata (IVProvider interface)
	e.mutex.Lock()
	e.lastIV = append([]byte(nil), iv...) // Copy the IV
	e.mutex.Unlock()

	// Create CTR mode cipher
	// #nosec G407 - IV is randomly generated, not hardcoded
	stream := cipher.NewCTR(block, iv)

	// Create HMAC calculator
	hmacCalculator := hmac.New(sha256.New, actualHMACKey)

	// Create streaming encryptor reader with HMAC
	encryptedReader := &ctrStreamReaderWithHMAC{
		reader:    reader,
		stream:    stream,
		hmac:      hmacCalculator,
		isEncrypt: true,
	}

	// Return encrypted reader and function to get final HMAC
	return bufio.NewReader(encryptedReader), func() []byte {
		return hmacCalculator.Sum(nil)
	}, nil
}

// DecryptStreamWithHMAC implements the HMACProviderStreaming interface for AES-CTR
func (e *AESCTRDataEncryptor) DecryptStreamWithHMAC(ctx context.Context, encryptedReader *bufio.Reader, dek []byte, hmacKey []byte, expectedHMAC []byte, associatedData []byte) (*bufio.Reader, error) {
	return nil, fmt.Errorf("AES-CTR HMAC decryption requires IV from metadata - use DecryptStreamWithIVAndHMAC instead")
}

// DecryptStreamWithIVAndHMAC decrypts data and verifies HMAC with known IV
func (e *AESCTRDataEncryptor) DecryptStreamWithIVAndHMAC(ctx context.Context, encryptedReader *bufio.Reader, dek []byte, iv []byte, hmacKey []byte, expectedHMAC []byte, associatedData []byte) (*bufio.Reader, error) {
	if len(dek) != 32 {
		return nil, fmt.Errorf("invalid DEK size: expected 32 bytes, got %d", len(dek))
	}
	if len(iv) != aes.BlockSize {
		return nil, fmt.Errorf("invalid IV size: expected %d bytes, got %d", aes.BlockSize, len(iv))
	}

	// Use provided HMAC key or derive from DEK if not provided
	var actualHMACKey []byte
	if hmacKey != nil {
		actualHMACKey = hmacKey
	} else {
		// Derive HMAC key from DEK using HKDF
		var err error
		actualHMACKey, err = crypto.DeriveIntegrityKey(dek)
		if err != nil {
			return nil, fmt.Errorf("failed to derive HMAC key: %w", err)
		}
	}

	// Create AES cipher with DEK
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	// Create CTR mode cipher with the provided IV
	// #nosec G407 - IV comes from trusted metadata
	stream := cipher.NewCTR(block, iv)

	// Create HMAC calculator for verification
	hmacCalculator := hmac.New(sha256.New, actualHMACKey)

	// Create streaming decryptor reader with HMAC verification
	decryptedReader := &ctrStreamReaderWithHMACVerification{
		reader:       encryptedReader,
		stream:       stream,
		hmac:         hmacCalculator,
		expectedHMAC: expectedHMAC,
	}

	return bufio.NewReader(decryptedReader), nil
}

// ctrStreamReaderWithHMAC implements io.Reader for AES-CTR streaming with HMAC calculation
type ctrStreamReaderWithHMAC struct {
	reader    io.Reader
	stream    cipher.Stream
	hmac      hash.Hash
	isEncrypt bool
}

func (r *ctrStreamReaderWithHMAC) Read(p []byte) (n int, err error) {
	n, err = r.reader.Read(p)
	if n > 0 {
		if r.isEncrypt {
			// For encryption: calculate HMAC over original data, then encrypt
			r.hmac.Write(p[:n])
			r.stream.XORKeyStream(p[:n], p[:n])
		} else {
			// For decryption: decrypt first, then calculate HMAC over decrypted data
			r.stream.XORKeyStream(p[:n], p[:n])
			r.hmac.Write(p[:n])
		}
	}
	return n, err
}

// ctrStreamReaderWithHMACVerification implements io.Reader for AES-CTR streaming with HMAC verification
type ctrStreamReaderWithHMACVerification struct {
	reader       io.Reader
	stream       cipher.Stream
	hmac         hash.Hash
	expectedHMAC []byte
	finished     bool
	hmacError    error
}

func (r *ctrStreamReaderWithHMACVerification) Read(p []byte) (n int, err error) {
	if r.hmacError != nil {
		return 0, r.hmacError
	}

	n, err = r.reader.Read(p)
	if n > 0 {
		// Decrypt data first, then calculate HMAC over decrypted data
		r.stream.XORKeyStream(p[:n], p[:n])
		r.hmac.Write(p[:n])
	}

	// Check HMAC when we reach EOF
	if err == io.EOF && !r.finished {
		r.finished = true
		calculatedHMAC := r.hmac.Sum(nil)
		if !hmac.Equal(calculatedHMAC, r.expectedHMAC) {
			r.hmacError = fmt.Errorf("HMAC verification failed: integrity check failed")
			return n, r.hmacError
		}
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

	// HMAC support for streaming integrity verification
	hmacEnabled bool
	hmac        hash.Hash
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
		dek:         append([]byte(nil), dek...), // Copy DEK
		iv:          append([]byte(nil), iv...),  // Copy IV
		stream:      stream,
		offset:      0,
		hmacEnabled: false,
		hmac:        nil,
	}, nil
}

// NewAESCTRStreamingDataEncryptorWithHMAC creates a streaming encryptor with HMAC support
func NewAESCTRStreamingDataEncryptorWithHMAC(dek []byte) (*AESCTRStreamingDataEncryptor, error) {
	encryptor, err := NewAESCTRStreamingDataEncryptor(dek)
	if err != nil {
		return nil, err
	}

	// Derive HMAC key from DEK using HKDF
	hmacKey, err := crypto.DeriveIntegrityKey(dek)
	if err != nil {
		return nil, fmt.Errorf("failed to derive HMAC key: %w", err)
	}

	// Enable HMAC
	encryptor.hmacEnabled = true
	encryptor.hmac = hmac.New(sha256.New, hmacKey)

	return encryptor, nil
}

// NewAESCTRStreamingDataDecryptorWithHMAC creates a streaming decryptor with HMAC verification
func NewAESCTRStreamingDataDecryptorWithHMAC(dek, iv []byte, offset uint64) (*AESCTRStreamingDataEncryptor, error) {
	decryptor, err := NewAESCTRStreamingDataEncryptorWithIV(dek, iv, offset)
	if err != nil {
		return nil, err
	}

	// Derive HMAC key from DEK using HKDF
	hmacKey, err := crypto.DeriveIntegrityKey(dek)
	if err != nil {
		return nil, fmt.Errorf("failed to derive HMAC key: %w", err)
	}

	// Enable HMAC for verification
	decryptor.hmacEnabled = true
	decryptor.hmac = hmac.New(sha256.New, hmacKey)

	return decryptor, nil
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

	// If HMAC is enabled, update it with original data
	if e.hmacEnabled && e.hmac != nil {
		e.hmac.Write(data)
	}

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

	// Decrypt the data first (AES-CTR decryption is the same as encryption)
	decrypted := make([]byte, len(data))
	copy(decrypted, data)
	e.stream.XORKeyStream(decrypted, decrypted)

	// If HMAC is enabled, update it with decrypted data
	if e.hmacEnabled && e.hmac != nil {
		e.hmac.Write(decrypted)
	}

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

// GetStreamingHMAC returns the current HMAC if enabled
func (e *AESCTRStreamingDataEncryptor) GetStreamingHMAC() []byte {
	e.mutex.Lock()
	defer e.mutex.Unlock()

	if !e.hmacEnabled || e.hmac == nil {
		return nil
	}

	return e.hmac.Sum(nil)
}

// VerifyStreamingHMAC verifies the final HMAC against the expected value
func (e *AESCTRStreamingDataEncryptor) VerifyStreamingHMAC(expectedHMAC []byte) error {
	e.mutex.Lock()
	defer e.mutex.Unlock()

	if !e.hmacEnabled || e.hmac == nil {
		return fmt.Errorf("HMAC verification not enabled")
	}

	calculatedHMAC := e.hmac.Sum(nil)
	if !hmac.Equal(calculatedHMAC, expectedHMAC) {
		return fmt.Errorf("HMAC verification failed: integrity check failed")
	}

	return nil
}

// Algorithm returns the algorithm identifier
func (e *AESCTRStreamingDataEncryptor) Algorithm() string {
	return "aes-256-ctr"
}
