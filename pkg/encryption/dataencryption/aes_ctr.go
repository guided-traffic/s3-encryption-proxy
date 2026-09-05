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
func (e *AESCTRDataEncryptor) EncryptStream(_ context.Context, reader *bufio.Reader, dek []byte, _ []byte) (*bufio.Reader, error) {
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
func (e *AESCTRDataEncryptor) DecryptStream(_ context.Context, encryptedReader *bufio.Reader, dek []byte, iv []byte, _ []byte) (*bufio.Reader, error) {
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

// AESCTRStatefulEncryptor provides stateful AES-CTR encryption for multipart uploads.
// It maintains cipher stream state across multiple calls and is therefore
// inherently sequential: a single owner must drive EncryptPart/DecryptPart/Cleanup
// one call at a time. Concurrent use from multiple goroutines is not supported.
type AESCTRStatefulEncryptor struct {
	dek    []byte
	iv     []byte
	stream cipher.Stream
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
	stream := cipher.NewCTR(block, iv) // #nosec G407 -- IV is randomly generated above

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
	stream := cipher.NewCTR(block, iv) // #nosec G407 -- IV comes from metadata for decryption operations

	return &AESCTRStatefulEncryptor{
		dek:    append([]byte(nil), dek...), // Copy DEK
		iv:     append([]byte(nil), iv...),  // Copy IV
		stream: stream,
	}, nil
}

// EncryptPart encrypts data in-place using the maintained cipher stream and
// returns the same slice. The caller's buffer is mutated. Not safe for
// concurrent use — see the type comment.
func (e *AESCTRStatefulEncryptor) EncryptPart(data []byte) ([]byte, error) {
	e.stream.XORKeyStream(data, data)
	return data, nil
}

// DecryptPart decrypts data in-place using the maintained cipher stream and
// returns the same slice. AES-CTR decryption is identical to encryption. Not
// safe for concurrent use — see the type comment.
func (e *AESCTRStatefulEncryptor) DecryptPart(data []byte) ([]byte, error) {
	e.stream.XORKeyStream(data, data)
	return data, nil
}

// GetIV returns the IV used by this encryptor
func (e *AESCTRStatefulEncryptor) GetIV() []byte {
	return append([]byte(nil), e.iv...) // Return a copy
}

// Algorithm returns the algorithm identifier
func (e *AESCTRStatefulEncryptor) Algorithm() string {
	return "aes-ctr"
}

// Cleanup securely clears sensitive data from memory. Must be called by the
// single owner after all EncryptPart/DecryptPart calls have returned.
func (e *AESCTRStatefulEncryptor) Cleanup() {
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

// NewCTRStreamAt returns an AES-CTR keystream positioned at plaintextOffset.
//
// AES-CTR is seekable: the keystream for byte n depends only on the key, the IV
// and n, so a range of an encrypted object can be decrypted without touching the
// bytes before it. That is what makes partial reads of large encrypted objects
// possible at all -- kopia, the uploader Velero uses for volume data, reads its
// pack blobs with small ranged GETs and would otherwise have to download every
// blob in full for every read.
//
// The counter is the IV advanced by offset/16 blocks; the first offset%16 bytes
// of the resulting keystream belong to the preceding partial block and are
// discarded.
func NewCTRStreamAt(dek, iv []byte, plaintextOffset int64) (cipher.Stream, error) {
	if len(dek) != 32 {
		return nil, fmt.Errorf("invalid DEK size: expected 32 bytes, got %d", len(dek))
	}
	if len(iv) != aes.BlockSize {
		return nil, fmt.Errorf("invalid IV size: expected %d bytes, got %d", aes.BlockSize, len(iv))
	}
	if plaintextOffset < 0 {
		return nil, fmt.Errorf("negative offset: %d", plaintextOffset)
	}

	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	counter := addCounter(iv, uint64(plaintextOffset)/aes.BlockSize)
	// #nosec G407 - the counter is derived from the per-object IV in metadata
	stream := cipher.NewCTR(block, counter)

	if skip := int(plaintextOffset % aes.BlockSize); skip > 0 {
		discard := make([]byte, skip)
		stream.XORKeyStream(discard, discard)
	}
	return stream, nil
}

// NewCTRRangeReader wraps a ciphertext reader positioned at plaintextOffset and
// yields the corresponding plaintext.
func NewCTRRangeReader(src io.Reader, dek, iv []byte, plaintextOffset int64) (io.Reader, error) {
	stream, err := NewCTRStreamAt(dek, iv, plaintextOffset)
	if err != nil {
		return nil, err
	}
	return &ctrStreamReader{reader: src, stream: stream}, nil
}

// addCounter adds blocks to a 16-byte big-endian counter block, wrapping like
// the AES-CTR counter itself does.
func addCounter(iv []byte, blocks uint64) []byte {
	out := make([]byte, len(iv))
	copy(out, iv)

	carry := blocks
	for i := len(out) - 1; i >= 0 && carry > 0; i-- {
		sum := uint64(out[i]) + (carry & 0xff)
		// Truncation to the low byte is the point: this is byte-wise addition
		// with the overflow carried into the next iteration below.
		out[i] = byte(sum) // #nosec G115

		carry = (carry >> 8) + (sum >> 8)
	}
	return out
}
