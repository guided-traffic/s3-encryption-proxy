package keyencryption

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/guided-traffic/s3-encryption-proxy/v5/pkg/encryption"
)

const (
	// KEKSize is the only accepted length of the master key: 32 random bytes.
	KEKSize = 32

	// MinDistinctKeyBytes is the entropy floor DecodeAESKey applies to a master
	// key.
	MinDistinctKeyBytes = 16

	// wrapSaltSize is the per-wrap salt that separates two wraps of the same DEK.
	wrapSaltSize = 16

	// The HKDF info strings. Distinct labels keep the published fingerprint and
	// the wrapping key independent derivations of the same master key.
	infoFingerprint = "s3ep-kek-fingerprint"
	infoWrap        = "s3ep-kek-wrap-v1"

	// aadWrap binds the wrapped DEK to its purpose.
	aadWrap = "s3ep-dek-wrap-v1"
)

// ErrWrappedDEKAuth is returned when a wrapped DEK fails authentication. It is
// distinct so a caller can tell a wrong or tampered key from a transport error
// before it reads a single body byte.
var ErrWrappedDEKAuth = errors.New("wrapped DEK authentication failed")

// AESProvider wraps Data Encryption Keys with a local AES-256 master key.
//
// The master key itself is never used directly: an HKDF pseudorandom key is
// extracted from it once, and both the published fingerprint and every wrapping
// key are expanded from that. Publishing a fingerprint therefore says nothing
// about the master key, and no two wraps share a key.
type AESProvider struct {
	prk         []byte
	fingerprint string
}

// NewAESKeyEncryptor creates an AES key encryptor from raw master key bytes.
func NewAESKeyEncryptor(kek []byte) (encryption.KeyEncryptor, error) {
	if len(kek) != KEKSize {
		return nil, fmt.Errorf("AES-256 key must be exactly %d bytes, got %d", KEKSize, len(kek))
	}

	prk, err := hkdf.Extract(sha256.New, kek, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to derive key material from AES key: %w", err)
	}

	fingerprint, err := hkdf.Expand(sha256.New, prk, infoFingerprint, sha256.Size)
	if err != nil {
		return nil, fmt.Errorf("failed to derive key fingerprint: %w", err)
	}

	return &AESProvider{prk: prk, fingerprint: hex.EncodeToString(fingerprint)}, nil
}

// NewAESProvider creates an AES key encryptor from the provider configuration.
// aes_key is base64 of exactly 32 bytes and nothing else; a string that decodes
// to another length, or does not decode at all, is a configuration error.
func NewAESProvider(config map[string]interface{}) (encryption.KeyEncryptor, error) {
	keyInterface, exists := config["aes_key"]
	if !exists {
		return nil, fmt.Errorf("missing 'aes_key' in configuration")
	}

	keyStr, ok := keyInterface.(string)
	if !ok {
		return nil, fmt.Errorf("aes_key must be a string")
	}

	kek, err := DecodeAESKey(keyStr)
	if err != nil {
		return nil, fmt.Errorf("aes_key: %w", err)
	}
	defer clear(kek)

	return NewAESKeyEncryptor(kek)
}

// DecodeAESKey decodes a configured AES master key and applies the admission
// rules every place that takes one shares: the proxy's configuration, the
// provider factory and the client library. The key is base64 of exactly 32
// bytes, and it must look random: a value that decodes to printable characters
// only is a passphrase, and one with fewer than MinDistinctKeyBytes distinct
// byte values is a pattern. A random key clears both with overwhelming
// probability; a typed one does not.
//
// The caller owns the returned bytes and should clear them once a key encryptor
// has been built from them.
func DecodeAESKey(b64 string) ([]byte, error) {
	kek, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(kek) != KEKSize {
		clear(kek)
		return nil, fmt.Errorf("must be base64 of exactly %d bytes", KEKSize)
	}

	printable := true
	distinct := make(map[byte]struct{}, KEKSize)
	for _, b := range kek {
		if b < 0x20 || b > 0x7e {
			printable = false
		}
		distinct[b] = struct{}{}
	}
	if printable {
		clear(kek)
		return nil, errors.New("decodes to printable characters only, which is a passphrase and not a key")
	}
	if len(distinct) < MinDistinctKeyBytes {
		clear(kek)
		return nil, fmt.Errorf("decodes to only %d distinct byte values", len(distinct))
	}
	return kek, nil
}

// EncryptDEK wraps a Data Encryption Key: a fresh salt, a wrapping key derived
// from it, and AES-256-GCM with a random nonce over the DEK.
func (p *AESProvider) EncryptDEK(_ context.Context, dek []byte) ([]byte, error) {
	salt := make([]byte, wrapSaltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("failed to generate DEK wrap salt: %w", err)
	}

	aead, err := p.wrapAEAD(salt)
	if err != nil {
		return nil, err
	}

	// #nosec G407 - NewGCMWithRandomNonce has a zero nonce size: it draws a
	// random nonce itself and prepends it, so the nonce argument must be empty.
	return aead.Seal(salt, nil, dek, []byte(aadWrap)), nil
}

// DecryptDEK unwraps a Data Encryption Key and fails closed on a tampered wrap.
func (p *AESProvider) DecryptDEK(_ context.Context, encryptedDEK []byte) ([]byte, error) {
	if len(encryptedDEK) <= wrapSaltSize {
		return nil, fmt.Errorf("%w: wrapped DEK too short, got %d bytes", ErrWrappedDEKAuth, len(encryptedDEK))
	}

	aead, err := p.wrapAEAD(encryptedDEK[:wrapSaltSize])
	if err != nil {
		return nil, err
	}

	dek, err := aead.Open(nil, nil, encryptedDEK[wrapSaltSize:], []byte(aadWrap))
	if err != nil {
		return nil, ErrWrappedDEKAuth
	}

	return dek, nil
}

// wrapAEAD derives the wrapping key for one salt.
func (p *AESProvider) wrapAEAD(salt []byte) (cipher.AEAD, error) {
	wrapKey, err := hkdf.Expand(sha256.New, p.prk, infoWrap+string(salt), KEKSize)
	if err != nil {
		return nil, fmt.Errorf("failed to derive DEK wrapping key: %w", err)
	}

	block, err := aes.NewCipher(wrapKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	return cipher.NewGCMWithRandomNonce(block)
}

// Name returns the short unique name for this KeyEncryptor type
func (p *AESProvider) Name() string {
	return "aes"
}

// Fingerprint identifies the master key without revealing anything about it.
func (p *AESProvider) Fingerprint() string {
	return p.fingerprint
}
