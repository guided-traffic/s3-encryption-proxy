package providers

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"

	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption"
)

// RSAEnvelopeConfig holds configuration for RSA envelope encryption
type RSAEnvelopeConfig struct {
	PublicKeyPEM  string `json:"public_key_pem" mapstructure:"public_key_pem"`   // PEM-encoded RSA public key
	PrivateKeyPEM string `json:"private_key_pem" mapstructure:"private_key_pem"` // PEM-encoded RSA private key
	KeySize       int    `json:"key_size" mapstructure:"key_size"`               // RSA key size (2048, 3072, 4096)
}

// Validate validates the RSA envelope configuration
func (c *RSAEnvelopeConfig) Validate() error {
	if c.PublicKeyPEM == "" {
		return fmt.Errorf("public_key_pem is required for RSA envelope provider")
	}

	if c.PrivateKeyPEM == "" {
		return fmt.Errorf("private_key_pem is required for RSA envelope provider")
	}

	// Validate public key
	if _, err := parseRSAPublicKeyFromPEM(c.PublicKeyPEM); err != nil {
		return fmt.Errorf("invalid public key: %w", err)
	}

	// Validate private key
	if _, err := parseRSAPrivateKeyFromPEM(c.PrivateKeyPEM); err != nil {
		return fmt.Errorf("invalid private key: %w", err)
	}

	// Validate key size if specified
	if c.KeySize != 0 {
		privateKey, _ := parseRSAPrivateKeyFromPEM(c.PrivateKeyPEM)
		actualKeySize := privateKey.N.BitLen()
		if actualKeySize != c.KeySize {
			return fmt.Errorf("key size mismatch: expected %d bits, got %d bits", c.KeySize, actualKeySize)
		}
	}

	return nil
}

// NewRSAEnvelopeProviderFromConfig creates a new RSA envelope provider from config
func NewRSAEnvelopeProviderFromConfig(config *RSAEnvelopeConfig) (*RSAEnvelopeProvider, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}

	publicKey, err := parseRSAPublicKeyFromPEM(config.PublicKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	privateKey, err := parseRSAPrivateKeyFromPEM(config.PrivateKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	return NewRSAEnvelopeProvider(publicKey, privateKey)
}

// RSAEnvelopeProvider implements RSA-based envelope encryption
// For each file, a new AES-256 key (DEK) is generated and encrypted with the RSA public key
type RSAEnvelopeProvider struct {
	publicKey  *rsa.PublicKey
	privateKey *rsa.PrivateKey
}

// NewRSAEnvelopeProvider creates a new RSA envelope encryption provider
func NewRSAEnvelopeProvider(publicKey *rsa.PublicKey, privateKey *rsa.PrivateKey) (*RSAEnvelopeProvider, error) {
	if publicKey == nil {
		return nil, fmt.Errorf("public key cannot be nil")
	}

	if privateKey == nil {
		return nil, fmt.Errorf("private key cannot be nil")
	}

	// Validate that the keys are a matching pair
	if !privateKey.PublicKey.Equal(publicKey) {
		return nil, fmt.Errorf("public and private keys do not match")
	}

	// Check minimum key size for security (2048 bits)
	keySize := publicKey.N.BitLen()
	if keySize < 2048 {
		return nil, fmt.Errorf("RSA key size too small: %d bits (minimum 2048 required)", keySize)
	}

	return &RSAEnvelopeProvider{
		publicKey:  publicKey,
		privateKey: privateKey,
	}, nil
}

// Encrypt encrypts data using RSA envelope encryption
// 1. Generate a random AES-256 key (DEK)
// 2. Encrypt the data with the DEK using AES-256-GCM
// 3. Encrypt the DEK with the RSA public key
// 4. Return encrypted data and encrypted DEK
func (p *RSAEnvelopeProvider) Encrypt(ctx context.Context, data []byte, associatedData []byte) (*encryption.EncryptionResult, error) {
	// 1. Generate a random AES-256 key (DEK)
	dek := make([]byte, 32) // 256 bits
	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		return nil, fmt.Errorf("failed to generate DEK: %w", err)
	}

	// 2. Encrypt the data with the DEK using AES-256-GCM
	encryptedData, nonce, err := p.encryptWithDEK(dek, data, associatedData)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt data with DEK: %w", err)
	}

	// 3. Encrypt the DEK with the RSA public key
	encryptedDEK, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, p.publicKey, dek, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt DEK with RSA: %w", err)
	}

	// 4. Prepend nonce to encrypted data
	finalEncryptedData := make([]byte, len(nonce)+len(encryptedData))
	copy(finalEncryptedData[:len(nonce)], nonce)
	copy(finalEncryptedData[len(nonce):], encryptedData)

	return &encryption.EncryptionResult{
		EncryptedData: finalEncryptedData,
		EncryptedDEK:  encryptedDEK,
		Metadata: map[string]string{
			"algorithm":     "rsa-envelope",
			"version":       "1.0",
			"rsa_key_size":  fmt.Sprintf("%d", p.publicKey.N.BitLen()),
			"aes_algorithm": "aes-256-gcm",
			"nonce_size":    fmt.Sprintf("%d", len(nonce)),
			"hash_function": "sha256",
		},
	}, nil
}

// Decrypt decrypts data using RSA envelope encryption
// 1. Decrypt the DEK with the RSA private key
// 2. Decrypt the data with the DEK using AES-256-GCM
func (p *RSAEnvelopeProvider) Decrypt(ctx context.Context, encryptedData []byte, encryptedDEK []byte, associatedData []byte) ([]byte, error) {
	if len(encryptedDEK) == 0 {
		return nil, fmt.Errorf("encrypted DEK is required for RSA envelope decryption")
	}

	// 1. Decrypt the DEK with the RSA private key
	dek, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, p.privateKey, encryptedDEK, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt DEK with RSA: %w", err)
	}

	// Validate DEK length
	if len(dek) != 32 {
		return nil, fmt.Errorf("invalid DEK length: expected 32 bytes, got %d", len(dek))
	}

	// 2. Decrypt the data with the DEK using AES-256-GCM
	plaintext, err := p.decryptWithDEK(dek, encryptedData, associatedData)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data with DEK: %w", err)
	}

	return plaintext, nil
}

// RotateKEK rotates the RSA key pair (not implemented - requires new key generation)
func (p *RSAEnvelopeProvider) RotateKEK(ctx context.Context) error {
	return fmt.Errorf("RSA key rotation requires manual key pair regeneration and configuration update")
}

// encryptWithDEK encrypts data with a DEK using AES-256-GCM
func (p *RSAEnvelopeProvider) encryptWithDEK(dek []byte, data []byte, associatedData []byte) ([]byte, []byte, error) {
	// Create AES cipher
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create GCM mode: %w", err)
	}

	// Generate random nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt data
	ciphertext := gcm.Seal(nil, nonce, data, associatedData)

	return ciphertext, nonce, nil
}

// decryptWithDEK decrypts data with a DEK using AES-256-GCM
func (p *RSAEnvelopeProvider) decryptWithDEK(dek []byte, encryptedData []byte, associatedData []byte) ([]byte, error) {
	// Create AES cipher
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM mode: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(encryptedData) < nonceSize {
		return nil, fmt.Errorf("encrypted data too short, expected at least %d bytes, got %d", nonceSize, len(encryptedData))
	}

	// Extract nonce and ciphertext
	nonce := encryptedData[:nonceSize]
	ciphertext := encryptedData[nonceSize:]

	// Decrypt data
	plaintext, err := gcm.Open(nil, nonce, ciphertext, associatedData)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data: %w", err)
	}

	return plaintext, nil
}

// parseRSAPublicKeyFromPEM parses an RSA public key from PEM format
func parseRSAPublicKeyFromPEM(pemData string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	if block.Type != "PUBLIC KEY" && block.Type != "RSA PUBLIC KEY" {
		return nil, fmt.Errorf("invalid PEM block type: %s", block.Type)
	}

	var publicKey *rsa.PublicKey
	var err error

	if block.Type == "PUBLIC KEY" {
		// PKIX format
		pubKeyInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PKIX public key: %w", err)
		}

		var ok bool
		publicKey, ok = pubKeyInterface.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("not an RSA public key")
		}
	} else {
		// PKCS#1 format
		publicKey, err = x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PKCS1 public key: %w", err)
		}
	}

	return publicKey, nil
}

// parseRSAPrivateKeyFromPEM parses an RSA private key from PEM format
func parseRSAPrivateKeyFromPEM(pemData string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	var privateKey *rsa.PrivateKey
	var err error

	switch block.Type {
	case "RSA PRIVATE KEY":
		// PKCS#1 format
		privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PKCS1 private key: %w", err)
		}
	case "PRIVATE KEY":
		// PKCS#8 format
		privKeyInterface, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PKCS8 private key: %w", err)
		}

		var ok bool
		privateKey, ok = privKeyInterface.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("not an RSA private key")
		}
	default:
		return nil, fmt.Errorf("invalid PEM block type: %s", block.Type)
	}

	return privateKey, nil
}

// GenerateRSAKeyPair generates a new RSA key pair
func GenerateRSAKeyPair(keySize int) (*rsa.PrivateKey, error) {
	if keySize < 2048 {
		return nil, fmt.Errorf("RSA key size too small: %d bits (minimum 2048 required)", keySize)
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key pair: %w", err)
	}

	return privateKey, nil
}

// RSAKeyPairToPEM converts an RSA key pair to PEM format
func RSAKeyPairToPEM(privateKey *rsa.PrivateKey) (string, string, error) {
	// Encode private key to PEM (PKCS#1 format)
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	// Encode public key to PEM (PKIX format)
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to marshal public key: %w", err)
	}

	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	return string(privateKeyPEM), string(publicKeyPEM), nil
}
