package keyencryption

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"

	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption"
)

// RSAConfig represents the configuration for RSA KeyEncryptor
type RSAConfig struct {
	PublicKeyPEM  string `yaml:"public_key_pem" json:"public_key_pem"`
	PrivateKeyPEM string `yaml:"private_key_pem" json:"private_key_pem"`
}

// RSAProvider implements encryption.KeyEncryptor using RSA for DEK encryption
// This handles ONLY DEK encryption/decryption with RSA keys
type RSAProvider struct {
	publicKey  *rsa.PublicKey
	privateKey *rsa.PrivateKey
}

// NewRSAProvider creates a new RSA key encryptor
func NewRSAProvider(publicKey *rsa.PublicKey, privateKey *rsa.PrivateKey) (encryption.KeyEncryptor, error) {
	if publicKey == nil {
		return nil, fmt.Errorf("public key cannot be nil")
	}

	if privateKey == nil {
		return nil, fmt.Errorf("private key cannot be nil")
	}

	// Validate key size (minimum 2048 bits)
	keySize := publicKey.N.BitLen()
	if keySize < 2048 {
		return nil, fmt.Errorf("RSA key size must be at least 2048 bits, got %d", keySize)
	}

	// Validate that private and public key match
	if err := validateRSAKeyPair(publicKey, privateKey); err != nil {
		return nil, fmt.Errorf("RSA key pair validation failed: %w", err)
	}

	return &RSAProvider{
		publicKey:  publicKey,
		privateKey: privateKey,
	}, nil
}

// NewRSAProviderFromPEM creates a new RSA key encryptor from PEM-encoded keys
func NewRSAProviderFromPEM(publicKeyPEM, privateKeyPEM string) (encryption.KeyEncryptor, error) {
	// Parse public key
	pubKey, err := parseRSAPublicKeyFromPEM(publicKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	// Parse private key
	privKey, err := parseRSAPrivateKeyFromPEM(privateKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	return NewRSAProvider(pubKey, privKey)
}

// NewRSAProviderFromConfig creates a new RSA KeyEncryptor from configuration
func NewRSAProviderFromConfig(config *RSAConfig) (encryption.KeyEncryptor, error) {
	if config == nil {
		return nil, fmt.Errorf("config cannot be nil")
	}

	if config.PublicKeyPEM == "" {
		return nil, fmt.Errorf("public_key_pem is required")
	}

	if config.PrivateKeyPEM == "" {
		return nil, fmt.Errorf("private_key_pem is required")
	}

	return NewRSAProviderFromPEM(config.PublicKeyPEM, config.PrivateKeyPEM)
}

// EncryptDEK encrypts a Data Encryption Key with the RSA public key using OAEP
func (p *RSAProvider) EncryptDEK(_ context.Context, dek []byte) ([]byte, string, error) {
	// Encrypt DEK with RSA public key using OAEP
	encryptedDEK, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, p.publicKey, dek, nil)
	if err != nil {
		return nil, "", fmt.Errorf("failed to encrypt DEK with RSA: %w", err)
	}

	return encryptedDEK, p.Fingerprint(), nil
}

// DecryptDEK decrypts a Data Encryption Key using the RSA private key
func (p *RSAProvider) DecryptDEK(_ context.Context, encryptedDEK []byte, keyID string) ([]byte, error) {
	// Verify key ID matches our fingerprint
	if keyID != p.Fingerprint() {
		return nil, fmt.Errorf("key ID mismatch: expected %s, got %s", p.Fingerprint(), keyID)
	}

	// Decrypt DEK with RSA private key using OAEP
	dek, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, p.privateKey, encryptedDEK, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt DEK with RSA: %w", err)
	}

	return dek, nil
}

// Name returns the short unique name for this KeyEncryptor type
func (p *RSAProvider) Name() string {
	return "rsa"
}

// Fingerprint returns a SHA-256 fingerprint of the RSA public key
// This allows identification of the correct KEK provider during decryption
func (p *RSAProvider) Fingerprint() string {
	// Create fingerprint from public key components
	keyData := append(p.publicKey.N.Bytes(), byte(p.publicKey.E))
	hash := sha256.Sum256(keyData)
	return hex.EncodeToString(hash[:])
}

// RotateKEK is not implemented for RSA key encryptor - requires manual key pair regeneration
func (p *RSAProvider) RotateKEK(_ context.Context) error {
	return fmt.Errorf("RSA key rotation is not implemented - requires manual key pair regeneration")
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

// validateRSAKeyPair validates that the private and public RSA keys are a matching pair
func validateRSAKeyPair(publicKey *rsa.PublicKey, privateKey *rsa.PrivateKey) error {
	// Check that the public key components match
	if privateKey.PublicKey.N.Cmp(publicKey.N) != 0 {
		return fmt.Errorf("public key modulus N does not match private key")
	}

	if privateKey.PublicKey.E != publicKey.E {
		return fmt.Errorf("public key exponent E does not match private key")
	}

	// Additional validation: Test encryption/decryption with a small test message
	testMessage := []byte("key-validation-test")

	// Encrypt with public key
	encrypted, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey, testMessage, nil)
	if err != nil {
		return fmt.Errorf("failed to encrypt test message with public key: %w", err)
	}

	// Decrypt with private key
	decrypted, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, encrypted, nil)
	if err != nil {
		return fmt.Errorf("failed to decrypt test message with private key: %w", err)
	}

	// Verify the message matches
	if string(decrypted) != string(testMessage) {
		return fmt.Errorf("key pair validation failed: decrypted message does not match original")
	}

	return nil
}
