package keyencryption

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption"
)

// RSAConfig represents the configuration for RSA KeyEncryptor
type RSAConfig struct {
	PublicKeyPEM  string `yaml:"public_key_pem" json:"public_key_pem"`
	PrivateKeyPEM string `yaml:"private_key_pem" json:"private_key_pem"`
}

// NewRSAProviderFromConfig creates a new RSA KeyEncryptor from configuration
func NewRSAProviderFromConfig(config RSAConfig) (encryption.KeyEncryptor, error) {
	return NewRSAProviderFromPEM(config.PublicKeyPEM, config.PrivateKeyPEM)
}

// GenerateRSAKeyPair generates a new RSA key pair with the specified bit size
func GenerateRSAKeyPair(bits int) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	if bits < 2048 {
		return nil, nil, fmt.Errorf("RSA key size must be at least 2048 bits, got %d", bits)
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate RSA key pair: %w", err)
	}

	return privateKey, &privateKey.PublicKey, nil
}

// RSAPrivateKeyToPEM converts an RSA private key to PEM format
func RSAPrivateKeyToPEM(privateKey *rsa.PrivateKey) (string, error) {
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	return string(privateKeyPEM), nil
}

// RSAPublicKeyToPEM converts an RSA public key to PEM format
func RSAPublicKeyToPEM(publicKey *rsa.PublicKey) (string, error) {
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", fmt.Errorf("failed to marshal public key: %w", err)
	}

	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	return string(publicKeyPEM), nil
}
