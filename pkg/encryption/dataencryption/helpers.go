package dataencryption

import (
	"crypto/rand"
	"fmt"

	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption"
)

// GenerateAESGCMKey generates a secure random 256-bit key for AES-GCM
func GenerateAESGCMKey() ([]byte, error) {
	key := make([]byte, 32) // 256 bits
	_, err := rand.Read(key)
	if err != nil {
		return nil, fmt.Errorf("failed to generate AES-GCM key: %w", err)
	}
	return key, nil
}

// GenerateAESCTRKey generates a secure random 256-bit key for AES-CTR
func GenerateAESCTRKey() ([]byte, error) {
	key := make([]byte, 32) // 256 bits
	_, err := rand.Read(key)
	if err != nil {
		return nil, fmt.Errorf("failed to generate AES-CTR key: %w", err)
	}
	return key, nil
}

// AESGCMConfig represents the configuration for AES-GCM DataEncryptor
type AESGCMConfig struct {
	Key []byte `yaml:"key" json:"key"`
}

// AESCTRConfig represents the configuration for AES-CTR DataEncryptor
type AESCTRConfig struct {
	Key []byte `yaml:"key" json:"key"`
}

// NewAESGCMProviderFromConfig creates a new AES-GCM DataEncryptor from configuration
func NewAESGCMProviderFromConfig(config AESGCMConfig) (encryption.DataEncryptor, error) {
	return NewAESGCMProvider(config.Key)
}

// NewAESCTRProviderFromConfig creates a new AES-CTR DataEncryptor from configuration
func NewAESCTRProviderFromConfig(config AESCTRConfig) (encryption.DataEncryptor, error) {
	return NewAESCTRProvider(config.Key)
}
