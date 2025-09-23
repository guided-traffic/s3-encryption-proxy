package factory

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFactory_CreateEnvelopeEncryptor(t *testing.T) {
	factory := NewFactory()

	// Create and register AES key encryptor
	aesKeyEncryptor, err := factory.CreateKeyEncryptorFromConfig(KeyEncryptionTypeAES, map[string]interface{}{
		"aes_key": "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=", // 32-byte key
	})
	require.NoError(t, err)
	factory.RegisterKeyEncryptor(aesKeyEncryptor)

	tests := []struct {
		name        string
		contentType ContentType
		expectError bool
	}{
		{
			name:        "multipart content uses AES-CTR",
			contentType: ContentTypeMultipart,
			expectError: false,
		},
		{
			name:        "whole file content uses AES-GCM",
			contentType: ContentTypeWhole,
			expectError: false,
		},
		{
			name:        "invalid content type fails",
			contentType: ContentType("invalid"),
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			envelopeEncryptor, err := factory.CreateEnvelopeEncryptor(tt.contentType, aesKeyEncryptor.Fingerprint())

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, envelopeEncryptor)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, envelopeEncryptor)
			}
		})
	}
}

func TestFactory_CreateKeyEncryptorFromConfig(t *testing.T) {
	factory := NewFactory()

	t.Run("AES key encryptor", func(t *testing.T) {
		keyEncryptor, err := factory.CreateKeyEncryptorFromConfig(KeyEncryptionTypeAES, map[string]interface{}{
			"aes_key": "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=",
		})
		assert.NoError(t, err)
		assert.NotNil(t, keyEncryptor)
		assert.NotEmpty(t, keyEncryptor.Fingerprint())
	})

	t.Run("RSA key encryptor", func(t *testing.T) {
		// This will fail with fake keys, but tests the structure
		_, err := factory.CreateKeyEncryptorFromConfig(KeyEncryptionTypeRSA, map[string]interface{}{
			"public_key_pem":  "fake-public-key",
			"private_key_pem": "fake-private-key",
		})
		assert.Error(t, err) // Expected to fail with fake keys
	})

	t.Run("unsupported key type", func(t *testing.T) {
		_, err := factory.CreateKeyEncryptorFromConfig(KeyEncryptionType("unsupported"), map[string]interface{}{})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported key encryption type")
	})
}

func TestFactory_GetRegisteredKeyEncryptors(t *testing.T) {
	factory := NewFactory()

	// Initially empty
	fingerprints := factory.GetRegisteredKeyEncryptors()
	assert.Empty(t, fingerprints)

	// Register a key encryptor
	keyEncryptor, err := factory.CreateKeyEncryptorFromConfig(KeyEncryptionTypeAES, map[string]interface{}{
		"aes_key": "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=",
	})
	require.NoError(t, err)
	factory.RegisterKeyEncryptor(keyEncryptor)

	// Check it's registered
	fingerprints = factory.GetRegisteredKeyEncryptors()
	assert.Len(t, fingerprints, 1)
	assert.Contains(t, fingerprints, keyEncryptor.Fingerprint())
}
