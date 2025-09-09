package dataencryption

import (
"context"
"testing"

"github.com/stretchr/testify/assert"
"github.com/stretchr/testify/require"
)

func TestAESCTRProvider_EncryptDecrypt(t *testing.T) {
provider := NewAESCTRDataEncryptor()
ctx := context.Background()

// Generate a DEK
dek, err := provider.GenerateDEK(ctx)
require.NoError(t, err)

// Test data
testData := []byte("Hello, World!")
associatedData := []byte("test-key")

// Encrypt
encryptedData, err := provider.Encrypt(ctx, testData, dek, associatedData)
require.NoError(t, err)
assert.NotEmpty(t, encryptedData)

// Decrypt
decrypted, err := provider.Decrypt(ctx, encryptedData, dek, associatedData)
require.NoError(t, err)
assert.Equal(t, testData, decrypted)
}

func TestAESCTRProvider_Algorithm(t *testing.T) {
provider := NewAESCTRDataEncryptor()
assert.Equal(t, "aes-256-ctr", provider.Algorithm())
}
