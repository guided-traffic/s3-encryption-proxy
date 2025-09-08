package keyencryption

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewAESProvider(t *testing.T) {
	provider, err := NewAESProvider(map[string]interface{}{
		"key": "12345678901234567890123456789012",
	})
	require.NoError(t, err)
	assert.NotNil(t, provider)
}

func TestAESProvider_EncryptDecrypt(t *testing.T) {
	provider, err := NewAESProvider(map[string]interface{}{
		"key": "12345678901234567890123456789012",
	})
	require.NoError(t, err)

	ctx := context.Background()
	testData := []byte("test data")
	associatedData := []byte("associated")

	result, err := provider.Encrypt(ctx, testData, associatedData)
	require.NoError(t, err)

	decrypted, err := provider.Decrypt(ctx, result.EncryptedData, result.EncryptedDEK, associatedData)
	require.NoError(t, err)
	assert.Equal(t, testData, decrypted)
}

func TestAESProvider_RotateKEK(t *testing.T) {
	provider, err := NewAESProvider(map[string]interface{}{
		"key": "12345678901234567890123456789012",
	})
	require.NoError(t, err)

	err = provider.RotateKEK(context.Background())
	require.NoError(t, err)
}