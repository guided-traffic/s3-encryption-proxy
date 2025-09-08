//go:build integration
// +build integration

package integration

import (
	"context"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption/factory"
	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption/keyencryption"
)

// TestMultipartEncryptionManager tests the multipart encryption functionality using Factory pattern
// Real MinIO integration tests are in multipart_e2e_test.go
func TestMultipartEncryptionManager(t *testing.T) {
	// Test the factory-based encryption with multipart content type

	// Create factory
	factoryInstance := factory.NewFactory()

	// Generate a test key and create AES key encryptor
	key := make([]byte, 32) // AES-256 key
	_, err := rand.Read(key)
	require.NoError(t, err)

	aesKeyEncryptor, err := keyencryption.NewAESKeyEncryptor(key)
	require.NoError(t, err)

	// Register the key encryptor with the factory
	factoryInstance.RegisterKeyEncryptor(aesKeyEncryptor)

	// Create envelope encryptor for multipart files (uses AES-CTR)
	envelopeEncryptor, err := factoryInstance.CreateEnvelopeEncryptor(factory.ContentTypeMultipart, aesKeyEncryptor.Fingerprint())
	require.NoError(t, err)

	ctx := context.Background()

	// Test data for multipart content (should use AES-CTR)
	testData := []byte("This is test data for multipart upload part 1")
	associatedData := []byte("test-bucket:test/object.txt")

	// Test encrypting multipart data
	encryptedData, encryptedDEK, metadata, err := envelopeEncryptor.EncryptData(ctx, testData, associatedData)
	require.NoError(t, err)
	require.NotEmpty(t, encryptedData)
	require.NotEmpty(t, encryptedDEK)
	require.NotNil(t, metadata)

	// Verify encrypted data is different from original
	assert.NotEqual(t, testData, encryptedData, "Data should be encrypted")

	// Test decrypting the data back
	decryptedData, err := factoryInstance.DecryptData(ctx, encryptedData, encryptedDEK, metadata, associatedData)
	require.NoError(t, err)
	require.NotNil(t, decryptedData)

	// Verify decrypted data matches original
	assert.Equal(t, testData, decryptedData, "Decrypted data should match original")

	// Verify metadata contains expected values
	assert.Equal(t, aesKeyEncryptor.Fingerprint(), metadata["kek_fingerprint"])
	assert.NotEmpty(t, metadata["data_algorithm"], "Should have data algorithm in metadata")

	t.Log("Multipart encryption factory test completed successfully")
}
