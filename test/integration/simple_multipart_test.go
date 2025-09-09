//go:build integration
// +build integration

package integration

import (
	"context"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/guided-traffic/s3-encryption-proxy/internal/config"
	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption/factory"
	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption/keyencryption"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy"
)

func TestSimpleMultipartManagerIntegration(t *testing.T) {
	// Test the factory-based encryption with multipart content type
	// This focuses on the encryption functionality rather than complex S3 mocking

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

	// Test encrypting multipart data (part 1)
	part1Data := []byte("This is part 1 data for multipart upload")
	associatedData1 := []byte("test-bucket:test/object.txt:1")

	encryptedData1, encryptedDEK1, metadata1, err := envelopeEncryptor.EncryptData(ctx, part1Data, associatedData1)
	require.NoError(t, err)
	require.NotEmpty(t, encryptedData1)
	require.NotEmpty(t, encryptedDEK1)
	require.NotNil(t, metadata1)
	assert.NotEqual(t, part1Data, encryptedData1, "Part 1 should be encrypted")

	// Test encrypting multipart data (part 2)
	part2Data := []byte("This is part 2 data for multipart upload")
	associatedData2 := []byte("test-bucket:test/object.txt:2")

	encryptedData2, encryptedDEK2, metadata2, err := envelopeEncryptor.EncryptData(ctx, part2Data, associatedData2)
	require.NoError(t, err)
	require.NotEmpty(t, encryptedData2)
	require.NotEmpty(t, encryptedDEK2)
	require.NotNil(t, metadata2)
	assert.NotEqual(t, part2Data, encryptedData2, "Part 2 should be encrypted")

	// Test decrypting part 1
	decryptedData1, err := factoryInstance.DecryptData(ctx, encryptedData1, encryptedDEK1, metadata1, associatedData1)
	require.NoError(t, err)
	assert.Equal(t, part1Data, decryptedData1, "Decrypted part 1 should match original")

	// Test decrypting part 2
	decryptedData2, err := factoryInstance.DecryptData(ctx, encryptedData2, encryptedDEK2, metadata2, associatedData2)
	require.NoError(t, err)
	assert.Equal(t, part2Data, decryptedData2, "Decrypted part 2 should match original")

	// Verify metadata contains expected values
	assert.Equal(t, aesKeyEncryptor.Fingerprint(), metadata1["kek-fingerprint"])
	assert.Equal(t, aesKeyEncryptor.Fingerprint(), metadata2["kek-fingerprint"])

	t.Log("Simple multipart factory integration test completed successfully")
}

func TestMultipartAbortIntegration(t *testing.T) {
	// Test that encryption factory handles different multipart scenarios properly
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

	// Test with different upload IDs to simulate abort scenarios
	partData := []byte("This part would be aborted in a real scenario")
	associatedData := []byte("test-bucket:test/object-to-abort.txt:1")

	// Encrypt part for upload that would be aborted
	encryptedData, encryptedDEK, metadata, err := envelopeEncryptor.EncryptData(ctx, partData, associatedData)
	require.NoError(t, err)
	require.NotEmpty(t, encryptedData)
	require.NotEmpty(t, encryptedDEK)
	require.NotNil(t, metadata)

	// Verify the part was encrypted (would normally be uploaded to S3)
	assert.NotEqual(t, partData, encryptedData, "Part should be encrypted")

	// Test that the same part can be encrypted again (simulating retry after abort)
	associatedData2 := []byte("test-bucket:test/object-to-abort.txt:retry:1")
	encryptedData2, encryptedDEK2, metadata2, err := envelopeEncryptor.EncryptData(ctx, partData, associatedData2)
	require.NoError(t, err)
	require.NotEmpty(t, encryptedData2)
	require.NotEmpty(t, encryptedDEK2)
	require.NotNil(t, metadata2)

	// Verify both encryptions worked but produced different results (due to different associated data)
	assert.NotEqual(t, encryptedData, encryptedData2, "Different associated data should produce different encrypted results")

	t.Log("Multipart abort simulation completed successfully")
}

func TestProxyServerCreation(t *testing.T) {
	// Test that we can create a proxy server with the test configuration
	testCfg := &config.Config{
		BindAddress:    "localhost:0",
		LogLevel:       "debug",
		TargetEndpoint: "http://localhost:9000",
		Region:         "us-east-1",
		AccessKeyID:    "test-access-key",
		SecretKey:      "test-secret-key",
		Encryption: config.EncryptionConfig{
			EncryptionMethodAlias: "test-aes",
			Providers: []config.EncryptionProvider{
				{
					Alias:       "test-aes",
					Type:        "aes-gcm",
					Description: "Test AES-GCM provider",
					Config: map[string]interface{}{
						"key": "dGVzdC1rZXktMzItYnl0ZXMtZm9yLWFlcy0yNTYhISE=",
					},
				},
			},
		},
	}

	// Create proxy server - this should work without errors
	proxyServer, err := proxy.NewServer(testCfg)
	require.NoError(t, err)
	require.NotNil(t, proxyServer)

	// Get the HTTP handler - this should also work
	handler := proxyServer.GetHandler()
	require.NotNil(t, handler)
}
