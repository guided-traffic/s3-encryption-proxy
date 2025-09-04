package integration

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/guided-traffic/s3-encryption-proxy/internal/config"
	"github.com/guided-traffic/s3-encryption-proxy/internal/encryption"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy"
)

func TestSimpleMultipartManagerIntegration(t *testing.T) {
	// Test only the encryption manager's multipart functionality
	// This is a more focused test without the complexities of mocking S3

	// Create test configuration
	testCfg := &config.Config{
		BindAddress:    "localhost:0",
		LogLevel:       "debug",
		TargetEndpoint: "http://localhost:9000", // Not used in this test
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
						"aes_key": "dGVzdC1rZXktMzItYnl0ZXMtZm9yLWFlcy0yNTYhISE=", // base64 of "test-key-32-bytes-for-aes-256!!!"
					},
				},
			},
		},
	}

	// Create encryption manager
	encMgr, err := encryption.NewManager(testCfg)
	require.NoError(t, err)

	// Test creating multipart upload state
	uploadID := "test-upload-123"
	objectKey := "test/object.txt"

	uploadState, err := encMgr.CreateMultipartUpload(nil, uploadID, objectKey)
	require.NoError(t, err)
	require.NotNil(t, uploadState)

	assert.Equal(t, uploadID, uploadState.UploadID)
	assert.Equal(t, objectKey, uploadState.ObjectKey)
	assert.Equal(t, "test-aes", uploadState.ProviderAlias)
	assert.NotEmpty(t, uploadState.DEK)

	// Test uploading parts
	part1Data := []byte("This is part 1 data")
	part2Data := []byte("This is part 2 data")

	// Encrypt part 1
	encryptedPart1, err := encMgr.EncryptMultipartData(nil, uploadID, 1, part1Data)
	require.NoError(t, err)
	require.NotNil(t, encryptedPart1)

	// Record part 1 ETag
	err = encMgr.RecordPartETag(uploadID, 1, "part1-etag")
	require.NoError(t, err)

	// Encrypt part 2
	encryptedPart2, err := encMgr.EncryptMultipartData(nil, uploadID, 2, part2Data)
	require.NoError(t, err)
	require.NotNil(t, encryptedPart2)

	// Record part 2 ETag
	err = encMgr.RecordPartETag(uploadID, 2, "part2-etag")
	require.NoError(t, err)

	// Test completing multipart upload
	completedState, err := encMgr.CompleteMultipartUpload(uploadID)
	require.NoError(t, err)
	require.NotNil(t, completedState)

	// Verify metadata contains encryption info
	assert.Equal(t, "test-aes", completedState.Metadata["provider_alias"])

	// Test that we can still access upload state after completion (it's not automatically cleaned up)
	finalState, err := encMgr.GetMultipartUploadState(uploadID)
	if err != nil {
		// Upload was cleaned up - this is also acceptable behavior
		t.Log("Upload state was cleaned up after completion - this is valid behavior")
	} else {
		// Upload state still exists - verify it has the correct data
		assert.Equal(t, "test-aes", finalState.Metadata["provider_alias"])
	}
}

func TestMultipartAbortIntegration(t *testing.T) {
	// Create test configuration
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
						"aes_key": "dGVzdC1rZXktMzItYnl0ZXMtZm9yLWFlcy0yNTYhISE=",
					},
				},
			},
		},
	}

	// Create encryption manager
	encMgr, err := encryption.NewManager(testCfg)
	require.NoError(t, err)

	// Test creating multipart upload
	uploadID := "test-upload-456"
	objectKey := "test/object-to-abort.txt"

	uploadState, err := encMgr.CreateMultipartUpload(nil, uploadID, objectKey)
	require.NoError(t, err)
	require.NotNil(t, uploadState)

	// Upload a part
	partData := []byte("This part will be aborted")
	encryptedPart, err := encMgr.EncryptMultipartData(nil, uploadID, 1, partData)
	require.NoError(t, err)
	require.NotNil(t, encryptedPart)

	// Abort the upload
	err = encMgr.AbortMultipartUpload(uploadID)
	require.NoError(t, err)

	// Verify upload state is cleaned up
	_, err = encMgr.EncryptMultipartData(nil, uploadID, 2, []byte("should fail"))
	assert.Error(t, err, "Upload should be cleaned up after abort")
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
						"aes_key": "dGVzdC1rZXktMzItYnl0ZXMtZm9yLWFlcy0yNTYhISE=",
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
