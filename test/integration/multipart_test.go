//go:build integration
// +build integration

package integration

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/guided-traffic/s3-encryption-proxy/internal/config"
	"github.com/guided-traffic/s3-encryption-proxy/internal/encryption"
)

// TestMultipartEncryptionManager tests the multipart encryption functionality without S3 backend
// Real MinIO integration tests are in multipart_e2e_test.go
func TestMultipartEncryptionManager(t *testing.T) {
	// Test only the encryption manager's multipart functionality

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

	uploadState, err := encMgr.CreateMultipartUpload(context.TODO(), uploadID, objectKey, "test-bucket")
	require.NoError(t, err)
	assert.NotNil(t, uploadState)

	// Test encrypting a part
	partNumber := 1
	testData := []byte("This is test data for part 1")

	encryptionResult, err := encMgr.EncryptMultipartData(context.TODO(), uploadID, partNumber, testData)
	require.NoError(t, err)
	assert.NotEqual(t, testData, encryptionResult.EncryptedData, "Data should be encrypted")
	assert.Greater(t, len(encryptionResult.EncryptedData), len(testData), "Encrypted data should be longer due to auth tag")

	// Test storing part metadata
	etag := "test-etag-1"
	err = encMgr.RecordPartETag(uploadID, partNumber, etag)
	require.NoError(t, err)

	// Test completing multipart upload
	finalState, err := encMgr.CompleteMultipartUpload(uploadID)
	require.NoError(t, err)
	assert.NotNil(t, finalState)

	t.Log("Multipart encryption manager test completed successfully")
}
