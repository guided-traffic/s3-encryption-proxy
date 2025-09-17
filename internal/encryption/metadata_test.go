package encryption

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/guided-traffic/s3-encryption-proxy/internal/config"
)

// Test helper functions

func createTestConfigForMetadata() *config.Config {
	prefix := "s3ep-"
	return &config.Config{
		Encryption: config.EncryptionConfig{
			MetadataKeyPrefix: &prefix,
		},
	}
}

func createTestConfigWithCustomPrefix(prefix string) *config.Config {
	return &config.Config{
		Encryption: config.EncryptionConfig{
			MetadataKeyPrefix: &prefix,
		},
	}
}

func createTestConfigWithoutPrefix() *config.Config {
	return &config.Config{
		Encryption: config.EncryptionConfig{
			MetadataKeyPrefix: nil,
		},
	}
}

func generateTestData() map[string]interface{} {
	return map[string]interface{}{
		"dek":          []byte("test-dek-32-bytes-long-for-aes256"),
		"encryptedDEK": []byte("encrypted-dek-data-example-bytes"),
		"iv":           []byte("test-iv-16-bytes"),
		"hmac":         []byte("test-hmac-32-bytes-long-example12"),
		"algorithm":    "aes-gcm",
		"fingerprint":  "test-fingerprint-12345",
		"kekAlgorithm": "aes",
	}
}

// Tests for MetadataManager

func TestNewMetadataManager(t *testing.T) {
	tests := []struct {
		name           string
		config         *config.Config
		prefix         string
		expectedPrefix string
	}{
		{
			name:           "with explicit prefix",
			config:         createTestConfigForMetadata(),
			prefix:         "custom-",
			expectedPrefix: "custom-",
		},
		{
			name:           "with config prefix (empty explicit prefix)",
			config:         createTestConfigForMetadata(),
			prefix:         "",
			expectedPrefix: "s3ep-",
		},
		{
			name:           "with default prefix (no config)",
			config:         createTestConfigWithoutPrefix(),
			prefix:         "",
			expectedPrefix: "s3ep-",
		},
		{
			name:           "with nil config",
			config:         nil,
			prefix:         "test-",
			expectedPrefix: "test-",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mm := NewMetadataManager(tt.config, tt.prefix)
			require.NotNil(t, mm)
			assert.Equal(t, tt.expectedPrefix, mm.GetMetadataPrefix())
			assert.Equal(t, tt.config, mm.config)
			assert.NotNil(t, mm.logger)
		})
	}
}

func TestBuildMetadataForEncryption(t *testing.T) {
	testData := generateTestData()
	config := createTestConfigForMetadata()
	mm := NewMetadataManager(config, "s3ep-")

	result := mm.BuildMetadataForEncryption(
		testData["dek"].([]byte),
		testData["encryptedDEK"].([]byte),
		testData["iv"].([]byte),
		testData["algorithm"].(string),
		testData["fingerprint"].(string),
		testData["kekAlgorithm"].(string),
		map[string]string{"user-key": "user-value"},
	)

	require.NotNil(t, result)
	assert.Contains(t, result, "s3ep-encrypted-dek")
	assert.Contains(t, result, "s3ep-dek-algorithm")
	assert.Contains(t, result, "s3ep-kek-fingerprint")
	assert.Contains(t, result, "s3ep-kek-algorithm")
	assert.Contains(t, result, "s3ep-aes-iv")
	assert.Contains(t, result, "user-key")
	
	assert.Equal(t, base64.StdEncoding.EncodeToString(testData["encryptedDEK"].([]byte)), result["s3ep-encrypted-dek"])
	assert.Equal(t, testData["algorithm"].(string), result["s3ep-dek-algorithm"])
	assert.Equal(t, testData["fingerprint"].(string), result["s3ep-kek-fingerprint"])
	assert.Equal(t, testData["kekAlgorithm"].(string), result["s3ep-kek-algorithm"])
	assert.Equal(t, base64.StdEncoding.EncodeToString(testData["iv"].([]byte)), result["s3ep-aes-iv"])
	assert.Equal(t, "user-value", result["user-key"])
}

func TestExtractEncryptionMetadata(t *testing.T) {
	config := createTestConfigForMetadata()
	mm := NewMetadataManager(config, "s3ep-")

	inputMetadata := map[string]string{
		"s3ep-encrypted-dek":   "test-dek",
		"s3ep-dek-algorithm":   "aes-gcm",
		"s3ep-kek-fingerprint": "test-fp",
		"user-key":             "user-value",
		"another-key":          "another-value",
	}

	result, err := mm.ExtractEncryptionMetadata(inputMetadata)
	require.NoError(t, err)
	assert.Len(t, result, 3)
	assert.Contains(t, result, "encrypted-dek")
	assert.Contains(t, result, "dek-algorithm")
	assert.Contains(t, result, "kek-fingerprint")
	assert.NotContains(t, result, "user-key")
	assert.NotContains(t, result, "another-key")
}

func TestFilterMetadataForClient(t *testing.T) {
	config := createTestConfigForMetadata()
	mm := NewMetadataManager(config, "s3ep-")

	inputMetadata := map[string]string{
		"s3ep-encrypted-dek":   "test-dek",
		"s3ep-dek-algorithm":   "aes-gcm",
		"s3ep-kek-fingerprint": "test-fp",
		"s3ep-hmac":            "test-hmac",
		"user-key":             "user-value",
		"content-type":         "text/plain",
		"another-key":          "another-value",
	}

	result := mm.FilterMetadataForClient(inputMetadata)
	
	assert.Contains(t, result, "user-key")
	assert.Contains(t, result, "content-type")
	assert.Contains(t, result, "another-key")
	assert.NotContains(t, result, "s3ep-encrypted-dek")
	assert.NotContains(t, result, "s3ep-dek-algorithm")
	assert.NotContains(t, result, "s3ep-kek-fingerprint")
	assert.NotContains(t, result, "s3ep-hmac")
}

func TestGetEncryptedDEK(t *testing.T) {
	config := createTestConfigForMetadata()
	mm := NewMetadataManager(config, "s3ep-")

	testDEK := []byte("test-encrypted-dek-data")
	encodedDEK := base64.StdEncoding.EncodeToString(testDEK)

	metadata := map[string]string{
		"s3ep-encrypted-dek": encodedDEK,
	}

	result, err := mm.GetEncryptedDEK(metadata)
	require.NoError(t, err)
	assert.Equal(t, testDEK, result)
}

func TestGetAlgorithm(t *testing.T) {
	config := createTestConfigForMetadata()
	mm := NewMetadataManager(config, "s3ep-")

	metadata := map[string]string{
		"s3ep-dek-algorithm": "aes-gcm",
	}

	result, err := mm.GetAlgorithm(metadata)
	require.NoError(t, err)
	assert.Equal(t, "aes-gcm", result)
}

func TestGetIV(t *testing.T) {
	config := createTestConfigForMetadata()
	mm := NewMetadataManager(config, "s3ep-")

	testIV := []byte("test-iv-16-bytes")
	encodedIV := base64.StdEncoding.EncodeToString(testIV)

	metadata := map[string]string{
		"s3ep-aes-iv": encodedIV,
	}

	result, err := mm.GetIV(metadata)
	require.NoError(t, err)
	assert.Equal(t, testIV, result)
}

func TestGetFingerprint(t *testing.T) {
	config := createTestConfigForMetadata()
	mm := NewMetadataManager(config, "s3ep-")

	metadata := map[string]string{
		"s3ep-kek-fingerprint": "test-fingerprint-12345",
	}

	result, err := mm.GetFingerprint(metadata)
	require.NoError(t, err)
	assert.Equal(t, "test-fingerprint-12345", result)
}

func TestGetKEKAlgorithm(t *testing.T) {
	config := createTestConfigForMetadata()
	mm := NewMetadataManager(config, "s3ep-")

	metadata := map[string]string{
		"s3ep-kek-algorithm": "aes",
	}

	result, err := mm.GetKEKAlgorithm(metadata)
	require.NoError(t, err)
	assert.Equal(t, "aes", result)
}

func TestHMACOperations(t *testing.T) {
	config := createTestConfigForMetadata()
	mm := NewMetadataManager(config, "s3ep-")

	hmac := []byte("test-hmac-32-bytes-long-example12")
	metadata := make(map[string]string)

	// Test SetHMAC
	mm.SetHMAC(metadata, hmac)
	assert.Contains(t, metadata, "s3ep-hmac")
	assert.Equal(t, base64.StdEncoding.EncodeToString(hmac), metadata["s3ep-hmac"])

	// Test GetHMAC
	result, err := mm.GetHMAC(metadata)
	require.NoError(t, err)
	assert.Equal(t, hmac, result)
}

func TestValidateEncryptionMetadata(t *testing.T) {
	config := createTestConfigForMetadata()
	mm := NewMetadataManager(config, "s3ep-")

	validMetadata := map[string]string{
		"s3ep-encrypted-dek":   base64.StdEncoding.EncodeToString([]byte("test-dek")),
		"s3ep-dek-algorithm":   "aes-gcm",
		"s3ep-kek-fingerprint": "test-fingerprint",
		"s3ep-kek-algorithm":   "aes",
	}

	err := mm.ValidateEncryptionMetadata(validMetadata)
	assert.NoError(t, err)

	// Test missing required field
	invalidMetadata := map[string]string{
		"s3ep-dek-algorithm":   "aes-gcm",
		"s3ep-kek-fingerprint": "test-fingerprint",
		"s3ep-kek-algorithm":   "aes",
		// missing encrypted-dek
	}

	err = mm.ValidateEncryptionMetadata(invalidMetadata)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "encrypted-dek is required")
}

func TestGetMetadataPrefix(t *testing.T) {
	config := createTestConfigForMetadata()
	mm := NewMetadataManager(config, "custom-")
	assert.Equal(t, "custom-", mm.GetMetadataPrefix())

	mm2 := NewMetadataManager(config, "")
	assert.Equal(t, "s3ep-", mm2.GetMetadataPrefix())
}
