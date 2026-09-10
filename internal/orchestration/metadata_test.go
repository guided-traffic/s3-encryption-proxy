package orchestration

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

func createTestConfigWithoutPrefix() *config.Config {
	return &config.Config{
		Encryption: config.EncryptionConfig{
			MetadataKeyPrefix: nil,
		},
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

func TestGetMetadataPrefix(t *testing.T) {
	config := createTestConfigForMetadata()
	mm := NewMetadataManager(config, "custom-")
	assert.Equal(t, "custom-", mm.GetMetadataPrefix())

	mm2 := NewMetadataManager(config, "")
	assert.Equal(t, "s3ep-", mm2.GetMetadataPrefix())
}
