package object

import (
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

// Simple test to verify package compiles and basic functionality
func TestHandler_BasicInitialization(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel) // Suppress logs in tests

	handler := &Handler{
		logger:         logger.WithField("component", "object-handler"),
		metadataPrefix: "s3ep-",
	}

	assert.NotNil(t, handler)
	assert.Equal(t, "s3ep-", handler.metadataPrefix)
}

func TestExtractEncryptionMetadata(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel)

	handler := &Handler{
		logger:         logger.WithField("component", "object-handler"),
		metadataPrefix: "s3ep-",
	}

	tests := []struct {
		name                  string
		metadata              map[string]string
		expectedDEK           string
		expectedHasEncryption bool
		expectedIsStreaming   bool
	}{
		{
			name:                  "No metadata",
			metadata:              nil,
			expectedDEK:           "",
			expectedHasEncryption: false,
			expectedIsStreaming:   false,
		},
		{
			name:                  "No encryption metadata",
			metadata:              map[string]string{"user-key": "user-value"},
			expectedDEK:           "",
			expectedHasEncryption: false,
			expectedIsStreaming:   false,
		},
		{
			name: "AES-GCM encryption",
			metadata: map[string]string{
				"s3ep-encrypted-dek": "ZW5jcnlwdGVkLWRlaw==",
				"s3ep-dek-algorithm": "aes-gcm",
			},
			expectedDEK:           "ZW5jcnlwdGVkLWRlaw==",
			expectedHasEncryption: true,
			expectedIsStreaming:   false,
		},
		{
			name: "AES-CTR encryption",
			metadata: map[string]string{
				"s3ep-encrypted-dek": "ZW5jcnlwdGVkLWRlaw==",
				"s3ep-dek-algorithm": "aes-ctr",
			},
			expectedDEK:           "ZW5jcnlwdGVkLWRlaw==",
			expectedHasEncryption: true,
			expectedIsStreaming:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dek, hasEncryption, isStreaming := handler.extractEncryptionMetadata(tt.metadata)
			assert.Equal(t, tt.expectedDEK, dek)
			assert.Equal(t, tt.expectedHasEncryption, hasEncryption)
			assert.Equal(t, tt.expectedIsStreaming, isStreaming)
		})
	}
}

func TestCleanMetadata(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel)

	handler := &Handler{
		logger:         logger.WithField("component", "object-handler"),
		metadataPrefix: "s3ep-",
	}

	tests := []struct {
		name     string
		metadata map[string]string
		expected map[string]string
	}{
		{
			name:     "Nil metadata",
			metadata: nil,
			expected: nil,
		},
		{
			name:     "Empty metadata",
			metadata: map[string]string{},
			expected: nil,
		},
		{
			name: "Only encryption metadata",
			metadata: map[string]string{
				"s3ep-encrypted-dek": "value",
				"s3ep-dek-algorithm": "aes-gcm",
			},
			expected: nil,
		},
		{
			name: "Mixed metadata",
			metadata: map[string]string{
				"user-key":           "user-value",
				"s3ep-encrypted-dek": "value",
				"another-user-key":   "another-value",
			},
			expected: map[string]string{
				"user-key":         "user-value",
				"another-user-key": "another-value",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := handler.cleanMetadata(tt.metadata)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsEncryptionMetadata(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel)

	handler := &Handler{
		logger:         logger.WithField("component", "object-handler"),
		metadataPrefix: "s3ep-",
	}

	tests := []struct {
		name     string
		key      string
		expected bool
	}{
		{
			name:     "Encryption metadata",
			key:      "s3ep-encrypted-dek",
			expected: true,
		},
		{
			name:     "Another encryption metadata",
			key:      "s3ep-dek-algorithm",
			expected: true,
		},
		{
			name:     "User metadata",
			key:      "user-key",
			expected: false,
		},
		{
			name:     "Similar but not encryption metadata",
			key:      "s3ep",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := handler.isEncryptionMetadata(tt.key)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGetSegmentSize(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel)

	handler := &Handler{
		logger:         logger.WithField("component", "object-handler"),
		metadataPrefix: "s3ep-",
	}

	segmentSize := handler.getSegmentSize()
	assert.Equal(t, int64(12*1024*1024), segmentSize) // 12MB default
}
