package encryption

import (
	"crypto/rand"
	"encoding/base64"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/guided-traffic/s3-encryption-proxy/internal/config"
)

func TestNewMetadataManager(t *testing.T) {
	prefix := "s3ep-"
	manager := NewMetadataManager(prefix)

	if manager.prefix != prefix {
		t.Errorf("Expected prefix %s, got %s", prefix, manager.prefix)
	}
}

func TestMetadataManager_AddHMACToMetadata(t *testing.T) {
	manager := NewMetadataManager("s3ep-")

	tests := []struct {
		name     string
		metadata map[string]string
		rawData  []byte
		dek      []byte
		enabled  bool
		wantErr  bool
		checkKey bool
	}{
		{
			name:     "valid HMAC addition",
			metadata: make(map[string]string),
			rawData:  []byte("test data"),
			dek:      make([]byte, 32), // 256-bit key
			enabled:  true,
			wantErr:  false,
			checkKey: true,
		},
		{
			name:     "disabled integrity verification",
			metadata: make(map[string]string),
			rawData:  []byte("test data"),
			dek:      make([]byte, 32),
			enabled:  false,
			wantErr:  false,
			checkKey: false,
		},
		{
			name:     "nil metadata",
			metadata: nil,
			rawData:  []byte("test data"),
			dek:      make([]byte, 32),
			enabled:  true,
			wantErr:  true,
			checkKey: false,
		},
		{
			name:     "empty raw data",
			metadata: make(map[string]string),
			rawData:  []byte{},
			dek:      make([]byte, 32),
			enabled:  true,
			wantErr:  true,
			checkKey: false,
		},
		{
			name:     "empty DEK",
			metadata: make(map[string]string),
			rawData:  []byte("test data"),
			dek:      []byte{},
			enabled:  true,
			wantErr:  true,
			checkKey: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Fill DEK with random data if not empty
			if len(tt.dek) > 0 {
				_, err := rand.Read(tt.dek)
				if err != nil {
					t.Fatalf("Failed to generate random DEK: %v", err)
				}
			}

			err := manager.AddHMACToMetadata(tt.metadata, tt.rawData, tt.dek, tt.enabled)

			if (err != nil) != tt.wantErr {
				t.Errorf("AddHMACToMetadata() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.checkKey {
				hmacKey := "s3ep-hmac"
				if _, exists := tt.metadata[hmacKey]; !exists {
					t.Errorf("Expected HMAC key %s to be present in metadata", hmacKey)
				}

				// Verify HMAC value is valid base64
				hmacValue := tt.metadata[hmacKey]
				_, err := base64.StdEncoding.DecodeString(hmacValue)
				if err != nil {
					t.Errorf("HMAC value is not valid base64: %v", err)
				}
			}

			if !tt.checkKey && tt.metadata != nil {
				hmacKey := "s3ep-hmac"
				if _, exists := tt.metadata[hmacKey]; exists {
					t.Errorf("HMAC key %s should not be present when disabled", hmacKey)
				}
			}
		})
	}
}

func TestMetadataManager_VerifyHMACFromMetadata(t *testing.T) {
	manager := NewMetadataManager("s3ep-")
	rawData := []byte("test data for verification")
	dek := make([]byte, 32)
	_, err := rand.Read(dek)
	if err != nil {
		t.Fatalf("Failed to generate random DEK: %v", err)
	}

	// Create metadata with valid HMAC
	metadata := make(map[string]string)
	err = manager.AddHMACToMetadata(metadata, rawData, dek, true)
	if err != nil {
		t.Fatalf("Failed to add HMAC to metadata: %v", err)
	}

	tests := []struct {
		name     string
		metadata map[string]string
		rawData  []byte
		dek      []byte
		enabled  bool
		wantOK   bool
		wantErr  bool
	}{
		{
			name:     "valid HMAC verification",
			metadata: metadata,
			rawData:  rawData,
			dek:      dek,
			enabled:  true,
			wantOK:   true,
			wantErr:  false,
		},
		{
			name:     "disabled verification (should pass)",
			metadata: metadata,
			rawData:  rawData,
			dek:      dek,
			enabled:  false,
			wantOK:   true,
			wantErr:  false,
		},
		{
			name:     "missing HMAC (backward compatibility)",
			metadata: make(map[string]string),
			rawData:  rawData,
			dek:      dek,
			enabled:  true,
			wantOK:   true,
			wantErr:  false,
		},
		{
			name:     "corrupted data",
			metadata: metadata,
			rawData:  []byte("corrupted data"),
			dek:      dek,
			enabled:  true,
			wantOK:   false,
			wantErr:  true,
		},
		{
			name:     "wrong DEK",
			metadata: metadata,
			rawData:  rawData,
			dek:      make([]byte, 32), // Different DEK
			enabled:  true,
			wantOK:   false,
			wantErr:  true,
		},
		{
			name:     "empty raw data",
			metadata: metadata,
			rawData:  []byte{},
			dek:      dek,
			enabled:  true,
			wantOK:   false,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Generate different DEK for "wrong DEK" test
			if tt.name == "wrong DEK" {
				_, err := rand.Read(tt.dek)
				if err != nil {
					t.Fatalf("Failed to generate different DEK: %v", err)
				}
			}

			ok, err := manager.VerifyHMACFromMetadata(tt.metadata, tt.rawData, tt.dek, tt.enabled)

			if (err != nil) != tt.wantErr {
				t.Errorf("VerifyHMACFromMetadata() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if ok != tt.wantOK {
				t.Errorf("VerifyHMACFromMetadata() ok = %v, wantOK %v", ok, tt.wantOK)
			}
		})
	}
}

func TestMetadataManager_ExtractHMACFromMetadata(t *testing.T) {
	manager := NewMetadataManager("s3ep-")

	tests := []struct {
		name        string
		metadata    map[string]string
		wantHMAC    bool
		wantExists  bool
		wantErr     bool
	}{
		{
			name: "valid HMAC extraction",
			metadata: map[string]string{
				"s3ep-hmac": base64.StdEncoding.EncodeToString([]byte("test-hmac-value")),
			},
			wantHMAC:   true,
			wantExists: true,
			wantErr:    false,
		},
		{
			name:       "missing HMAC",
			metadata:   make(map[string]string),
			wantHMAC:   false,
			wantExists: false,
			wantErr:    false,
		},
		{
			name: "invalid base64 HMAC",
			metadata: map[string]string{
				"s3ep-hmac": "invalid-base64!",
			},
			wantHMAC:   false,
			wantExists: true,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hmacBytes, exists, err := manager.ExtractHMACFromMetadata(tt.metadata)

			if (err != nil) != tt.wantErr {
				t.Errorf("ExtractHMACFromMetadata() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if exists != tt.wantExists {
				t.Errorf("ExtractHMACFromMetadata() exists = %v, wantExists %v", exists, tt.wantExists)
			}

			if tt.wantHMAC && hmacBytes == nil {
				t.Error("Expected HMAC bytes to be returned")
			}

			if !tt.wantHMAC && hmacBytes != nil {
				t.Error("Expected HMAC bytes to be nil")
			}
		})
	}
}

func TestMetadataManager_IsHMACMetadata(t *testing.T) {
	manager := NewMetadataManager("s3ep-")

	tests := []struct {
		name string
		key  string
		want bool
	}{
		{
			name: "HMAC metadata key",
			key:  "s3ep-hmac",
			want: true,
		},
		{
			name: "other encryption metadata",
			key:  "s3ep-encrypted-dek",
			want: false,
		},
		{
			name: "user metadata",
			key:  "user-metadata",
			want: false,
		},
		{
			name: "different prefix",
			key:  "other-hmac",
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := manager.IsHMACMetadata(tt.key); got != tt.want {
				t.Errorf("IsHMACMetadata() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMetadataManager_FilterHMACMetadata(t *testing.T) {
	manager := NewMetadataManager("s3ep-")

	tests := []struct {
		name     string
		input    map[string]string
		expected map[string]string
	}{
		{
			name: "filter HMAC from mixed metadata",
			input: map[string]string{
				"s3ep-hmac":          "hmac-value",
				"s3ep-encrypted-dek": "dek-value",
				"user-metadata":      "user-value",
			},
			expected: map[string]string{
				"s3ep-encrypted-dek": "dek-value",
				"user-metadata":      "user-value",
			},
		},
		{
			name:     "nil metadata",
			input:    nil,
			expected: nil,
		},
		{
			name:     "empty metadata",
			input:    make(map[string]string),
			expected: make(map[string]string),
		},
		{
			name: "no HMAC metadata",
			input: map[string]string{
				"s3ep-encrypted-dek": "dek-value",
				"user-metadata":      "user-value",
			},
			expected: map[string]string{
				"s3ep-encrypted-dek": "dek-value",
				"user-metadata":      "user-value",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := manager.FilterHMACMetadata(tt.input)

			if result == nil && tt.expected == nil {
				return
			}

			if result == nil || tt.expected == nil {
				t.Errorf("FilterHMACMetadata() result = %v, expected = %v", result, tt.expected)
				return
			}

			if len(result) != len(tt.expected) {
				t.Errorf("FilterHMACMetadata() result length = %d, expected length = %d", len(result), len(tt.expected))
				return
			}

			for key, expectedValue := range tt.expected {
				if resultValue, exists := result[key]; !exists || resultValue != expectedValue {
					t.Errorf("FilterHMACMetadata() key %s: got %s, expected %s", key, resultValue, expectedValue)
				}
			}

			// Ensure HMAC key is not present
			if _, exists := result["s3ep-hmac"]; exists {
				t.Error("FilterHMACMetadata() should remove HMAC metadata")
			}
		})
	}
}

func TestMetadataManager_GetHMACMetadataKey(t *testing.T) {
	tests := []struct {
		name     string
		prefix   string
		expected string
	}{
		{
			name:     "default prefix",
			prefix:   "s3ep-",
			expected: "s3ep-hmac",
		},
		{
			name:     "custom prefix",
			prefix:   "myapp-",
			expected: "myapp-hmac",
		},
		{
			name:     "no prefix",
			prefix:   "",
			expected: "hmac",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manager := NewMetadataManager(tt.prefix)
			if got := manager.GetHMACMetadataKey(); got != tt.expected {
				t.Errorf("GetHMACMetadataKey() = %v, expected %v", got, tt.expected)
			}
		})
	}
}

func TestMetadataManager_HMACIntegration(t *testing.T) {
	// Integration test: Add HMAC, then verify it
	manager := NewMetadataManager("s3ep-")
	rawData := []byte("integration test data")
	dek := make([]byte, 32)
	_, err := rand.Read(dek)
	if err != nil {
		t.Fatalf("Failed to generate random DEK: %v", err)
	}

	metadata := make(map[string]string)

	// Add HMAC
	err = manager.AddHMACToMetadata(metadata, rawData, dek, true)
	if err != nil {
		t.Fatalf("Failed to add HMAC: %v", err)
	}

	// Verify HMAC
	ok, err := manager.VerifyHMACFromMetadata(metadata, rawData, dek, true)
	if err != nil {
		t.Fatalf("Failed to verify HMAC: %v", err)
	}

	if !ok {
		t.Error("HMAC verification should have succeeded")
	}

	// Test with modified data (should fail)
	modifiedData := []byte("modified data")
	ok, err = manager.VerifyHMACFromMetadata(metadata, modifiedData, dek, true)
	if err == nil {
		t.Error("Expected error for modified data")
	}

	if ok {
		t.Error("HMAC verification should have failed for modified data")
	}
}

// MetadataManagerV2 Tests

func TestNewMetadataManagerV2(t *testing.T) {
	logger := logrus.WithField("test", "metadata_manager_v2")

	tests := []struct {
		name        string
		config      *config.Config
		expectError bool
		expectPrefix string
	}{
		{
			name: "default prefix",
			config: &config.Config{
				Encryption: config.EncryptionConfig{},
			},
			expectError:  false,
			expectPrefix: "s3ep-",
		},
		{
			name: "custom prefix",
			config: &config.Config{
				Encryption: config.EncryptionConfig{
					MetadataKeyPrefix: func(s string) *string { return &s }("custom-"),
				},
			},
			expectError:  false,
			expectPrefix: "custom-",
		},
		{
			name: "empty prefix",
			config: &config.Config{
				Encryption: config.EncryptionConfig{
					MetadataKeyPrefix: func(s string) *string { return &s }(""),
				},
			},
			expectError:  false,
			expectPrefix: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mm, err := NewMetadataManagerV2(tt.config, logger)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, mm)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, mm)
				assert.Equal(t, tt.expectPrefix, mm.GetPrefix())

				// Verify HMAC manager is embedded
				assert.NotNil(t, mm.GetHMACManager())
			}
		})
	}
}

func TestMetadataManagerV2_BuildExtractKeys(t *testing.T) {
	logger := logrus.WithField("test", "metadata_manager_v2")

	tests := []struct {
		name     string
		prefix   string
		baseKey  string
		expected string
	}{
		{
			name:     "with prefix",
			prefix:   "s3ep-",
			baseKey:  "encrypted-dek",
			expected: "s3ep-encrypted-dek",
		},
		{
			name:     "empty prefix",
			prefix:   "",
			baseKey:  "encrypted-dek",
			expected: "encrypted-dek",
		},
		{
			name:     "custom prefix",
			prefix:   "custom-",
			baseKey:  "kek-fingerprint",
			expected: "custom-kek-fingerprint",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &config.Config{
				Encryption: config.EncryptionConfig{
					MetadataKeyPrefix: &tt.prefix,
				},
			}

			mm, err := NewMetadataManagerV2(config, logger)
			require.NoError(t, err)

			// Test BuildMetadataKey
			fullKey := mm.BuildMetadataKey(tt.baseKey)
			assert.Equal(t, tt.expected, fullKey)

			// Test ExtractMetadataKey
			extractedKey := mm.ExtractMetadataKey(fullKey)
			assert.Equal(t, tt.baseKey, extractedKey)
		})
	}
}

func TestMetadataManagerV2_IsEncryptionMetadata(t *testing.T) {
	logger := logrus.WithField("test", "metadata_manager_v2")
	config := &config.Config{
		Encryption: config.EncryptionConfig{
			MetadataKeyPrefix: func(s string) *string { return &s }("s3ep-"),
		},
	}

	mm, err := NewMetadataManagerV2(config, logger)
	require.NoError(t, err)

	tests := []struct {
		key        string
		isEncryption bool
	}{
		{"s3ep-encrypted-dek", true},
		{"s3ep-kek-fingerprint", true},
		{"s3ep-hmac", true},
		{"s3ep-aes-iv", true},
		{"encrypted-dek", true}, // without prefix should still be detected
		{"user-custom-metadata", false},
		{"content-type", true}, // this is encryption metadata
		{"s3ep-user-data", false}, // not in the encryption keys list
	}

	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			result := mm.IsEncryptionMetadata(tt.key)
			assert.Equal(t, tt.isEncryption, result)
		})
	}
}

func TestMetadataManagerV2_FilterEncryptionMetadata(t *testing.T) {
	logger := logrus.WithField("test", "metadata_manager_v2")
	config := &config.Config{
		Encryption: config.EncryptionConfig{
			MetadataKeyPrefix: func(s string) *string { return &s }("s3ep-"),
		},
	}

	mm, err := NewMetadataManagerV2(config, logger)
	require.NoError(t, err)

	metadata := map[string]string{
		"s3ep-encrypted-dek":     "base64encrypteddek",
		"s3ep-kek-fingerprint":   "fingerprint123",
		"s3ep-hmac":              "hmacvalue",
		"user-custom-header":     "custom-value",
		"content-disposition":    "attachment",
		"x-amz-meta-user-data":   "user-data",
	}

	filtered := mm.FilterEncryptionMetadata(metadata)

	// Should only keep non-encryption metadata
	expected := map[string]string{
		"user-custom-header":   "custom-value",
		"content-disposition":  "attachment",
		"x-amz-meta-user-data": "user-data",
	}

	assert.Equal(t, expected, filtered)

	// Test with nil metadata
	assert.Nil(t, mm.FilterEncryptionMetadata(nil))
}

func TestMetadataManagerV2_ExtractRequiredFingerprint(t *testing.T) {
	logger := logrus.WithField("test", "metadata_manager_v2")
	config := &config.Config{
		Encryption: config.EncryptionConfig{
			MetadataKeyPrefix: func(s string) *string { return &s }("s3ep-"),
		},
	}

	mm, err := NewMetadataManagerV2(config, logger)
	require.NoError(t, err)

	tests := []struct {
		name        string
		metadata    map[string]string
		expected    string
	}{
		{
			name: "fingerprint with prefix",
			metadata: map[string]string{
				"s3ep-kek-fingerprint": "test-fingerprint-123",
			},
			expected: "test-fingerprint-123",
		},
		{
			name: "fingerprint without prefix",
			metadata: map[string]string{
				"kek-fingerprint": "fallback-fingerprint",
			},
			expected: "fallback-fingerprint",
		},
		{
			name: "legacy s3ep format",
			metadata: map[string]string{
				"s3ep-key-id": "legacy-fingerprint",
			},
			expected: "legacy-fingerprint",
		},
		{
			name: "multiple formats - prefixed takes priority",
			metadata: map[string]string{
				"s3ep-kek-fingerprint": "priority-fingerprint",
				"kek-fingerprint":      "fallback-fingerprint",
			},
			expected: "priority-fingerprint",
		},
		{
			name:     "no fingerprint",
			metadata: map[string]string{
				"some-other-key": "some-value",
			},
			expected: "",
		},
		{
			name:     "nil metadata",
			metadata: nil,
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := mm.ExtractRequiredFingerprint(tt.metadata)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestMetadataManagerV2_ValidateMetadata(t *testing.T) {
	logger := logrus.WithField("test", "metadata_manager_v2")
	config := &config.Config{
		Encryption: config.EncryptionConfig{
			MetadataKeyPrefix: func(s string) *string { return &s }("s3ep-"),
		},
	}

	mm, err := NewMetadataManagerV2(config, logger)
	require.NoError(t, err)

	tests := []struct {
		name        string
		metadata    map[string]string
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid metadata",
			metadata: map[string]string{
				"s3ep-encrypted-dek":   "base64encrypteddek",
				"s3ep-kek-fingerprint": "fingerprint123",
			},
			expectError: false,
		},
		{
			name: "missing encrypted-dek",
			metadata: map[string]string{
				"s3ep-kek-fingerprint": "fingerprint123",
			},
			expectError: true,
			errorMsg:    "missing required metadata keys",
		},
		{
			name: "missing kek-fingerprint",
			metadata: map[string]string{
				"s3ep-encrypted-dek": "base64encrypteddek",
			},
			expectError: true,
			errorMsg:    "missing required metadata keys",
		},
		{
			name:        "nil metadata",
			metadata:    nil,
			expectError: true,
			errorMsg:    "metadata cannot be nil",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := mm.ValidateMetadata(tt.metadata)

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestMetadataManagerV2_AddStandardMetadata(t *testing.T) {
	logger := logrus.WithField("test", "metadata_manager_v2")
	config := &config.Config{
		Encryption: config.EncryptionConfig{
			MetadataKeyPrefix: func(s string) *string { return &s }("s3ep-"),
		},
	}

	mm, err := NewMetadataManagerV2(config, logger)
	require.NoError(t, err)

	metadata := make(map[string]string)
	mm.AddStandardMetadata(metadata, "test-fingerprint", "aes-256-gcm")

	expected := map[string]string{
		"s3ep-kek-fingerprint": "test-fingerprint",
		"s3ep-algorithm":       "aes-256-gcm",
	}

	assert.Equal(t, expected, metadata)

	// Test with nil metadata (should not panic)
	mm.AddStandardMetadata(nil, "test", "test")

	// Test with empty algorithm
	metadata2 := make(map[string]string)
	mm.AddStandardMetadata(metadata2, "test-fingerprint", "")

	expected2 := map[string]string{
		"s3ep-kek-fingerprint": "test-fingerprint",
	}

	assert.Equal(t, expected2, metadata2)
}

func TestMetadataManagerV2_GetAlgorithmFromMetadata(t *testing.T) {
	logger := logrus.WithField("test", "metadata_manager_v2")
	config := &config.Config{
		Encryption: config.EncryptionConfig{
			MetadataKeyPrefix: func(s string) *string { return &s }("s3ep-"),
		},
	}

	mm, err := NewMetadataManagerV2(config, logger)
	require.NoError(t, err)

	tests := []struct {
		name     string
		metadata map[string]string
		expected string
	}{
		{
			name: "dek-algorithm with prefix",
			metadata: map[string]string{
				"s3ep-dek-algorithm": "aes-256-gcm",
			},
			expected: "aes-256-gcm",
		},
		{
			name: "algorithm with prefix",
			metadata: map[string]string{
				"s3ep-algorithm": "aes-256-ctr",
			},
			expected: "aes-256-ctr",
		},
		{
			name: "algorithm without prefix",
			metadata: map[string]string{
				"dek-algorithm": "fallback-algorithm",
			},
			expected: "fallback-algorithm",
		},
		{
			name: "no algorithm",
			metadata: map[string]string{
				"some-other-key": "some-value",
			},
			expected: "",
		},
		{
			name:     "nil metadata",
			metadata: nil,
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := mm.GetAlgorithmFromMetadata(tt.metadata)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestMetadataManagerV2_CreateMissingKEKError(t *testing.T) {
	logger := logrus.WithField("test", "metadata_manager_v2")
	config := &config.Config{
		Encryption: config.EncryptionConfig{
			MetadataKeyPrefix: func(s string) *string { return &s }("s3ep-"),
		},
	}

	mm, err := NewMetadataManagerV2(config, logger)
	require.NoError(t, err)

	metadata := map[string]string{
		"s3ep-kek-algorithm": "aes-256",
	}

	err = mm.CreateMissingKEKError("test-object", "missing-fingerprint", metadata)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "KEK_MISSING")
	assert.Contains(t, err.Error(), "test-object")
	assert.Contains(t, err.Error(), "missing-fingerprint")
	assert.Contains(t, err.Error(), "aes-256")
}

func TestMetadataManagerV2_ValidateConfiguration(t *testing.T) {
	logger := logrus.WithField("test", "metadata_manager_v2")

	tests := []struct {
		name        string
		config      *config.Config
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid configuration",
			config: &config.Config{
				Encryption: config.EncryptionConfig{
					MetadataKeyPrefix: func(s string) *string { return &s }("s3ep-") ,
				},
			},
			expectError: false,
		},
		{
			name: "valid empty prefix",
			config: &config.Config{
				Encryption: config.EncryptionConfig{
					MetadataKeyPrefix: func(s string) *string { return &s }("") ,
				},
			},
			expectError: false,
		},
		{
			name:        "nil configuration",
			config:      nil,
			expectError: true,
			errorMsg:    "configuration cannot be nil",
		},
		{
			name: "invalid prefix with space",
			config: &config.Config{
				Encryption: config.EncryptionConfig{
					MetadataKeyPrefix: func(s string) *string { return &s }("s3ep ") ,
				},
			},
			expectError: true,
			errorMsg:    "metadata prefix cannot contain whitespace characters",
		},
		{
			name: "invalid prefix with tab",
			config: &config.Config{
				Encryption: config.EncryptionConfig{
					MetadataKeyPrefix: func(s string) *string { return &s }("s3ep\t") ,
				},
			},
			expectError: true,
			errorMsg:    "metadata prefix cannot contain whitespace characters",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.config == nil {
				mm := &MetadataManagerV2{config: nil}
				err := mm.ValidateConfiguration()
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				mm, err := NewMetadataManagerV2(tt.config, logger)
				require.NoError(t, err)

				err = mm.ValidateConfiguration()
				if tt.expectError {
					assert.Error(t, err)
					assert.Contains(t, err.Error(), tt.errorMsg)
				} else {
					assert.NoError(t, err)
				}
			}
		})
	}
}

func TestMetadataManagerV2_HMACDelegation(t *testing.T) {
	logger := logrus.WithField("test", "metadata_manager_v2")
	config := &config.Config{
		Encryption: config.EncryptionConfig{
			MetadataKeyPrefix: func(s string) *string { return &s }("s3ep-"),
		},
	}

	mm, err := NewMetadataManagerV2(config, logger)
	require.NoError(t, err)

	// Test data
	metadata := make(map[string]string)
	rawData := []byte("test data for HMAC")
	dek := make([]byte, 32)
	rand.Read(dek)

	// Test HMAC operations are properly delegated
	t.Run("HMAC operations delegation", func(t *testing.T) {
		// Add HMAC
		err := mm.AddHMACToMetadata(metadata, rawData, dek, true)
		assert.NoError(t, err)
		assert.Contains(t, metadata, "s3ep-hmac")

		// Verify HMAC
		valid, err := mm.VerifyHMACFromMetadata(metadata, rawData, dek, true)
		assert.NoError(t, err)
		assert.True(t, valid)

		// Extract HMAC
		hmacValue, exists, err := mm.ExtractHMACFromMetadata(metadata)
		assert.NoError(t, err)
		assert.True(t, exists)
		assert.NotEmpty(t, hmacValue)

		// Check HMAC metadata key
		assert.True(t, mm.IsHMACMetadata("s3ep-hmac"))
		assert.False(t, mm.IsHMACMetadata("other-key"))

		// Filter HMAC metadata
		filtered := mm.FilterHMACMetadata(metadata)
		assert.NotContains(t, filtered, "s3ep-hmac")

		// Get HMAC metadata key
		assert.Equal(t, "s3ep-hmac", mm.GetHMACMetadataKey())
	})
}
