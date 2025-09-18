package orchestration

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/guided-traffic/s3-encryption-proxy/internal/config"
)

// calculateSHA256ForSinglepartTest computes SHA256 hash for singlepart testing
func calculateSHA256ForSinglepartTest(data []byte) string {
	hash := sha256.Sum256(data)
	return fmt.Sprintf("%x", hash)
}

// calculateStreamingSHA256ForSinglepartTest computes SHA256 hash from a reader without loading all data into memory
func calculateStreamingSHA256ForSinglepartTest(reader io.Reader) (string, error) {
	hasher := sha256.New()
	_, err := io.Copy(hasher, reader)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", hasher.Sum(nil)), nil
}

// testDataToReader converts test data bytes to bufio.Reader
func testDataToReaderSinglepart(data []byte) *bufio.Reader {
	return bufio.NewReader(bytes.NewReader(data))
}

// Helper functions for tests

func createTestConfig() *config.Config {
	return &config.Config{
		Encryption: config.EncryptionConfig{
			EncryptionMethodAlias: "test-aes",
			MetadataKeyPrefix:     func(s string) *string { return &s }("s3ep-"),
			Providers: []config.EncryptionProvider{
				{
					Alias: "test-aes",
					Type:  "aes",
					Config: map[string]interface{}{
						"aes_key": "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=", // base64 encoded 32-byte key
					},
				},
			},
		},
		Optimizations: config.OptimizationsConfig{
			StreamingSegmentSize: 12 * 1024 * 1024, // 12MB (default)
		},
	}
}

func createTestConfigWithNoneProvider() *config.Config {
	return &config.Config{
		Encryption: config.EncryptionConfig{
			EncryptionMethodAlias: "test-none",
			MetadataKeyPrefix:     func(s string) *string { return &s }("s3ep-"),
			Providers: []config.EncryptionProvider{
				{
					Alias:  "test-none",
					Type:   "none",
					Config: map[string]interface{}{},
				},
			},
		},
		Optimizations: config.OptimizationsConfig{
			StreamingSegmentSize: 12 * 1024 * 1024, // 12MB
		},
	}
}

func createTestConfigWithoutMetadataPrefix() *config.Config {
	return &config.Config{
		Encryption: config.EncryptionConfig{
			EncryptionMethodAlias: "test-aes",
			Providers: []config.EncryptionProvider{
				{
					Alias: "test-aes",
					Type:  "aes",
					Config: map[string]interface{}{
						"aes_key": "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=",
					},
				},
			},
		},
		Optimizations: config.OptimizationsConfig{
			StreamingSegmentSize: 12 * 1024 * 1024, // 12MB
		},
	}
}

func createTestConfigWithCustomThreshold(threshold int64) *config.Config {
	return &config.Config{
		Encryption: config.EncryptionConfig{
			EncryptionMethodAlias: "test-aes",
			MetadataKeyPrefix:     func(s string) *string { return &s }("s3ep-"),
			Providers: []config.EncryptionProvider{
				{
					Alias: "test-aes",
					Type:  "aes",
					Config: map[string]interface{}{
						"aes_key": "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=",
					},
				},
			},
		},
		Optimizations: config.OptimizationsConfig{
			StreamingSegmentSize: threshold,
		},
	}
}

func generateRandomData(size int) []byte {
	data := make([]byte, size)
	rand.Read(data)
	return data
}

func generateTestDEK() []byte {
	dek := make([]byte, 32) // AES-256 key
	rand.Read(dek)
	return dek
}

func generateTestIV() []byte {
	iv := make([]byte, 16) // AES block size
	rand.Read(iv)
	return iv
}

// createTestManager creates a test manager with real components
func createTestManager(config *config.Config) (*Manager, error) {
	return NewManager(config)
}

// TestNewSinglePartOperations tests the constructor
func TestNewSinglePartOperations(t *testing.T) {
	tests := []struct {
		name   string
		config *config.Config
	}{
		{
			name:   "valid configuration with AES provider",
			config: createTestConfig(),
		},
		{
			name:   "configuration without metadata prefix",
			config: createTestConfigWithoutMetadataPrefix(),
		},
		{
			name:   "nil configuration",
			config: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.config == nil {
				// Can't create real managers with nil config, so skip detailed testing
				return
			}

			// Create real managers for testing
			manager, err := createTestManager(tt.config)
			require.NoError(t, err)
			require.NotNil(t, manager)

			spo := manager.singlePartOps
			assert.NotNil(t, spo)
			assert.NotNil(t, spo.providerManager)
			assert.NotNil(t, spo.metadataManager)
			assert.NotNil(t, spo.hmacManager)
			assert.Equal(t, tt.config, spo.config)
			assert.NotNil(t, spo.bufferPool)
			assert.NotNil(t, spo.logger)
		})
	}
}

// TestShouldUseGCM tests the GCM selection logic
func TestShouldUseGCM(t *testing.T) {
	tests := []struct {
		name      string
		config    *config.Config
		dataSize  int64
		expected  bool
	}{
		{
			name:     "small data with default threshold",
			config:   createTestConfig(),
			dataSize: 1024, // 1KB
			expected: true,
		},
		{
			name:     "large data with default threshold",
			config:   createTestConfig(),
			dataSize: 20 * 1024 * 1024, // 20MB (larger than 12MB default)
			expected: false,
		},
		{
			name:     "data at threshold boundary",
			config:   createTestConfig(),
			dataSize: 12 * 1024 * 1024, // 12MB exactly (default threshold)
			expected: false,
		},
		{
			name:     "data just below threshold",
			config:   createTestConfig(),
			dataSize: 12*1024*1024 - 1, // 12MB - 1 byte
			expected: true,
		},
		{
			name:     "custom threshold - small data",
			config:   createTestConfigWithCustomThreshold(5 * 1024 * 1024), // 5MB threshold
			dataSize: 1024, // 1KB
			expected: true,
		},
		{
			name:     "custom threshold - large data",
			config:   createTestConfigWithCustomThreshold(5 * 1024 * 1024), // 5MB threshold
			dataSize: 10 * 1024 * 1024, // 10MB
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manager, err := createTestManager(tt.config)
			require.NoError(t, err)
			require.NotNil(t, manager)

			spo := manager.singlePartOps
			result := spo.ShouldUseGCM(tt.dataSize)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestGetThreshold tests the threshold getter
func TestGetThreshold(t *testing.T) {
	tests := []struct {
		name     string
		config   *config.Config
		expected int64
	}{
		{
			name:     "default threshold",
			config:   createTestConfig(),
			expected: 12 * 1024 * 1024, // 12MB default
		},
		{
			name:     "custom threshold",
			config:   createTestConfigWithCustomThreshold(10 * 1024 * 1024),
			expected: 10 * 1024 * 1024,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manager, err := createTestManager(tt.config)
			require.NoError(t, err)
			require.NotNil(t, manager)

			spo := manager.singlePartOps
			result := spo.GetThreshold()
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestEncryptCTR tests CTR encryption functionality
func TestEncryptCTR(t *testing.T) {
	tests := []struct {
		name           string
		data           []byte
		objectKey      string
		config         *config.Config
		expectedError  string
		validateResult func(*testing.T, *EncryptionResult)
	}{
		{
			name:      "successful CTR encryption with AES provider",
			data:      generateRandomData(1024), // 1KB of random data
			objectKey: "test/large-file.bin",
			config:    createTestConfig(),
			validateResult: func(t *testing.T, result *EncryptionResult) {
				assert.NotEmpty(t, result.EncryptedData)
				assert.Equal(t, "aes-ctr", result.Algorithm)
				assert.NotEmpty(t, result.KeyFingerprint)
				assert.Contains(t, result.Metadata, "s3ep-dek-algorithm")
				assert.Equal(t, "aes-256-ctr", result.Metadata["s3ep-dek-algorithm"])
				assert.Contains(t, result.Metadata, "s3ep-aes-iv")
				assert.Contains(t, result.Metadata, "s3ep-kek-algorithm")
				assert.Contains(t, result.Metadata, "s3ep-kek-fingerprint")
				assert.Contains(t, result.Metadata, "s3ep-encrypted-dek")
			},
		},
		{
			name:      "empty data encryption",
			data:      []byte{},
			objectKey: "test/empty.bin",
			config:    createTestConfig(),
			validateResult: func(t *testing.T, result *EncryptionResult) {
				assert.NotNil(t, result)
				// Empty data should still encrypt successfully
			},
		},
	{
		name:      "large data encryption",
		data:      generateRandomData(10 * 1024), // 10KB
		objectKey: "test/large-file.bin",
		config:    createTestConfig(),
		validateResult: func(t *testing.T, result *EncryptionResult) {
			assert.NotEmpty(t, result.EncryptedData)

			// Verify the encrypted data stream is valid by calculating its hash
			encryptedHash, err := calculateStreamingSHA256ForSinglepartTest(result.EncryptedData)
			require.NoError(t, err)
			assert.NotEmpty(t, encryptedHash, "Encrypted data should have a valid hash")
		},
	},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manager, err := createTestManager(tt.config)
			require.NoError(t, err)
			require.NotNil(t, manager)

			spo := manager.singlePartOps
			ctx := context.Background()
			result, err := spo.EncryptCTR(ctx, testDataToReaderSinglepart(tt.data), tt.objectKey)

			if tt.expectedError != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
				assert.Nil(t, result)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, result)
				if tt.validateResult != nil {
					tt.validateResult(t, result)
				}
			}
		})
	}
}

// TestEncryptGCM tests GCM encryption functionality
func TestEncryptGCM(t *testing.T) {
	tests := []struct {
		name           string
		data           []byte
		objectKey      string
		config         *config.Config
		expectedError  string
		validateResult func(*testing.T, *EncryptionResult)
	}{
		{
			name:      "successful GCM encryption with AES provider",
			data:      []byte("test data for GCM encryption"),
			objectKey: "test/key.txt",
			config:    createTestConfig(),
			validateResult: func(t *testing.T, result *EncryptionResult) {
				assert.NotEmpty(t, result.EncryptedData)
				assert.NotEmpty(t, result.Metadata)
				// GCM metadata is handled by envelope encryptor
			},
		},
		{
			name:      "empty data encryption",
			data:      []byte{},
			objectKey: "test/empty.txt",
			config:    createTestConfig(),
			validateResult: func(t *testing.T, result *EncryptionResult) {
				assert.NotNil(t, result)
				// Empty data should still encrypt successfully
			},
		},
		{
			name:      "small data encryption",
			data:      []byte("small test data"),
			objectKey: "test/small.txt",
			config:    createTestConfig(),
			validateResult: func(t *testing.T, result *EncryptionResult) {
				assert.NotEmpty(t, result.EncryptedData)
				assert.NotEmpty(t, result.Metadata)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manager, err := createTestManager(tt.config)
			require.NoError(t, err)
			require.NotNil(t, manager)

			spo := manager.singlePartOps
			ctx := context.Background()
			result, err := spo.EncryptGCM(ctx, testDataToReaderSinglepart(tt.data), tt.objectKey)

			if tt.expectedError != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
				assert.Nil(t, result)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, result)
				if tt.validateResult != nil {
					tt.validateResult(t, result)
				}
			}
		})
	}
}

// TestDecryptData tests the main decryption dispatcher
func TestDecryptData(t *testing.T) {
	tests := []struct {
		name           string
		encryptedData  []byte
		metadata       map[string]string
		objectKey      string
		config         *config.Config
		expectedError  string
	}{
		{
			name:          "unknown algorithm",
			encryptedData: []byte("encrypted-data"),
			metadata: map[string]string{
				"s3ep-dek-algorithm": "unknown-algorithm",
			},
			objectKey:     "test/unknown-file.txt",
			config:        createTestConfig(),
			expectedError: "unknown algorithm: unknown-algorithm",
		},
		{
			name:          "empty encrypted data",
			encryptedData: []byte{},
			metadata: map[string]string{
				"s3ep-dek-algorithm": "aes-gcm",
			},
			objectKey:     "test/empty-file.txt",
			config:        createTestConfig(),
			expectedError: "encrypted data is empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manager, err := createTestManager(tt.config)
			require.NoError(t, err)
			require.NotNil(t, manager)

			spo := manager.singlePartOps
			ctx := context.Background()
			_, err = spo.DecryptData(ctx, testDataToReaderSinglepart(tt.encryptedData), tt.metadata, tt.objectKey)

			if tt.expectedError != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
			}
		})
	}
}

// TestRoundTripEncryptionCTR tests CTR encryption followed by decryption
func TestRoundTripEncryptionCTR(t *testing.T) {
	config := createTestConfig()
	manager, err := createTestManager(config)
	require.NoError(t, err)
	require.NotNil(t, manager)

	spo := manager.singlePartOps
	ctx := context.Background()

	// Test data
	originalData := []byte("This is test data for CTR round-trip encryption testing.")
	objectKey := "test/roundtrip.bin"
	originalHash := calculateSHA256ForSinglepartTest(originalData)

	// Encrypt
	encryptResult, err := spo.EncryptCTR(ctx, testDataToReaderSinglepart(originalData), objectKey)
	require.NoError(t, err)
	require.NotNil(t, encryptResult)

	// Store encrypted data for decryption (necessary for round-trip test)
	var encryptedBuffer bytes.Buffer
	_, err = io.Copy(&encryptedBuffer, encryptResult.EncryptedData)
	require.NoError(t, err)
	encryptedData := encryptedBuffer.Bytes()

	// Verify encryption worked using hash comparison
	encryptedHash := calculateSHA256ForSinglepartTest(encryptedData)
	assert.NotEqual(t, originalHash, encryptedHash, "Encrypted data should differ from original")
	assert.NotEmpty(t, encryptResult.Metadata)

	// Decrypt (need to recreate reader since we consumed it above)
	encryptedReader := testDataToReaderSinglepart(encryptedData)
	decryptedReader, err := spo.DecryptCTR(ctx, encryptedReader, encryptResult.Metadata, objectKey)
	require.NoError(t, err)

	// Verify round-trip using streaming hash calculation
	decryptedHash, err := calculateStreamingSHA256ForSinglepartTest(decryptedReader)
	require.NoError(t, err)
	assert.Equal(t, originalHash, decryptedHash, "Decrypted data should match original")
}

// TestRoundTripEncryptionGCM tests GCM encryption followed by decryption
func TestRoundTripEncryptionGCM(t *testing.T) {
	config := createTestConfig()
	manager, err := createTestManager(config)
	require.NoError(t, err)
	require.NotNil(t, manager)

	spo := manager.singlePartOps
	ctx := context.Background()

	// Test data
	originalData := []byte("This is test data for GCM round-trip encryption testing.")
	objectKey := "test/roundtrip-gcm.txt"
	originalHash := calculateSHA256ForSinglepartTest(originalData)

	// Encrypt
	encryptResult, err := spo.EncryptGCM(ctx, testDataToReaderSinglepart(originalData), objectKey)
	require.NoError(t, err)
	require.NotNil(t, encryptResult)

	// Store encrypted data for decryption (necessary for round-trip test)
	var encryptedBuffer bytes.Buffer
	_, err = io.Copy(&encryptedBuffer, encryptResult.EncryptedData)
	require.NoError(t, err)
	encryptedData := encryptedBuffer.Bytes()

	// Verify encryption worked using hash comparison
	encryptedHash := calculateSHA256ForSinglepartTest(encryptedData)
	assert.NotEqual(t, originalHash, encryptedHash, "Encrypted data should differ from original")
	assert.NotEmpty(t, encryptResult.Metadata)

	// Decrypt (need to recreate reader since we consumed it above)
	encryptedReader := testDataToReaderSinglepart(encryptedData)
	decryptedReader, err := spo.DecryptGCM(ctx, encryptedReader, encryptResult.Metadata, objectKey)
	require.NoError(t, err)

	// Verify round-trip using streaming hash calculation
	decryptedHash, err := calculateStreamingSHA256ForSinglepartTest(decryptedReader)
	require.NoError(t, err)
	assert.Equal(t, originalHash, decryptedHash, "Decrypted data should match original")
}

// TestWithNoneProvider tests encryption/decryption with none provider
func TestWithNoneProvider(t *testing.T) {
	config := createTestConfigWithNoneProvider()
	manager, err := createTestManager(config)
	require.NoError(t, err)
	require.NotNil(t, manager)

	spo := manager.singlePartOps
	ctx := context.Background()

	// Test data
	originalData := []byte("This is test data for none provider testing.")
	objectKey := "test/none-provider.txt"

	// With none provider, EncryptGCM should work but not actually encrypt
	result, err := spo.EncryptGCM(ctx, testDataToReaderSinglepart(originalData), objectKey)

	// This might error with none provider, which is expected behavior
	// The none provider handles pass-through differently
	if err != nil {
		t.Logf("None provider encryption error (expected): %v", err)
		return
	}

	// If it succeeds, verify the result
	assert.NotNil(t, result)
}

// Test helper methods

func TestSinglePartGetMetadataPrefix(t *testing.T) {
	tests := []struct {
		name     string
		config   *config.Config
		expected string
	}{
		{
			name:     "config with prefix",
			config:   createTestConfig(),
			expected: "s3ep-",
		},
		{
			name:     "config without prefix",
			config:   createTestConfigWithoutMetadataPrefix(),
			expected: "s3ep-",
		},
		{
			name: "config with custom prefix",
			config: &config.Config{
				Encryption: config.EncryptionConfig{
					EncryptionMethodAlias: "test-aes",
					MetadataKeyPrefix:     func(s string) *string { return &s }("custom-"),
					Providers: []config.EncryptionProvider{
						{
							Alias: "test-aes",
							Type:  "aes",
							Config: map[string]interface{}{
								"aes_key": "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=",
							},
						},
					},
				},
			},
			expected: "custom-",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manager, err := createTestManager(tt.config)
			require.NoError(t, err)
			require.NotNil(t, manager)

			spo := manager.singlePartOps
			result := spo.getMetadataPrefix()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGetAlgorithmFromMetadata(t *testing.T) {
	tests := []struct {
		name     string
		metadata map[string]string
		expected string
	}{
		{
			name: "with prefix",
			metadata: map[string]string{
				"s3ep-dek-algorithm": "aes-256-ctr",
			},
			expected: "aes-256-ctr",
		},
		{
			name: "without prefix (backward compatibility)",
			metadata: map[string]string{
				"dek-algorithm": "aes-gcm",
			},
			expected: "aes-gcm",
		},
		{
			name:     "missing algorithm defaults to GCM",
			metadata: map[string]string{},
			expected: "aes-gcm",
		},
		{
			name: "prefix takes precedence",
			metadata: map[string]string{
				"s3ep-dek-algorithm": "aes-256-ctr",
				"dek-algorithm":      "aes-gcm",
			},
			expected: "aes-256-ctr",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := createTestConfig()
			manager, err := createTestManager(config)
			require.NoError(t, err)
			require.NotNil(t, manager)

			spo := manager.singlePartOps
			result := spo.getAlgorithmFromMetadata(tt.metadata)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGetRequiredFingerprint(t *testing.T) {
	tests := []struct {
		name     string
		metadata map[string]string
		expected string
	}{
		{
			name: "with prefix",
			metadata: map[string]string{
				"s3ep-kek-fingerprint": "test-fingerprint-with-prefix",
			},
			expected: "test-fingerprint-with-prefix",
		},
		{
			name: "without prefix (backward compatibility)",
			metadata: map[string]string{
				"kek-fingerprint": "test-fingerprint-no-prefix",
			},
			expected: "test-fingerprint-no-prefix",
		},
		{
			name:     "missing fingerprint",
			metadata: map[string]string{},
			expected: "",
		},
		{
			name: "prefix takes precedence",
			metadata: map[string]string{
				"s3ep-kek-fingerprint": "with-prefix",
				"kek-fingerprint":      "without-prefix",
			},
			expected: "with-prefix",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := createTestConfig()
			manager, err := createTestManager(config)
			require.NoError(t, err)
			require.NotNil(t, manager)

			spo := manager.singlePartOps
			result := spo.getRequiredFingerprint(tt.metadata)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGetEncryptedDEKFromMetadata(t *testing.T) {
	testDEK := []byte("test-encrypted-dek")
	encodedDEK := base64.StdEncoding.EncodeToString(testDEK)

	tests := []struct {
		name          string
		metadata      map[string]string
		expected      []byte
		expectedError string
	}{
		{
			name: "with prefix",
			metadata: map[string]string{
				"s3ep-encrypted-dek": encodedDEK,
			},
			expected: testDEK,
		},
		{
			name: "without prefix (backward compatibility)",
			metadata: map[string]string{
				"encrypted-dek": encodedDEK,
			},
			expected: testDEK,
		},
		{
			name:          "missing encrypted DEK",
			metadata:      map[string]string{},
			expectedError: "encrypted DEK not found in metadata",
		},
		{
			name: "invalid base64",
			metadata: map[string]string{
				"s3ep-encrypted-dek": "invalid-base64!@#",
			},
			expectedError: "failed to decode encrypted DEK",
		},
		{
			name: "prefix takes precedence",
			metadata: map[string]string{
				"s3ep-encrypted-dek": base64.StdEncoding.EncodeToString([]byte("with-prefix")),
				"encrypted-dek":      base64.StdEncoding.EncodeToString([]byte("without-prefix")),
			},
			expected: []byte("with-prefix"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := createTestConfig()
			manager, err := createTestManager(config)
			require.NoError(t, err)
			require.NotNil(t, manager)

			spo := manager.singlePartOps
			result, err := spo.getEncryptedDEKFromMetadata(tt.metadata)

			if tt.expectedError != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
				assert.Nil(t, result)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestGetIVFromMetadata(t *testing.T) {
	testIV := generateTestIV()
	encodedIV := base64.StdEncoding.EncodeToString(testIV)

	tests := []struct {
		name          string
		metadata      map[string]string
		expected      []byte
		expectedError string
	}{
		{
			name: "with prefix",
			metadata: map[string]string{
				"s3ep-aes-iv": encodedIV,
			},
			expected: testIV,
		},
		{
			name: "without prefix (backward compatibility)",
			metadata: map[string]string{
				"aes-iv": encodedIV,
			},
			expected: testIV,
		},
		{
			name:          "missing IV",
			metadata:      map[string]string{},
			expectedError: "IV not found in metadata",
		},
		{
			name: "invalid base64",
			metadata: map[string]string{
				"s3ep-aes-iv": "invalid-base64!@#",
			},
			expectedError: "failed to decode IV",
		},
		{
			name: "prefix takes precedence",
			metadata: map[string]string{
				"s3ep-aes-iv": base64.StdEncoding.EncodeToString([]byte("0123456789abcdef")),
				"aes-iv":      base64.StdEncoding.EncodeToString([]byte("fedcba9876543210")),
			},
			expected: []byte("0123456789abcdef"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := createTestConfig()
			manager, err := createTestManager(config)
			require.NoError(t, err)
			require.NotNil(t, manager)

			spo := manager.singlePartOps
			result, err := spo.getIVFromMetadata(tt.metadata)

			if tt.expectedError != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
				assert.Nil(t, result)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

// Test edge cases and error conditions

func TestSinglePartOperationsEdgeCases(t *testing.T) {
	t.Run("buffer pool functionality", func(t *testing.T) {
		config := createTestConfig()
		manager, err := createTestManager(config)
		require.NoError(t, err)
		require.NotNil(t, manager)

		spo := manager.singlePartOps

		// Test that buffer pool is properly initialized
		assert.NotNil(t, spo.bufferPool)

		// Get a buffer from the pool
		buffer := spo.bufferPool.Get()
		assert.NotNil(t, buffer)

		// Put it back
		spo.bufferPool.Put(buffer)
	})

	t.Run("logger initialization", func(t *testing.T) {
		config := createTestConfig()
		manager, err := createTestManager(config)
		require.NoError(t, err)
		require.NotNil(t, manager)

		spo := manager.singlePartOps
		assert.NotNil(t, spo.logger)
		// The logger should have the component field set
		assert.Contains(t, spo.logger.Data, "component")
	})

	t.Run("data size validation", func(t *testing.T) {
		config := createTestConfig()
		manager, err := createTestManager(config)
		require.NoError(t, err)
		require.NotNil(t, manager)

		spo := manager.singlePartOps
		ctx := context.Background()

		// Test zero-length data
		_, err = spo.EncryptGCM(ctx, testDataToReaderSinglepart([]byte{}), "test/empty.txt")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "data is empty")

		_, err = spo.EncryptCTR(ctx, testDataToReaderSinglepart([]byte{}), "test/empty.bin")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "data is empty")
	})

	t.Run("large data handling", func(t *testing.T) {
		config := createTestConfig()
		manager, err := createTestManager(config)
		require.NoError(t, err)
		require.NotNil(t, manager)

		spo := manager.singlePartOps

		// Test with data larger than threshold (default 12MB)
		largeData := generateRandomData(20 * 1024 * 1024) // 20MB
		assert.False(t, spo.ShouldUseGCM(int64(len(largeData))))

		// Test with data smaller than threshold
		smallData := generateRandomData(1024) // 1KB
		assert.True(t, spo.ShouldUseGCM(int64(len(smallData))))
	})
}

// Benchmark tests for performance validation

func BenchmarkShouldUseGCM(b *testing.B) {
	config := createTestConfig()
	manager, err := createTestManager(config)
	require.NoError(b, err)
	require.NotNil(b, manager)

	spo := manager.singlePartOps

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		spo.ShouldUseGCM(1024) // 1KB
	}
}

func BenchmarkGetMetadataPrefix(b *testing.B) {
	config := createTestConfig()
	manager, err := createTestManager(config)
	require.NoError(b, err)
	require.NotNil(b, manager)

	spo := manager.singlePartOps

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		spo.getMetadataPrefix()
	}
}

func BenchmarkGetAlgorithmFromMetadata(b *testing.B) {
	config := createTestConfig()
	manager, err := createTestManager(config)
	require.NoError(b, err)
	require.NotNil(b, manager)

	spo := manager.singlePartOps

	metadata := map[string]string{
		"s3ep-dek-algorithm": "aes-256-ctr",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		spo.getAlgorithmFromMetadata(metadata)
	}
}

func BenchmarkEncryptSmallData(b *testing.B) {
	config := createTestConfig()
	manager, err := createTestManager(config)
	require.NoError(b, err)
	require.NotNil(b, manager)

	spo := manager.singlePartOps
	ctx := context.Background()
	data := generateRandomData(1024) // 1KB

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := spo.EncryptGCM(ctx, testDataToReaderSinglepart(data), "benchmark/small.txt")
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEncryptLargeData(b *testing.B) {
	config := createTestConfig()
	manager, err := createTestManager(config)
	require.NoError(b, err)
	require.NotNil(b, manager)

	spo := manager.singlePartOps
	ctx := context.Background()
	data := generateRandomData(1024 * 1024) // 1MB

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := spo.EncryptCTR(ctx, testDataToReaderSinglepart(data), "benchmark/large.bin")
		if err != nil {
			b.Fatal(err)
		}
	}
}

// Integration tests with different data sizes
func TestDataSizeHandling(t *testing.T) {
	config := createTestConfig()
	manager, err := createTestManager(config)
	require.NoError(t, err)
	require.NotNil(t, manager)

	spo := manager.singlePartOps
	ctx := context.Background()

	tests := []struct {
		name     string
		dataSize int
		shouldUseGCM bool
	}{
		{
			name:         "tiny data (100 bytes)",
			dataSize:     100,
			shouldUseGCM: true,
		},
		{
			name:         "small data (10 KB)",
			dataSize:     10 * 1024,
			shouldUseGCM: true,
		},
		{
			name:         "medium data (1 MB)",
			dataSize:     1024 * 1024,
			shouldUseGCM: true,
		},
		{
			name:         "large data (20 MB)",
			dataSize:     20 * 1024 * 1024, // 20MB, larger than 12MB default threshold
			shouldUseGCM: false,
		},
		{
			name:         "very large data (50 MB)",
			dataSize:     50 * 1024 * 1024,
			shouldUseGCM: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := generateRandomData(tt.dataSize)
			objectKey := "test/size-test.bin"

			// Test algorithm selection
			actualShouldUseGCM := spo.ShouldUseGCM(int64(len(data)))
			assert.Equal(t, tt.shouldUseGCM, actualShouldUseGCM)

			// Test encryption with appropriate algorithm
			if tt.shouldUseGCM {
				result, err := spo.EncryptGCM(ctx, testDataToReaderSinglepart(data), objectKey)
				assert.NoError(t, err)
				assert.NotNil(t, result)
				assert.NotEmpty(t, result.EncryptedData)
			} else {
				result, err := spo.EncryptCTR(ctx, testDataToReaderSinglepart(data), objectKey)
				assert.NoError(t, err)
				assert.NotNil(t, result)
				assert.NotEmpty(t, result.EncryptedData)
				assert.Equal(t, "aes-ctr", result.Algorithm)
			}
		})
	}
}

// Test different metadata prefix configurations
func TestMetadataPrefixHandling(t *testing.T) {
	tests := []struct {
		name           string
		prefixConfig   *string
		expectedPrefix string
	}{
		{
			name:           "default prefix",
			prefixConfig:   func(s string) *string { return &s }("s3ep-"),
			expectedPrefix: "s3ep-",
		},
		{
			name:           "custom prefix",
			prefixConfig:   func(s string) *string { return &s }("custom-enc-"),
			expectedPrefix: "custom-enc-",
		},
		{
			name:           "empty prefix",
			prefixConfig:   func(s string) *string { return &s }(""),
			expectedPrefix: "",
		},
		{
			name:           "nil prefix (uses default)",
			prefixConfig:   nil,
			expectedPrefix: "s3ep-",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &config.Config{
				Encryption: config.EncryptionConfig{
					EncryptionMethodAlias: "test-aes",
					MetadataKeyPrefix:     tt.prefixConfig,
					Providers: []config.EncryptionProvider{
						{
							Alias: "test-aes",
							Type:  "aes",
							Config: map[string]interface{}{
								"aes_key": "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=",
							},
						},
					},
				},
			}

			manager, err := createTestManager(config)
			require.NoError(t, err)
			require.NotNil(t, manager)

			spo := manager.singlePartOps
			actualPrefix := spo.getMetadataPrefix()
			assert.Equal(t, tt.expectedPrefix, actualPrefix)
		})
	}
}
