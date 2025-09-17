package encryption

import (
	"encoding/base64"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/guided-traffic/s3-encryption-proxy/internal/config"
)

func TestNewHMACManager(t *testing.T) {
	tests := []struct {
		name   string
		config *config.Config
	}{
		{
			name: "with integrity verification enabled",
			config: &config.Config{
				Encryption: config.EncryptionConfig{
					IntegrityVerification: true,
					HMACPolicy:           HMACPolicyAlways,
				},
			},
		},
		{
			name: "with integrity verification disabled",
			config: &config.Config{
				Encryption: config.EncryptionConfig{
					IntegrityVerification: false,
					HMACPolicy:           HMACPolicyNever,
				},
			},
		},
		{
			name: "with auto HMAC policy",
			config: &config.Config{
				Encryption: config.EncryptionConfig{
					IntegrityVerification: true,
					HMACPolicy:           HMACPolicyAuto,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manager := NewHMACManager(tt.config)

			assert.NotNil(t, manager)
			assert.Equal(t, tt.config, manager.config)
			assert.NotNil(t, manager.logger)
			assert.NotNil(t, manager.keyDeriver)
		})
	}
}

func TestHMACManager_IsEnabled(t *testing.T) {
	tests := []struct {
		name                  string
		integrityVerification bool
		hmacPolicy           string
		algorithm            string
		expected             bool
	}{
		{
			name:                  "disabled globally",
			integrityVerification: false,
			hmacPolicy:           HMACPolicyAlways,
			algorithm:            "aes-gcm",
			expected:             false,
		},
		{
			name:                  "always policy with GCM",
			integrityVerification: true,
			hmacPolicy:           HMACPolicyAlways,
			algorithm:            "aes-gcm",
			expected:             true,
		},
		{
			name:                  "always policy with CTR",
			integrityVerification: true,
			hmacPolicy:           HMACPolicyAlways,
			algorithm:            "aes-ctr",
			expected:             true,
		},
		{
			name:                  "never policy",
			integrityVerification: true,
			hmacPolicy:           HMACPolicyNever,
			algorithm:            "aes-ctr",
			expected:             false,
		},
		{
			name:                  "auto policy with GCM (authenticated)",
			integrityVerification: true,
			hmacPolicy:           HMACPolicyAuto,
			algorithm:            "aes-gcm",
			expected:             false,
		},
		{
			name:                  "auto policy with CTR (not authenticated)",
			integrityVerification: true,
			hmacPolicy:           HMACPolicyAuto,
			algorithm:            "aes-ctr",
			expected:             true,
		},
		{
			name:                  "auto policy with ChaCha20Poly1305 (authenticated)",
			integrityVerification: true,
			hmacPolicy:           HMACPolicyAuto,
			algorithm:            "chacha20poly1305",
			expected:             false,
		},
		{
			name:                  "unknown policy defaults to always",
			integrityVerification: true,
			hmacPolicy:           "unknown",
			algorithm:            "aes-ctr",
			expected:             true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.Config{
				Encryption: config.EncryptionConfig{
					IntegrityVerification: tt.integrityVerification,
					HMACPolicy:           tt.hmacPolicy,
				},
			}

			manager := NewHMACManager(cfg)
			result := manager.IsEnabled(tt.algorithm)

			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestHMACManager_DeriveHMACKey(t *testing.T) {
	manager := NewHMACManager(&config.Config{})

	tests := []struct {
		name    string
		dek     []byte
		wantErr bool
	}{
		{
			name:    "valid DEK",
			dek:     []byte("test-dek-32-bytes-for-testing!!"),
			wantErr: false,
		},
		{
			name:    "empty DEK",
			dek:     []byte{},
			wantErr: true,
		},
		{
			name:    "nil DEK",
			dek:     nil,
			wantErr: true,
		},
		{
			name:    "short DEK",
			dek:     []byte("short"),
			wantErr: false, // HKDF should work with any input
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hmacKey, err := manager.deriveHMACKey(tt.dek)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, hmacKey)
			} else {
				assert.NoError(t, err)
				assert.Len(t, hmacKey, 32) // HMAC-SHA256 key should be 32 bytes

				// Ensure deterministic: same DEK should produce same HMAC key
				hmacKey2, err2 := manager.deriveHMACKey(tt.dek)
				assert.NoError(t, err2)
				assert.Equal(t, hmacKey, hmacKey2)
			}
		})
	}
}

func TestHMACManager_CreateCalculator(t *testing.T) {
	manager := NewHMACManager(&config.Config{})

	tests := []struct {
		name    string
		dek     []byte
		wantErr bool
	}{
		{
			name:    "valid DEK",
			dek:     []byte("test-dek-32-bytes-for-testing!!"),
			wantErr: false,
		},
		{
			name:    "empty DEK",
			dek:     []byte{},
			wantErr: true,
		},
		{
			name:    "nil DEK",
			dek:     nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			calculator, err := manager.CreateCalculator(tt.dek)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, calculator)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, calculator)

				// Test that calculator works
				calculator.Write([]byte("test data"))
				hmacValue := calculator.Sum(nil)
				assert.Len(t, hmacValue, 32) // SHA256 output is 32 bytes
			}
		})
	}
}

func TestHMACManager_CalculateHMAC(t *testing.T) {
	manager := NewHMACManager(&config.Config{})

	testDEK := []byte("test-dek-32-bytes-for-testing!!")
	testData := []byte("Hello, World!")

	tests := []struct {
		name    string
		data    []byte
		dek     []byte
		wantErr bool
	}{
		{
			name:    "valid inputs",
			data:    testData,
			dek:     testDEK,
			wantErr: false,
		},
		{
			name:    "empty data",
			data:    []byte{},
			dek:     testDEK,
			wantErr: true,
		},
		{
			name:    "nil data",
			data:    nil,
			dek:     testDEK,
			wantErr: true,
		},
		{
			name:    "empty DEK",
			data:    testData,
			dek:     []byte{},
			wantErr: true,
		},
		{
			name:    "nil DEK",
			data:    testData,
			dek:     nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hmacValue, err := manager.CalculateHMAC(tt.data, tt.dek)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, hmacValue)
			} else {
				assert.NoError(t, err)
				assert.Len(t, hmacValue, 32) // SHA256 output is 32 bytes

				// Ensure deterministic: same inputs should produce same HMAC
				hmacValue2, err2 := manager.CalculateHMAC(tt.data, tt.dek)
				assert.NoError(t, err2)
				assert.Equal(t, hmacValue, hmacValue2)
			}
		})
	}
}

func TestHMACManager_VerifyIntegrity(t *testing.T) {
	manager := NewHMACManager(&config.Config{})

	testDEK := []byte("test-dek-32-bytes-for-testing!!")
	testData := []byte("Hello, World!")

	// Calculate a valid HMAC
	validHMAC, err := manager.CalculateHMAC(testData, testDEK)
	require.NoError(t, err)

	// Create an invalid HMAC
	invalidHMAC := make([]byte, 32)
	copy(invalidHMAC, validHMAC)
	invalidHMAC[0] ^= 0xFF // Flip bits to make it invalid

	tests := []struct {
		name         string
		data         []byte
		expectedHMAC []byte
		dek          []byte
		wantErr      bool
	}{
		{
			name:         "valid HMAC",
			data:         testData,
			expectedHMAC: validHMAC,
			dek:          testDEK,
			wantErr:      false,
		},
		{
			name:         "invalid HMAC",
			data:         testData,
			expectedHMAC: invalidHMAC,
			dek:          testDEK,
			wantErr:      true,
		},
		{
			name:         "empty data",
			data:         []byte{},
			expectedHMAC: validHMAC,
			dek:          testDEK,
			wantErr:      true,
		},
		{
			name:         "empty expected HMAC",
			data:         testData,
			expectedHMAC: []byte{},
			dek:          testDEK,
			wantErr:      true,
		},
		{
			name:         "empty DEK",
			data:         testData,
			expectedHMAC: validHMAC,
			dek:          []byte{},
			wantErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := manager.VerifyIntegrity(tt.data, tt.expectedHMAC, tt.dek)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestHMACManager_AddToMetadata(t *testing.T) {
	tests := []struct {
		name                  string
		integrityVerification bool
		hmacPolicy           string
		algorithm            string
		data                 []byte
		dek                  []byte
		metadata             map[string]string
		metadataPrefix       string
		wantErr              bool
		expectHMAC           bool
	}{
		{
			name:                  "add HMAC when enabled",
			integrityVerification: true,
			hmacPolicy:           HMACPolicyAlways,
			algorithm:            "aes-ctr",
			data:                 []byte("test data"),
			dek:                  []byte("test-dek-32-bytes-for-testing!!"),
			metadata:             make(map[string]string),
			metadataPrefix:       "s3ep-",
			wantErr:              false,
			expectHMAC:           true,
		},
		{
			name:                  "skip HMAC when disabled",
			integrityVerification: false,
			hmacPolicy:           HMACPolicyAlways,
			algorithm:            "aes-ctr",
			data:                 []byte("test data"),
			dek:                  []byte("test-dek-32-bytes-for-testing!!"),
			metadata:             make(map[string]string),
			metadataPrefix:       "s3ep-",
			wantErr:              false,
			expectHMAC:           false,
		},
		{
			name:                  "skip HMAC for authenticated encryption with auto policy",
			integrityVerification: true,
			hmacPolicy:           HMACPolicyAuto,
			algorithm:            "aes-gcm",
			data:                 []byte("test data"),
			dek:                  []byte("test-dek-32-bytes-for-testing!!"),
			metadata:             make(map[string]string),
			metadataPrefix:       "s3ep-",
			wantErr:              false,
			expectHMAC:           false,
		},
		{
			name:                  "error with nil metadata",
			integrityVerification: true,
			hmacPolicy:           HMACPolicyAlways,
			algorithm:            "aes-ctr",
			data:                 []byte("test data"),
			dek:                  []byte("test-dek-32-bytes-for-testing!!"),
			metadata:             nil,
			metadataPrefix:       "s3ep-",
			wantErr:              true,
			expectHMAC:           false,
		},
		{
			name:                  "error with empty data",
			integrityVerification: true,
			hmacPolicy:           HMACPolicyAlways,
			algorithm:            "aes-ctr",
			data:                 []byte{},
			dek:                  []byte("test-dek-32-bytes-for-testing!!"),
			metadata:             make(map[string]string),
			metadataPrefix:       "s3ep-",
			wantErr:              true,
			expectHMAC:           false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.Config{
				Encryption: config.EncryptionConfig{
					IntegrityVerification: tt.integrityVerification,
					HMACPolicy:           tt.hmacPolicy,
				},
			}

			manager := NewHMACManager(cfg)
			err := manager.AddToMetadata(tt.metadata, tt.data, tt.dek, tt.algorithm, tt.metadataPrefix)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			hmacKey := tt.metadataPrefix + "hmac"
			if tt.expectHMAC {
				assert.Contains(t, tt.metadata, hmacKey)

				// Verify the HMAC value is valid base64
				hmacValue := tt.metadata[hmacKey]
				hmacBytes, err := base64.StdEncoding.DecodeString(hmacValue)
				assert.NoError(t, err)
				assert.Len(t, hmacBytes, 32) // SHA256 output
			} else {
				assert.NotContains(t, tt.metadata, hmacKey)
			}
		})
	}
}

func TestHMACManager_VerifyFromMetadata(t *testing.T) {
	testDEK := []byte("test-dek-32-bytes-for-testing!!")
	testData := []byte("test data")
	metadataPrefix := "s3ep-"

	// Create a manager and calculate valid HMAC
	cfg := &config.Config{
		Encryption: config.EncryptionConfig{
			IntegrityVerification: true,
			HMACPolicy:           HMACPolicyAlways,
		},
	}
	manager := NewHMACManager(cfg)

	validHMAC, err := manager.CalculateHMAC(testData, testDEK)
	require.NoError(t, err)

	tests := []struct {
		name       string
		metadata   map[string]string
		data       []byte
		dek        []byte
		algorithm  string
		wantErr    bool
	}{
		{
			name: "valid HMAC verification",
			metadata: map[string]string{
				metadataPrefix + "hmac": base64.StdEncoding.EncodeToString(validHMAC),
			},
			data:      testData,
			dek:       testDEK,
			algorithm: "aes-ctr",
			wantErr:   false,
		},
		{
			name:      "no HMAC in metadata (backward compatibility)",
			metadata:  map[string]string{},
			data:      testData,
			dek:       testDEK,
			algorithm: "aes-ctr",
			wantErr:   false,
		},
		{
			name: "invalid HMAC in metadata",
			metadata: map[string]string{
				metadataPrefix + "hmac": base64.StdEncoding.EncodeToString([]byte("invalid-hmac-value-here-32-b")),
			},
			data:      testData,
			dek:       testDEK,
			algorithm: "aes-ctr",
			wantErr:   true,
		},
		{
			name: "malformed HMAC base64",
			metadata: map[string]string{
				metadataPrefix + "hmac": "invalid-base64!",
			},
			data:      testData,
			dek:       testDEK,
			algorithm: "aes-ctr",
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := manager.VerifyFromMetadata(tt.metadata, tt.data, tt.dek, tt.algorithm, metadataPrefix)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestHMACManager_ExtractFromMetadata(t *testing.T) {
	metadataPrefix := "s3ep-"
	validHMACBytes := []byte("test-hmac-value-32-bytes-here!!!")
	validHMACBase64 := base64.StdEncoding.EncodeToString(validHMACBytes)

	tests := []struct {
		name           string
		metadata       map[string]string
		expectExists   bool
		expectBytes    []byte
		expectError    bool
	}{
		{
			name: "valid HMAC extraction",
			metadata: map[string]string{
				metadataPrefix + "hmac": validHMACBase64,
			},
			expectExists: true,
			expectBytes:  validHMACBytes,
			expectError:  false,
		},
		{
			name:         "no HMAC in metadata",
			metadata:     map[string]string{},
			expectExists: false,
			expectBytes:  nil,
			expectError:  false,
		},
		{
			name: "invalid base64 HMAC",
			metadata: map[string]string{
				metadataPrefix + "hmac": "invalid-base64!",
			},
			expectExists: true,
			expectBytes:  nil,
			expectError:  true,
		},
	}

	manager := NewHMACManager(&config.Config{})

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hmacBytes, exists, err := manager.ExtractFromMetadata(tt.metadata, metadataPrefix)

			assert.Equal(t, tt.expectExists, exists)
			assert.Equal(t, tt.expectBytes, hmacBytes)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestHMACManager_IsHMACMetadata(t *testing.T) {
	manager := NewHMACManager(&config.Config{})
	metadataPrefix := "s3ep-"

	tests := []struct {
		name     string
		key      string
		expected bool
	}{
		{
			name:     "HMAC key",
			key:      metadataPrefix + "hmac",
			expected: true,
		},
		{
			name:     "non-HMAC key",
			key:      metadataPrefix + "dek-algorithm",
			expected: false,
		},
		{
			name:     "different prefix",
			key:      "other-hmac",
			expected: false,
		},
		{
			name:     "empty key",
			key:      "",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := manager.IsHMACMetadata(tt.key, metadataPrefix)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestHMACManager_EndToEnd(t *testing.T) {
	// Test the complete flow: create HMAC, add to metadata, verify from metadata
	cfg := &config.Config{
		Encryption: config.EncryptionConfig{
			IntegrityVerification: true,
			HMACPolicy:           HMACPolicyAlways,
		},
	}

	manager := NewHMACManager(cfg)
	testData := []byte("Hello, World! This is test data for end-to-end HMAC testing.")
	testDEK := []byte("test-dek-32-bytes-for-testing!!")
	metadataPrefix := "s3ep-"
	algorithm := "aes-ctr"

	// Step 1: Add HMAC to metadata
	metadata := make(map[string]string)
	err := manager.AddToMetadata(metadata, testData, testDEK, algorithm, metadataPrefix)
	require.NoError(t, err)

	// Step 2: Verify HMAC is present in metadata
	hmacKey := metadataPrefix + "hmac"
	assert.Contains(t, metadata, hmacKey)

	// Step 3: Extract HMAC from metadata
	hmacBytes, exists, err := manager.ExtractFromMetadata(metadata, metadataPrefix)
	require.NoError(t, err)
	assert.True(t, exists)
	assert.Len(t, hmacBytes, 32)

	// Step 4: Verify HMAC from metadata
	err = manager.VerifyFromMetadata(metadata, testData, testDEK, algorithm, metadataPrefix)
	assert.NoError(t, err)

	// Step 5: Verify that corrupted data fails verification
	corruptedData := make([]byte, len(testData))
	copy(corruptedData, testData)
	corruptedData[0] ^= 0xFF // Flip bits

	err = manager.VerifyFromMetadata(metadata, corruptedData, testDEK, algorithm, metadataPrefix)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "HMAC verification failed")
}

// TestHMACManager_ConcurrentOperations tests thread safety of HMAC operations
func TestHMACManager_ConcurrentOperations(t *testing.T) {
	manager := NewHMACManager(&config.Config{
		Encryption: config.EncryptionConfig{
			IntegrityVerification: true,
			HMACPolicy:           HMACPolicyAlways,
		},
	})

	testDEK := []byte("test-dek-32-bytes-for-testing!!")
	testData := []byte("concurrent test data")

	// Run multiple goroutines calculating HMAC
	const numGoroutines = 10
	results := make([][]byte, numGoroutines)
	errors := make([]error, numGoroutines)

	done := make(chan int, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(index int) {
			hmac, err := manager.CalculateHMAC(testData, testDEK)
			results[index] = hmac
			errors[index] = err
			done <- index
		}(i)
	}

	// Wait for all goroutines to complete
	for i := 0; i < numGoroutines; i++ {
		<-done
	}

	// Verify all operations succeeded and produced the same result
	for i := 0; i < numGoroutines; i++ {
		assert.NoError(t, errors[i])
		assert.Len(t, results[i], 32)

		if i > 0 {
			assert.Equal(t, results[0], results[i], "All HMAC calculations should produce the same result")
		}
	}
}

func init() {
	// Set log level to error to reduce noise during tests
	logrus.SetLevel(logrus.ErrorLevel)
}
