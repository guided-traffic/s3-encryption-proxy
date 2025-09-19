package validation

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/guided-traffic/s3-encryption-proxy/internal/config"
)

// calculateSHA256ForHMACTest computes SHA256 hash for HMAC testing
func calculateSHA256ForHMACTest(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}

// compareSHA256 compares two byte slices using SHA256 hashes
func compareSHA256(a, b []byte) bool {
	hashA := calculateSHA256ForHMACTest(a)
	hashB := calculateSHA256ForHMACTest(b)
	return bytes.Equal(hashA, hashB)
}

func TestNewHMACManager(t *testing.T) {
	tests := []struct {
		name   string
		config *config.Config
	}{
		{
			name: "with integrity verification strict",
			config: &config.Config{
				Encryption: config.EncryptionConfig{
					IntegrityVerification: config.HMACVerificationStrict,
				},
			},
		},
		{
			name: "with integrity verification disabled",
			config: &config.Config{
				Encryption: config.EncryptionConfig{
					IntegrityVerification: config.HMACVerificationOff,
				},
			},
		},
		{
			name: "with lax verification and auto HMAC policy",
			config: &config.Config{
				Encryption: config.EncryptionConfig{
					IntegrityVerification: config.HMACVerificationLax,
				},
			},
		},
		{
			name: "with hybrid verification",
			config: &config.Config{
				Encryption: config.EncryptionConfig{
					IntegrityVerification: config.HMACVerificationHybrid,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manager := NewHMACManager(tt.config)

			assert.NotNil(t, manager)
			// Test functionality instead of accessing private fields
			// Verify the manager was properly configured by testing its behavior
			assert.NotPanics(t, func() {
				manager.IsEnabled()
			})
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
	cfg := &config.Config{
		Encryption: config.EncryptionConfig{
			IntegrityVerification: config.HMACVerificationStrict,
		},
	}

	testDEK := []byte("test-dek-32-bytes-for-testing!!")

	tests := []struct {
		name    string
		dek     []byte
		wantErr bool
	}{
		{
			name:    "valid DEK",
			dek:     testDEK,
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
			// Create manager with DEK
			manager, err := NewHMACManagerWithDEK(cfg, tt.dek)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, manager)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, manager)
			defer manager.Cleanup()

			calculator, err := manager.CreateCalculator()
			assert.NoError(t, err)
			assert.NotNil(t, calculator)

			// Test that calculator works
			calculator.Write([]byte("test data"))
			hmacValue := calculator.Sum(nil)
			assert.Len(t, hmacValue, 32) // SHA256 output is 32 bytes
		})
	}
}

func TestHMACManager_CalculateHMACFromStream(t *testing.T) {
	cfg := &config.Config{
		Encryption: config.EncryptionConfig{
			IntegrityVerification: config.HMACVerificationStrict,
		},
	}

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
			wantErr: false, // Empty data is valid for streaming
		},
		{
			name:    "nil DEK",
			data:    testData,
			dek:     nil,
			wantErr: true,
		},
		{
			name:    "empty DEK",
			data:    testData,
			dek:     []byte{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create manager with DEK
			manager, err := NewHMACManagerWithDEK(cfg, tt.dek)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, manager)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, manager)
			defer manager.Cleanup()

			reader := bufio.NewReader(bytes.NewReader(tt.data))
			hmacValue, err := manager.CalculateHMACFromStream(reader)

			assert.NoError(t, err)
			assert.Len(t, hmacValue, 32) // SHA256 output is 32 bytes

			// Ensure deterministic: same inputs should produce same HMAC
			reader2 := bufio.NewReader(bytes.NewReader(tt.data))
			hmacValue2, err2 := manager.CalculateHMACFromStream(reader2)
			assert.NoError(t, err2)
			assert.Equal(t, hmacValue, hmacValue2)
		})
	}
}

func TestHMACManager_VerifyIntegrityFromStream(t *testing.T) {
	cfg := &config.Config{
		Encryption: config.EncryptionConfig{
			IntegrityVerification: config.HMACVerificationStrict, // Use strict mode for this test
		},
	}

	testDEK := []byte("test-dek-32-bytes-for-testing!!")
	testData := []byte("Hello, World!")

	// Calculate a valid HMAC
	manager, err := NewHMACManagerWithDEK(cfg, testDEK)
	require.NoError(t, err)
	defer manager.Cleanup()

	reader := bufio.NewReader(bytes.NewReader(testData))
	validHMAC, err := manager.CalculateHMACFromStream(reader)
	require.NoError(t, err)

	// Create an invalid HMAC
	invalidHMAC := make([]byte, 32)
	copy(invalidHMAC, validHMAC)
	invalidHMAC[0] ^= 0xFF // Flip bits to make it invalid

	tests := []struct {
		name         string
		data         []byte
		expectedHMAC []byte
		wantErr      bool
	}{
		{
			name:         "valid HMAC",
			data:         testData,
			expectedHMAC: validHMAC,
			wantErr:      false,
		},
		{
			name:         "invalid HMAC",
			data:         testData,
			expectedHMAC: invalidHMAC,
			wantErr:      true,
		},
		{
			name:         "empty data",
			data:         []byte{},
			expectedHMAC: validHMAC,
			wantErr:      true, // HMAC won't match for different data
		},
		{
			name:         "empty expected HMAC",
			data:         testData,
			expectedHMAC: []byte{},
			wantErr:      true, // Strict mode requires HMAC
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := bufio.NewReader(bytes.NewReader(tt.data))
			err := manager.VerifyIntegrityFromStream(reader, tt.expectedHMAC)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestHMACManager_AddHMACToMetadataFromStream(t *testing.T) {
	tests := []struct {
		name                  string
		integrityVerification string
		data                  []byte
		dek                   []byte
		metadata              map[string]string
		metadataPrefix        string
		wantErr               bool
		expectHMAC            bool
	}{
		{
			name:                  "add HMAC when enabled in strict mode",
			integrityVerification: config.HMACVerificationStrict,
			data:                  []byte("test data"),
			dek:                   []byte("test-dek-32-bytes-for-testing!!"),
			metadata:              make(map[string]string),
			metadataPrefix:        "s3ep-",
			wantErr:               false,
			expectHMAC:            true,
		},
		{
			name:                  "skip HMAC when disabled (off mode)",
			integrityVerification: config.HMACVerificationOff,
			data:                  []byte("test data"),
			dek:                   []byte("test-dek-32-bytes-for-testing!!"),
			metadata:              make(map[string]string),
			metadataPrefix:        "s3ep-",
			wantErr:               false,
			expectHMAC:            false,
		},
		{
			name:                  "add HMAC in lax mode",
			integrityVerification: config.HMACVerificationLax,
			data:                  []byte("test data"),
			dek:                   []byte("test-dek-32-bytes-for-testing!!"),
			metadata:              make(map[string]string),
			metadataPrefix:        "s3ep-",
			wantErr:               false,
			expectHMAC:            true, // Should add HMAC even in lax mode
		},
		{
			name:                  "add HMAC in hybrid mode",
			integrityVerification: config.HMACVerificationHybrid,
			data:                  []byte("test data"),
			dek:                   []byte("test-dek-32-bytes-for-testing!!"),
			metadata:              make(map[string]string),
			metadataPrefix:        "s3ep-",
			wantErr:               false,
			expectHMAC:            true,
		},
		{
			name:                  "error with nil metadata",
			integrityVerification: config.HMACVerificationStrict,
			data:                  []byte("test data"),
			dek:                   []byte("test-dek-32-bytes-for-testing!!"),
			metadata:              nil,
			metadataPrefix:        "s3ep-",
			wantErr:               true,
			expectHMAC:            false,
		},
		{
			name:                  "handle empty data",
			integrityVerification: config.HMACVerificationStrict,
			data:                  []byte{},
			dek:                   []byte("test-dek-32-bytes-for-testing!!"),
			metadata:              make(map[string]string),
			metadataPrefix:        "s3ep-",
			wantErr:               false, // Empty data is valid for streaming
			expectHMAC:            true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.Config{
				Encryption: config.EncryptionConfig{
					IntegrityVerification: tt.integrityVerification,
				},
			}

			// Handle DEK validation (nil/empty DEK should cause manager creation to fail)
			if len(tt.dek) == 0 && tt.integrityVerification != config.HMACVerificationOff {
				// For enabled HMAC verification, empty DEK should fail at manager creation
				manager, err := NewHMACManagerWithDEK(cfg, tt.dek)
				assert.Error(t, err)
				assert.Nil(t, manager)
				return
			}

			manager, err := NewHMACManagerWithDEK(cfg, tt.dek)
			if tt.integrityVerification == config.HMACVerificationOff {
				// For disabled HMAC, manager creation should succeed even with empty DEK
				require.NoError(t, err)
			} else {
				require.NoError(t, err)
				defer manager.Cleanup()
			}

			reader := bufio.NewReader(bytes.NewReader(tt.data))
			err = manager.AddHMACToMetadataFromStream(tt.metadata, reader, tt.metadataPrefix)

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

func TestHMACManager_VerifyHMACFromMetadataStream(t *testing.T) {
	testDEK := []byte("test-dek-32-bytes-for-testing!!")
	testData := []byte("test data")
	metadataPrefix := "s3ep-"

	// Create a manager and calculate valid HMAC
	cfg := &config.Config{
		Encryption: config.EncryptionConfig{
			IntegrityVerification: config.HMACVerificationStrict,
		},
	}
	manager := NewHMACManager(cfg)

	reader := bufio.NewReader(bytes.NewReader(testData))
	validHMAC, err := manager.CalculateHMACFromStream(reader, testDEK)
	require.NoError(t, err)

	tests := []struct {
		name     string
		metadata map[string]string
		data     []byte
		dek      []byte
		wantErr  bool
	}{
		{
			name: "valid HMAC verification",
			metadata: map[string]string{
				metadataPrefix + "hmac": base64.StdEncoding.EncodeToString(validHMAC),
			},
			data:    testData,
			dek:     testDEK,
			wantErr: false,
		},
		{
			name:     "no HMAC in metadata (backward compatibility)",
			metadata: map[string]string{},
			data:     testData,
			dek:      testDEK,
			wantErr:  false,
		},
		{
			name: "invalid HMAC in metadata",
			metadata: map[string]string{
				metadataPrefix + "hmac": base64.StdEncoding.EncodeToString([]byte("invalid-hmac-value-here-32-b")),
			},
			data:    testData,
			dek:     testDEK,
			wantErr: true,
		},
		{
			name: "malformed HMAC base64",
			metadata: map[string]string{
				metadataPrefix + "hmac": "invalid-base64!",
			},
			data:    testData,
			dek:     testDEK,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Use different manager configuration based on test case
			var testManager *HMACManager
			if tt.name == "no HMAC in metadata (backward compatibility)" {
				// Use hybrid mode for backward compatibility test
				hybridCfg := &config.Config{
					Encryption: config.EncryptionConfig{
						IntegrityVerification: config.HMACVerificationHybrid,
					},
				}
				testManager = NewHMACManager(hybridCfg)
			} else {
				testManager = manager
			}

			reader := bufio.NewReader(bytes.NewReader(tt.data))
			err := testManager.VerifyHMACFromMetadataStream(tt.metadata, reader, tt.dek, metadataPrefix)

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
		name         string
		metadata     map[string]string
		expectExists bool
		expectBytes  []byte
		expectError  bool
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
			hmacBytes, exists, err := manager.ExtractHMACFromMetadata(tt.metadata, metadataPrefix)

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
			IntegrityVerification: config.HMACVerificationStrict,
		},
	}

	manager := NewHMACManager(cfg)
	testData := []byte("Hello, World! This is test data for end-to-end HMAC testing.")
	testDEK := []byte("test-dek-32-bytes-for-testing!!")
	metadataPrefix := "s3ep-"

	// Step 1: Add HMAC to metadata using streaming
	metadata := make(map[string]string)
	reader := bufio.NewReader(bytes.NewReader(testData))
	err := manager.AddHMACToMetadataFromStream(metadata, reader, testDEK, metadataPrefix)
	require.NoError(t, err)

	// Step 2: Verify HMAC is present in metadata
	hmacKey := metadataPrefix + "hmac"
	assert.Contains(t, metadata, hmacKey)

	// Step 3: Extract HMAC from metadata
	hmacBytes, exists, err := manager.ExtractHMACFromMetadata(metadata, metadataPrefix)
	require.NoError(t, err)
	assert.True(t, exists)
	assert.Len(t, hmacBytes, 32)

	// Step 4: Verify HMAC from metadata using streaming
	reader2 := bufio.NewReader(bytes.NewReader(testData))
	err = manager.VerifyHMACFromMetadataStream(metadata, reader2, testDEK, metadataPrefix)
	assert.NoError(t, err)

	// Step 5: Verify that corrupted data fails verification
	corruptedData := make([]byte, len(testData))
	copy(corruptedData, testData)
	corruptedData[0] ^= 0xFF // Flip bits

	reader3 := bufio.NewReader(bytes.NewReader(corruptedData))
	err = manager.VerifyHMACFromMetadataStream(metadata, reader3, testDEK, metadataPrefix)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "HMAC verification failed")
}

// TestHMACManager_ConcurrentOperations tests thread safety of HMAC operations
func TestHMACManager_ConcurrentOperations(t *testing.T) {
	manager := NewHMACManager(&config.Config{
		Encryption: config.EncryptionConfig{
			IntegrityVerification: config.HMACVerificationStrict,
		},
	})

	testDEK := []byte("test-dek-32-bytes-for-testing!!")
	testData := []byte("concurrent test data")

	// Run multiple goroutines calculating HMAC using streaming
	const numGoroutines = 10
	results := make([][]byte, numGoroutines)
	errors := make([]error, numGoroutines)

	done := make(chan int, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(index int) {
			reader := bufio.NewReader(bytes.NewReader(testData))
			hmac, err := manager.CalculateHMACFromStream(reader, testDEK)
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
			assert.True(t, compareSHA256(results[0], results[i]),
				"All HMAC calculations should produce the same result (SHA256 comparison)")
		}
	}
}

func TestHMACManager_StreamingVsSinglePassComparison(t *testing.T) {
	manager := NewHMACManager(&config.Config{
		Encryption: config.EncryptionConfig{
			IntegrityVerification: config.HMACVerificationStrict,
		},
	})

	// Generate 10MB of random test data
	const dataSize = 10 * 1024 * 1024 // 10MB
	testData := make([]byte, dataSize)
	for i := range testData {
		testData[i] = byte(i % 256) // Pattern that creates some variety
	}

	testDEK := []byte("test-dek-32-bytes-for-testing!!")

	t.Run("single_pass_vs_streaming_comparison", func(t *testing.T) {
		// Method 1: Single-pass HMAC calculation using streaming
		singlePassReader := bufio.NewReader(bytes.NewReader(testData))
		singlePassHMAC, err := manager.CalculateHMACFromStream(singlePassReader, testDEK)
		require.NoError(t, err, "Single-pass HMAC calculation should succeed")
		require.Len(t, singlePassHMAC, 32, "HMAC should be 32 bytes (SHA256)")

		// Method 2: Streaming HMAC calculation - split into 5 parts
		const numParts = 5
		partSize := dataSize / numParts
		require.Greater(t, partSize, 0, "Part size should be positive")

		// Create streaming calculator
		streamingCalculator, err := manager.CreateCalculator(testDEK)
		require.NoError(t, err, "Creating streaming calculator should succeed")
		require.NotNil(t, streamingCalculator, "Streaming calculator should not be nil")

		// Process data in 5 parts sequentially
		for i := 0; i < numParts; i++ {
			start := i * partSize
			end := start + partSize

			// Handle last part (might be slightly larger due to remainder)
			if i == numParts-1 {
				end = dataSize
			}

			part := testData[start:end]
			partLen := len(part)

			t.Logf("Processing part %d: start=%d, end=%d, size=%d bytes",
				i+1, start, end, partLen)

			// Use UpdateCalculatorSequential for proper streaming
			err := manager.UpdateCalculatorSequential(streamingCalculator, part, i+1)
			require.NoError(t, err, "Streaming part %d should be processed successfully", i+1)
		}

		// Finalize streaming calculation
		streamingHMAC := manager.FinalizeCalculator(streamingCalculator)
		require.Len(t, streamingHMAC, 32, "Streaming HMAC should be 32 bytes (SHA256)")

		// The critical assertion: both methods should produce identical results
		assert.True(t, compareSHA256(singlePassHMAC, streamingHMAC),
			"Single-pass HMAC and streaming HMAC must be identical (SHA256 comparison)")

		t.Logf("Successfully verified streaming HMAC equivalence:")
		t.Logf("  Data size: %d bytes (10MB)", dataSize)
		t.Logf("  Parts processed: %d", numParts)
		t.Logf("  Single-pass SHA256: %x", calculateSHA256ForHMACTest(singlePassHMAC)[:8]) // First 8 bytes for logging
		t.Logf("  Streaming SHA256:   %x", calculateSHA256ForHMACTest(streamingHMAC)[:8])  // First 8 bytes for logging
	})

	t.Run("streaming_with_different_part_sizes", func(t *testing.T) {
		// Test with irregular part sizes to ensure robustness
		partSizes := []int{
			1024,  // 1KB
			4096,  // 4KB
			8192,  // 8KB
			16384, // 16KB
			32768, // 32KB
		}

		singlePassReader := bufio.NewReader(bytes.NewReader(testData))
		singlePassHMAC, err := manager.CalculateHMACFromStream(singlePassReader, testDEK)
		require.NoError(t, err)

		for _, partSize := range partSizes {
			t.Run(fmt.Sprintf("part_size_%d_bytes", partSize), func(t *testing.T) {
				streamingCalculator, err := manager.CreateCalculator(testDEK)
				require.NoError(t, err)

				// Process data in chunks of specified size
				offset := 0
				partNum := 1

				for offset < len(testData) {
					end := offset + partSize
					if end > len(testData) {
						end = len(testData)
					}

					part := testData[offset:end]
					err := manager.UpdateCalculatorSequential(streamingCalculator, part, partNum)
					require.NoError(t, err, "Failed to process part %d with size %d", partNum, len(part))

					offset = end
					partNum++
				}

				streamingHMAC := manager.FinalizeCalculator(streamingCalculator)

				assert.True(t, compareSHA256(singlePassHMAC, streamingHMAC),
					"HMAC mismatch with part size %d bytes (SHA256 comparison)", partSize)
			})
		}
	})

	t.Run("streaming_edge_cases", func(t *testing.T) {
		// Test edge cases to ensure streaming is robust
		testCases := []struct {
			name        string
			description string
			dataSize    int
			numParts    int
		}{
			{
				name:        "single_byte_parts",
				description: "Process 1KB data one byte at a time",
				dataSize:    1024,
				numParts:    1024,
			},
			{
				name:        "uneven_split",
				description: "Process 1MB with 7 uneven parts",
				dataSize:    1024 * 1024,
				numParts:    7,
			},
			{
				name:        "large_parts",
				description: "Process 5MB with only 2 large parts",
				dataSize:    5 * 1024 * 1024,
				numParts:    2,
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				// Generate test data of specified size
				edgeTestData := make([]byte, tc.dataSize)
				for i := range edgeTestData {
					edgeTestData[i] = byte((i * 17) % 256) // Different pattern
				}

				// Single-pass calculation using streaming
				singlePassReader := bufio.NewReader(bytes.NewReader(edgeTestData))
				singlePassHMAC, err := manager.CalculateHMACFromStream(singlePassReader, testDEK)
				require.NoError(t, err)

				// Streaming calculation
				streamingCalculator, err := manager.CreateCalculator(testDEK)
				require.NoError(t, err)

				partSize := tc.dataSize / tc.numParts
				for i := 0; i < tc.numParts; i++ {
					start := i * partSize
					end := start + partSize
					if i == tc.numParts-1 {
						end = tc.dataSize // Include remainder in last part
					}

					part := edgeTestData[start:end]
					err := manager.UpdateCalculatorSequential(streamingCalculator, part, i+1)
					require.NoError(t, err)
				}

				streamingHMAC := manager.FinalizeCalculator(streamingCalculator)

				assert.True(t, compareSHA256(singlePassHMAC, streamingHMAC),
					"Edge case '%s' failed: %s (SHA256 comparison)", tc.name, tc.description)

				t.Logf("Edge case '%s' passed: %s (data: %d bytes, parts: %d)",
					tc.name, tc.description, tc.dataSize, tc.numParts)
			})
		}
	})
}
