package orchestration

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/guided-traffic/s3-encryption-proxy/internal/config"
	"github.com/guided-traffic/s3-encryption-proxy/internal/validation"
)

// TestNewHMACManagerIntegration tests that the new HMACManager integrates correctly
// with the orchestration layer and provides the required functionality
func TestNewHMACManagerIntegration(t *testing.T) {
	tests := []struct {
		name                    string
		integrityVerification   string
		expectHMACEnabled       bool
		expectConfigPresent     bool
	}{
		{
			name:                    "HMAC enabled with strict verification",
			integrityVerification:   "strict",
			expectHMACEnabled:       true,
			expectConfigPresent:     true,
		},
		{
			name:                    "HMAC enabled with lax verification",
			integrityVerification:   "lax",
			expectHMACEnabled:       true,
			expectConfigPresent:     true,
		},
		{
			name:                    "HMAC disabled with off verification",
			integrityVerification:   "off",
			expectHMACEnabled:       false,
			expectConfigPresent:     true,
		},
		{
			name:                    "HMAC enabled with hybrid verification",
			integrityVerification:   "hybrid",
			expectHMACEnabled:       true,
			expectConfigPresent:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test config
			cfg := createTestConfigForHMAC()
			cfg.Encryption.IntegrityVerification = tt.integrityVerification

			// Create HMACManager with config
			hmacManager := validation.NewHMACManager(cfg)
			require.NotNil(t, hmacManager, "HMACManager should not be nil")

			// Test IsEnabled functionality
			isEnabled := hmacManager.IsEnabled()
			assert.Equal(t, tt.expectHMACEnabled, isEnabled,
				"HMACManager.IsEnabled() should match expected value for %s", tt.integrityVerification)

			// Test CreateCalculator functionality
			testDEK := make([]byte, 32)
			for i := range testDEK {
				testDEK[i] = byte(i)
			}

			calculator, err := hmacManager.CreateCalculator(testDEK)
			require.NoError(t, err, "CreateCalculator should not return error")
			require.NotNil(t, calculator, "Calculator should not be nil")

			// Test calculator functionality
			testData := []byte("test data for HMAC calculation")
			_, err = calculator.Add(testData)
			require.NoError(t, err, "Calculator.Add should not return error")

			// Test FinalizeCalculator
			finalHMAC := hmacManager.FinalizeCalculator(calculator)
			require.NotNil(t, finalHMAC, "Final HMAC should not be nil")
			assert.Len(t, finalHMAC, 32, "HMAC should be 32 bytes (SHA256)")

			// Test VerifyIntegrity
			calculator2, err := hmacManager.CreateCalculator(testDEK)
			require.NoError(t, err, "Second calculator creation should not error")
			_, err = calculator2.Add(testData)
			require.NoError(t, err, "Second calculator Add should not error")

			err = hmacManager.VerifyIntegrity(calculator2, finalHMAC)
			assert.NoError(t, err, "VerifyIntegrity should succeed with matching HMAC")

			// Test ClearSensitiveData
			hmacManager.ClearSensitiveData(testDEK)
			// Verify data is cleared
			allZero := true
			for _, b := range testDEK {
				if b != 0 {
					allZero = false
					break
				}
			}
			assert.True(t, allZero, "Sensitive data should be cleared")
		})
	}
}

// TestMultipartHMACWorkflowIntegration tests the complete multipart workflow
// with the new HMACManager interface
func TestMultipartHMACWorkflowIntegration(t *testing.T) {
	ctx := context.Background()

	// Create test environment with HMAC enabled
	cfg := createTestConfigForHMAC()
	cfg.Encryption.IntegrityVerification = "strict"

	mpo, err := createTestMultipartOperations(cfg)
	require.NoError(t, err, "Failed to create multipart operations")

	// Test data
	const (
		testUploadID   = "test-hmac-workflow-upload"
		testObjectKey  = "test-hmac-workflow-object"
		testBucketName = "test-hmac-workflow-bucket"
	)

	// Phase 1: Initiate session
	session, err := mpo.InitiateSession(ctx, testUploadID, testObjectKey, testBucketName)
	require.NoError(t, err, "InitiateSession should succeed")
	require.NotNil(t, session, "Session should not be nil")
	require.NotNil(t, session.HMACCalculator, "HMAC calculator should be created")

	// Phase 2: Process parts
	parts := [][]byte{
		[]byte("First part of multipart upload data"),
		[]byte("Second part with different content"),
		[]byte("Third and final part of the upload"),
	}

	for i, partData := range parts {
		partNumber := i + 1
		partReader := bufio.NewReader(bytes.NewReader(partData))

		result, err := mpo.ProcessPart(ctx, testUploadID, partNumber, partReader)
		require.NoError(t, err, "ProcessPart %d should succeed", partNumber)
		require.NotNil(t, result, "Part result should not be nil")
		assert.Equal(t, "aes-ctr", result.Algorithm, "Should use AES-CTR for multipart")
	}

	// Phase 3: Finalize session
	metadata, err := mpo.FinalizeSession(ctx, testUploadID)
	require.NoError(t, err, "FinalizeSession should succeed")
	require.NotNil(t, metadata, "Metadata should not be nil")

	// Verify HMAC is present in metadata
	hmacKey := "s3ep-hmac"
	hmacValue, exists := metadata[hmacKey]
	assert.True(t, exists, "HMAC should be present in metadata")
	assert.NotEmpty(t, hmacValue, "HMAC value should not be empty")

	// Verify HMAC is valid base64
	hmacBytes, err := base64.StdEncoding.DecodeString(hmacValue)
	require.NoError(t, err, "HMAC should be valid base64")
	assert.Len(t, hmacBytes, 32, "HMAC should be 32 bytes")

	t.Logf("✅ Multipart HMAC workflow completed successfully")
	t.Logf("   - Session initiated with HMAC calculator")
	t.Logf("   - %d parts processed sequentially", len(parts))
	t.Logf("   - HMAC finalized and stored in metadata: %s", hmacValue)
}

// TestSinglepartHMACWorkflowIntegration tests the single-part workflow
// with the new HMACManager interface
func TestSinglepartHMACWorkflowIntegration(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name      string
		algorithm string
		dataSize  int
	}{
		{
			name:      "AES-GCM with small data",
			algorithm: "gcm",
			dataSize:  1024, // 1KB - should use GCM
		},
		{
			name:      "AES-CTR with large data",
			algorithm: "ctr",
			dataSize:  6 * 1024 * 1024, // 6MB - should use CTR
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test environment with HMAC enabled
			cfg := createTestConfigForHMAC()
			cfg.Encryption.IntegrityVerification = "strict"

			spo, err := createTestSinglePartOperations(cfg)
			require.NoError(t, err, "Failed to create single part operations")

			// Generate test data
			testData := make([]byte, tt.dataSize)
			for i := range testData {
				testData[i] = byte(i % 256)
			}

			const testObjectKey = "test-singlepart-hmac-object"

			// Phase 1: Encrypt data
			var result *EncryptionResult
			dataReader := bufio.NewReader(bytes.NewReader(testData))

			if tt.algorithm == "gcm" {
				result, err = spo.EncryptGCM(ctx, dataReader, testObjectKey)
			} else {
				result, err = spo.EncryptCTR(ctx, dataReader, testObjectKey)
			}

			require.NoError(t, err, "Encryption should succeed")
			require.NotNil(t, result, "Encryption result should not be nil")

			// Verify HMAC is present in metadata
			hmacKey := "s3ep-hmac"
			hmacValue, exists := result.Metadata[hmacKey]
			assert.True(t, exists, "HMAC should be present in metadata")
			assert.NotEmpty(t, hmacValue, "HMAC value should not be empty")

			// Read encrypted data
			encryptedData, err := io.ReadAll(result.EncryptedData)
			require.NoError(t, err, "Should read encrypted data")
			assert.True(t, len(encryptedData) > 0, "Encrypted data should not be empty")

			// Phase 2: Decrypt and verify HMAC
			encryptedReader := bufio.NewReader(bytes.NewReader(encryptedData))

			var decryptedReader *bufio.Reader
			if tt.algorithm == "gcm" {
				decryptedReader, err = spo.DecryptGCM(ctx, encryptedReader, result.Metadata, testObjectKey)
			} else {
				decryptedReader, err = spo.DecryptCTR(ctx, encryptedReader, result.Metadata, testObjectKey)
			}

			require.NoError(t, err, "Decryption should succeed")
			require.NotNil(t, decryptedReader, "Decrypted reader should not be nil")

			// Verify decrypted data matches original
			decryptedData, err := io.ReadAll(decryptedReader)
			require.NoError(t, err, "Should read decrypted data")
			assert.Equal(t, testData, decryptedData, "Decrypted data should match original")

			t.Logf("✅ Single-part %s HMAC workflow completed successfully", tt.algorithm)
			t.Logf("   - Data encrypted with %s algorithm", result.Algorithm)
			t.Logf("   - HMAC generated and stored: %s", hmacValue)
			t.Logf("   - Data decrypted and HMAC verified successfully")
		})
	}
}

// TestHMACCalculatorStreamingIntegration tests that the HMACCalculator
// properly handles streaming data using AddFromStream
func TestHMACCalculatorStreamingIntegration(t *testing.T) {
	cfg := createTestConfigForHMAC()
	cfg.Encryption.IntegrityVerification = "strict"

	hmacManager := validation.NewHMACManager(cfg)
	require.NotNil(t, hmacManager)
	assert.True(t, hmacManager.IsEnabled())

	// Test data
	testDEK := make([]byte, 32)
	for i := range testDEK {
		testDEK[i] = byte(i)
	}

	largeData := make([]byte, 1024*1024) // 1MB
	for i := range largeData {
		largeData[i] = byte(i % 256)
	}

	// Test 1: AddFromStream vs multiple Add calls should produce same result
	t.Run("AddFromStream vs Add equivalence", func(t *testing.T) {
		// Method 1: Use AddFromStream
		calc1, err := hmacManager.CreateCalculator(testDEK)
		require.NoError(t, err)

		dataReader := bufio.NewReader(bytes.NewReader(largeData))
		bytesProcessed, err := calc1.AddFromStream(dataReader)
		require.NoError(t, err)
		assert.Equal(t, int64(len(largeData)), bytesProcessed)

		hmac1 := hmacManager.FinalizeCalculator(calc1)

		// Method 2: Use multiple Add calls
		calc2, err := hmacManager.CreateCalculator(testDEK)
		require.NoError(t, err)

		chunkSize := 64 * 1024 // 64KB chunks
		for i := 0; i < len(largeData); i += chunkSize {
			end := i + chunkSize
			if end > len(largeData) {
				end = len(largeData)
			}
			_, err = calc2.Add(largeData[i:end])
			require.NoError(t, err)
		}

		hmac2 := hmacManager.FinalizeCalculator(calc2)

		// Results should be identical
		assert.Equal(t, hmac1, hmac2, "AddFromStream and chunked Add should produce same HMAC")
	})

	// Test 2: VerifyIntegrity with streaming
	t.Run("VerifyIntegrity streaming workflow", func(t *testing.T) {
		// Create HMAC
		calc1, err := hmacManager.CreateCalculator(testDEK)
		require.NoError(t, err)

		dataReader1 := bufio.NewReader(bytes.NewReader(largeData))
		_, err = calc1.AddFromStream(dataReader1)
		require.NoError(t, err)

		expectedHMAC := hmacManager.FinalizeCalculator(calc1)

		// Verify HMAC
		calc2, err := hmacManager.CreateCalculator(testDEK)
		require.NoError(t, err)

		dataReader2 := bufio.NewReader(bytes.NewReader(largeData))
		_, err = calc2.AddFromStream(dataReader2)
		require.NoError(t, err)

		err = hmacManager.VerifyIntegrity(calc2, expectedHMAC)
		assert.NoError(t, err, "HMAC verification should succeed")

		// Test with corrupted data
		corruptedData := make([]byte, len(largeData))
		copy(corruptedData, largeData)
		corruptedData[500000] ^= 0xFF // Flip bits in middle

		calc3, err := hmacManager.CreateCalculator(testDEK)
		require.NoError(t, err)

		corruptedReader := bufio.NewReader(bytes.NewReader(corruptedData))
		_, err = calc3.AddFromStream(corruptedReader)
		require.NoError(t, err)

		err = hmacManager.VerifyIntegrity(calc3, expectedHMAC)
		assert.Error(t, err, "HMAC verification should fail with corrupted data")
		assert.Contains(t, err.Error(), "HMAC verification failed", "Error should mention HMAC verification failure")
	})

	t.Logf("✅ HMAC Calculator streaming integration tests completed successfully")
}

// Helper function to create SinglePartOperations for testing
func createTestSinglePartOperations(cfg *config.Config) (*SinglePartOperations, error) {
	providerManager, err := NewProviderManager(cfg)
	if err != nil {
		return nil, err
	}

	hmacManager := validation.NewHMACManager(cfg)
	metadataManager := NewMetadataManager(cfg, "s3ep-")

	return NewSinglePartOperations(
		providerManager,
		metadataManager,
		hmacManager,
		cfg,
	), nil
}

// Helper function to create test config
func createTestConfigForHMAC() *config.Config {
	return &config.Config{
		Encryption: config.EncryptionConfig{
			IntegrityVerification: "strict",
			MetadataKeyPrefix:     stringPtr("s3ep-"),
		},
	}
}

func stringPtr(s string) *string {
	return &s
}
