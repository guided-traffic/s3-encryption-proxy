package orchestration

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/guided-traffic/s3-encryption-proxy/internal/config"
	"github.com/guided-traffic/s3-encryption-proxy/internal/validation"
)

// TestHMACManagerInterfaceBasicFunctionality tests that the new HMACManager interface
// works correctly at the basic level
func TestHMACManagerInterfaceBasicFunctionality(t *testing.T) {
	t.Log("🔧 Testing basic HMACManager interface functionality")

	// Create config with HMAC enabled
	cfg := &config.Config{
		Encryption: config.EncryptionConfig{
			IntegrityVerification: "strict",
			MetadataKeyPrefix:     func(s string) *string { return &s }("s3ep-"),
		},
	}

	// Create HMACManager
	hmacManager := validation.NewHMACManager(cfg)
	require.NotNil(t, hmacManager, "HMACManager should not be nil")
	assert.True(t, hmacManager.IsEnabled(), "HMAC should be enabled")

	// Test data
	testDEK := make([]byte, 32)
	rand.Read(testDEK)

	testData := []byte("This is test data for HMAC interface validation")

	t.Log("Phase 1: Testing CreateCalculator functionality")

	// Create calculator
	calculator, err := hmacManager.CreateCalculator(testDEK)
	require.NoError(t, err, "CreateCalculator should succeed")
	require.NotNil(t, calculator, "Calculator should not be nil")

	t.Log("Phase 2: Testing Add functionality")

	// Add data
	bytesAdded, err := calculator.Add(testData)
	require.NoError(t, err, "Add should succeed")
	assert.Equal(t, len(testData), bytesAdded, "Should return correct bytes added")

	t.Log("Phase 3: Testing FinalizeCalculator functionality")

	// Finalize
	finalHMAC := hmacManager.FinalizeCalculator(calculator)
	require.NotNil(t, finalHMAC, "Final HMAC should not be nil")
	assert.Len(t, finalHMAC, 32, "HMAC should be 32 bytes")

	t.Log("Phase 4: Testing VerifyIntegrity functionality")

	// Create second calculator for verification
	verifyCalculator, err := hmacManager.CreateCalculator(testDEK)
	require.NoError(t, err, "Second CreateCalculator should succeed")

	// Add same data
	_, err = verifyCalculator.Add(testData)
	require.NoError(t, err, "Second Add should succeed")

	// Verify integrity
	err = hmacManager.VerifyIntegrity(verifyCalculator, finalHMAC)
	assert.NoError(t, err, "VerifyIntegrity should succeed with matching data")

	t.Log("Phase 5: Testing AddFromStream functionality")

	// Test streaming interface
	streamCalculator, err := hmacManager.CreateCalculator(testDEK)
	require.NoError(t, err, "Stream CreateCalculator should succeed")

	dataReader := bufio.NewReader(bytes.NewReader(testData))
	streamBytesAdded, err := streamCalculator.AddFromStream(dataReader)
	require.NoError(t, err, "AddFromStream should succeed")
	assert.Equal(t, int64(len(testData)), streamBytesAdded, "Should return correct stream bytes added")

	// Verify same result
	streamHMAC := hmacManager.FinalizeCalculator(streamCalculator)
	assert.Equal(t, finalHMAC, streamHMAC, "Add and AddFromStream should produce same HMAC")

	t.Log("Phase 6: Testing ClearSensitiveData functionality")

	// Test clearing sensitive data
	testDEKCopy := make([]byte, len(testDEK))
	copy(testDEKCopy, testDEK)

	hmacManager.ClearSensitiveData(testDEKCopy)

	// Verify data is cleared
	allZero := true
	for _, b := range testDEKCopy {
		if b != 0 {
			allZero = false
			break
		}
	}
	assert.True(t, allZero, "Sensitive data should be cleared")

	t.Log("✅ All HMACManager interface tests passed successfully!")
	t.Log("   ✓ CreateCalculator: Creates functional calculators")
	t.Log("   ✓ Add: Processes data correctly")
	t.Log("   ✓ AddFromStream: Handles streaming data")
	t.Log("   ✓ FinalizeCalculator: Extracts HMAC correctly")
	t.Log("   ✓ VerifyIntegrity: Validates HMAC successfully")
	t.Log("   ✓ ClearSensitiveData: Securely clears data")
}

// TestHMACManagerInterfaceMultipartWorkflow tests the complete multipart workflow
// that uses the new interface
func TestHMACManagerInterfaceMultipartWorkflow(t *testing.T) {
	ctx := context.Background()

	t.Log("🔧 Testing HMACManager interface in multipart workflow")

	// Create config with HMAC enabled
	cfg := createTestMultipartConfig()
	cfg.Encryption.IntegrityVerification = "strict"

	mpo, err := createTestMultipartOperations(cfg)
	require.NoError(t, err, "Should create multipart operations")

	// Test data
	const (
		testUploadID   = "hmac-workflow-test-upload"
		testObjectKey  = "hmac-workflow-test-object"
		testBucketName = "hmac-workflow-test-bucket"
	)

	testData := generateMultipartTestData(10 * 1024 * 1024) // 10MB
	const partSize = 5 * 1024 * 1024                       // 5MB parts
	numParts := 2 // Will be 2 parts: 5MB + 5MB

	t.Log("Phase 1: Testing session initiation with HMACManager interface")

	// Initiate session
	session, err := mpo.InitiateSession(ctx, testUploadID, testObjectKey, testBucketName)
	require.NoError(t, err, "Should initiate session")
	require.NotNil(t, session, "Session should not be nil")

	// Verify HMAC calculator is created
	require.NotNil(t, session.HMACCalculator, "HMAC calculator should be created")

	t.Log("Phase 2: Processing parts with streaming HMAC")

	// Process parts
	for partNum := 1; partNum <= numParts; partNum++ {
		startOffset := (partNum - 1) * partSize
		endOffset := startOffset + partSize
		if endOffset > len(testData) {
			endOffset = len(testData)
		}
		partData := testData[startOffset:endOffset]
		partReader := testDataToReader(partData)

		result, err := mpo.ProcessPart(ctx, testUploadID, partNum, partReader)
		require.NoError(t, err, "Should process part %d", partNum)
		require.NotNil(t, result, "Part result should not be nil")
		assert.Equal(t, "aes-ctr", result.Algorithm, "Should use AES-CTR")

		t.Logf("   ✓ Part %d processed (%d bytes)", partNum, len(partData))
	}

	t.Log("Phase 3: Finalizing session with HMACManager")

	// Finalize session
	metadata, err := mpo.FinalizeSession(ctx, testUploadID)
	require.NoError(t, err, "Should finalize session")
	require.NotNil(t, metadata, "Metadata should not be nil")

	// Verify HMAC is present
	hmacValue, exists := metadata["s3ep-hmac"]
	require.True(t, exists, "HMAC should be present in metadata")
	require.NotEmpty(t, hmacValue, "HMAC value should not be empty")

	t.Log("✅ Multipart HMACManager interface workflow completed successfully!")
	t.Logf("   ✓ Session initiated with HMAC calculator")
	t.Logf("   ✓ %d parts processed with streaming HMAC", numParts)
	t.Logf("   ✓ Session finalized with HMAC: %s", hmacValue)
}

// TestCTREncryptionWithNewHMACInterface tests CTR encryption specifically
// since this works correctly
func TestCTREncryptionWithNewHMACInterface(t *testing.T) {
	ctx := context.Background()

	t.Log("🔧 Testing CTR encryption with new HMACManager interface")

	// Create config with HMAC enabled
	cfg := createTestConfig()
	cfg.Encryption.IntegrityVerification = "strict"

	manager, err := createTestManager(cfg)
	require.NoError(t, err, "Should create manager")

	spo := manager.singlePartOps

	// Generate large test data to force CTR
	testData := make([]byte, 7*1024*1024) // 7MB
	rand.Read(testData)

	const testObjectKey = "ctr-hmac-interface-test"

	t.Log("Phase 1: Encrypting with CTR and new HMAC interface")

	// Encrypt
	dataReader := testDataToReaderSinglepart(testData)
	result, err := spo.EncryptCTR(ctx, dataReader, testObjectKey)
	require.NoError(t, err, "EncryptCTR should succeed")
	require.NotNil(t, result, "Result should not be nil")

	// Verify HMAC is present
	hmacValue, exists := result.Metadata["s3ep-hmac"]
	require.True(t, exists, "HMAC should be present")
	require.NotEmpty(t, hmacValue, "HMAC should not be empty")

	// Read encrypted data
	encryptedData, err := io.ReadAll(result.EncryptedData)
	require.NoError(t, err, "Should read encrypted data")

	t.Log("Phase 2: Decrypting with CTR and HMAC verification")

	// Decrypt
	encryptedReader := testDataToReaderSinglepart(encryptedData)
	decryptedReader, err := spo.DecryptCTR(ctx, encryptedReader, result.Metadata, testObjectKey)
	require.NoError(t, err, "DecryptCTR should succeed")

	// Verify data matches
	decryptedData, err := io.ReadAll(decryptedReader)
	require.NoError(t, err, "Should read decrypted data")
	assert.Equal(t, testData, decryptedData, "Decrypted data should match original")

	t.Log("✅ CTR encryption with new HMACManager interface works perfectly!")
	t.Logf("   ✓ Data encrypted with CTR algorithm")
	t.Logf("   ✓ HMAC generated: %s", hmacValue)
	t.Logf("   ✓ Data decrypted and HMAC verified successfully")
	t.Logf("   ✓ Original data integrity confirmed")
}
