package encryption

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/guided-traffic/s3-encryption-proxy/internal/config"
)

// TestStreamingHMACVerificationAtEndOfStream tests comprehensive HMAC verification behavior
// during real streaming operations, ensuring HMAC verification occurs at the correct point
// in the stream lifecycle (at EOF) and handles all edge cases properly.
//
// **Test Purpose:**
// Validates the complete streaming HMAC verification workflow with real encryption/decryption
// operations. This ensures that HMAC verification is properly integrated into the streaming
// architecture and occurs at the correct point (end of stream when EOF is reached).
//
// **Key Architecture Verification:**
// - HMAC is calculated incrementally during streaming (part-by-part)
// - HMAC verification only occurs when the entire stream has been processed (EOF)
// - Stream is interrupted if HMAC verification fails at the end
// - Partial stream reads do not trigger premature HMAC verification
// - Corrupted data results in HMAC verification failure
//
// **Coverage Goals:**
// - Test real end-to-end streaming HMAC verification workflow
// - Achieve high coverage for DecryptionReader.Read() HMAC verification path
// - Test error handling when HMAC verification fails during streaming
// - Verify performance and memory efficiency of streaming HMAC operations
// - Test integration between EncryptStream and DecryptionReader
//
// **Test Scenarios:**
// 1. Successful_HMAC_Verification_On_Complete_Stream - Happy path with valid HMAC
// 2. HMAC_Verification_Failure_On_Corrupted_Data - Error path with data corruption
// 3. Partial_Stream_Read_No_HMAC_Verification - Partial reads don't trigger verification
// 4. HMAC_Verification_Disabled_No_Error - Disabled HMAC works correctly
//
// **Expected Behavior:**
// - HMAC verification happens only at EOF (when stream is completely read)
// - Corrupted data causes HMAC verification failure and stream interruption
// - Partial reads work normally without triggering HMAC verification
// - Disabled HMAC verification allows normal streaming without HMAC checks
// - Performance remains optimal with no additional stream passes required
func TestStreamingHMACVerificationAtEndOfStream(t *testing.T) {
	t.Run("Successful_HMAC_Verification_On_Complete_Stream", func(t *testing.T) {
		// **Test Case: Happy Path - Complete Stream with Valid HMAC**
		//
		// **Purpose:** Validate that the complete streaming workflow with HMAC verification
		// works correctly when all data is valid and the stream is read to completion.
		//
		// **Test Flow:**
		// 1. Create test data larger than segment size to trigger true streaming behavior
		// 2. Encrypt data using EncryptStream (which generates HMAC)
		// 3. Verify HMAC is present in metadata after encryption
		// 4. Create DecryptionReader for streaming decryption
		// 5. Read entire stream to EOF (triggers HMAC verification)
		// 6. Verify decrypted data matches original data
		//
		// **Expected Result:**
		// - HMAC is generated during encryption and stored in metadata
		// - HMAC verification occurs automatically at EOF during decryption
		// - No errors occur and data integrity is maintained
		// - Streaming performance is maintained (no double-pass required)
		cfg := &config.Config{
			Encryption: config.EncryptionConfig{
				EncryptionMethodAlias: "aes-streaming",
				IntegrityVerification: "strict",
				MetadataKeyPrefix:     &[]string{"s3ep-"}[0],
				Providers: []config.EncryptionProvider{
					{
						Alias: "aes-streaming",
						Type:  "aes",
						Config: map[string]interface{}{
							"aes_key": "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=", // 32-byte key
						},
					},
				},
			},
			Optimizations: config.OptimizationsConfig{
				StreamingSegmentSize: 1024, // 1KB segments
			},
		}

		sop, err := createHMACTestStreamingOperations(cfg)
		require.NoError(t, err)

		// Generate test data larger than segment size to trigger streaming
		testData := make([]byte, 3072) // 3KB > 1KB segment size
		_, err = rand.Read(testData)
		require.NoError(t, err)

		// Encrypt the data first using segment-based encryption (which generates HMAC)
		encryptedData, metadata, err := sop.EncryptStream(context.Background(), bytes.NewReader(testData), "test-streaming-hmac")
		require.NoError(t, err)
		require.NotEmpty(t, metadata, "Metadata should be generated")

		// Verify HMAC is present in metadata
		_, hasHMAC := metadata["s3ep-hmac"]
		assert.True(t, hasHMAC, "HMAC should be present in metadata for streaming encryption")

		// Create decryption reader
		decReader, err := sop.CreateDecryptionReader(context.Background(), bytes.NewReader(encryptedData), metadata)
		require.NoError(t, err)

		// Read the entire stream - HMAC verification should happen at EOF
		decryptedData, err := io.ReadAll(decReader)
		require.NoError(t, err, "HMAC verification should succeed when reading complete stream")

		// Verify data integrity
		assert.Equal(t, testData, decryptedData, "Decrypted data should match original")

		t.Logf("✅ HMAC verification successful at end of stream for %d bytes", len(testData))
	})

	t.Run("HMAC_Verification_Failure_On_Corrupted_Data", func(t *testing.T) {
		// **Test Case: Error Path - Data Corruption Detection**
		//
		// **Purpose:** Ensure that data corruption is detected through HMAC verification
		// failure and that the stream is properly interrupted when corruption is found.
		//
		// **Test Flow:**
		// 1. Create and encrypt test data with valid HMAC generation
		// 2. Intentionally corrupt the encrypted data (flip bits in middle)
		// 3. Create DecryptionReader with corrupted data
		// 4. Attempt to read entire stream to EOF
		// 5. Verify that HMAC verification fails and returns appropriate error
		//
		// **Expected Result:**
		// - HMAC verification detects the data corruption
		// - Error is returned containing "HMAC" indicating verification failure
		// - Stream processing is interrupted when corruption is detected
		// - Error provides clear indication of integrity compromise
		cfg := &config.Config{
			Encryption: config.EncryptionConfig{
				EncryptionMethodAlias: "aes-streaming",
				IntegrityVerification: "strict",
				MetadataKeyPrefix:     &[]string{"s3ep-"}[0],
				Providers: []config.EncryptionProvider{
					{
						Alias: "aes-streaming",
						Type:  "aes",
						Config: map[string]interface{}{
							"aes_key": "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=", // 32-byte key
						},
					},
				},
			},
			Optimizations: config.OptimizationsConfig{
				StreamingSegmentSize: 1024, // 1KB segments
			},
		}

		sop, err := createHMACTestStreamingOperations(cfg)
		require.NoError(t, err)

		// Generate test data larger than segment size
		testData := make([]byte, 2048) // 2KB > 1KB segment size
		_, err = rand.Read(testData)
		require.NoError(t, err)

		// Encrypt the data
		encryptedData, metadata, err := sop.EncryptStream(context.Background(), bytes.NewReader(testData), "test-streaming-hmac-corruption")
		require.NoError(t, err)

		// Corrupt the encrypted data (flip a byte in the middle)
		corruptedData := make([]byte, len(encryptedData))
		copy(corruptedData, encryptedData)
		corruptedData[len(corruptedData)/2] ^= 0xFF // Flip all bits in middle byte

		// Create decryption reader with corrupted data
		decReader, err := sop.CreateDecryptionReader(context.Background(), bytes.NewReader(corruptedData), metadata)
		require.NoError(t, err)

		// Try to read the entire stream - HMAC verification should fail at EOF
		_, err = io.ReadAll(decReader)
		assert.Error(t, err, "HMAC verification should fail for corrupted data")
		assert.Contains(t, err.Error(), "HMAC", "Error should mention HMAC verification failure")

		t.Logf("✅ HMAC verification correctly failed for corrupted data: %v", err)
	})

	t.Run("Partial_Stream_Read_No_HMAC_Verification", func(t *testing.T) {
		// **Test Case: Partial Read Behavior - No Premature Verification**
		//
		// **Purpose:** Verify that HMAC verification only occurs when the complete stream
		// has been processed (EOF reached), not during partial reads. This ensures that
		// applications can perform partial reads without triggering verification.
		//
		// **Test Flow:**
		// 1. Create and encrypt test data with HMAC
		// 2. Create DecryptionReader
		// 3. Read only a small portion of the stream (not to EOF)
		// 4. Verify that no HMAC verification occurs during partial read
		// 5. Verify that partial data is correctly decrypted
		//
		// **Expected Result:**
		// - Partial reads work normally without HMAC verification
		// - No errors occur during partial stream processing
		// - Decrypted partial data matches original partial data
		// - HMAC verification is deferred until EOF is reached
		cfg := &config.Config{
			Encryption: config.EncryptionConfig{
				EncryptionMethodAlias: "aes-streaming",
				IntegrityVerification: "strict",
				MetadataKeyPrefix:     &[]string{"s3ep-"}[0],
				Providers: []config.EncryptionProvider{
					{
						Alias: "aes-streaming",
						Type:  "aes",
						Config: map[string]interface{}{
							"aes_key": "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=", // 32-byte key
						},
					},
				},
			},
			Optimizations: config.OptimizationsConfig{
				StreamingSegmentSize: 1024, // 1KB segments
			},
		}

		sop, err := createHMACTestStreamingOperations(cfg)
		require.NoError(t, err)

		// Generate test data
		testData := make([]byte, 2048) // 2KB
		_, err = rand.Read(testData)
		require.NoError(t, err)

		// Encrypt the data
		encryptedData, metadata, err := sop.EncryptStream(context.Background(), bytes.NewReader(testData), "test-partial-read")
		require.NoError(t, err)

		// Create decryption reader
		decReader, err := sop.CreateDecryptionReader(context.Background(), bytes.NewReader(encryptedData), metadata)
		require.NoError(t, err)

		// Read only partial data (not to EOF) - HMAC verification should not occur
		partialBuffer := make([]byte, 100) // Read only 100 bytes
		n, err := decReader.Read(partialBuffer)
		require.NoError(t, err, "Partial read should succeed without HMAC verification")
		assert.Equal(t, 100, n, "Should read exactly 100 bytes")

		// Verify partial data matches
		assert.Equal(t, testData[:100], partialBuffer, "Partial decrypted data should match")

		t.Logf("✅ Partial stream read successful without HMAC verification")
	})

	t.Run("HMAC_Verification_Disabled_No_Error", func(t *testing.T) {
		// **Test Case: Disabled HMAC Mode - Backward Compatibility**
		//
		// **Purpose:** Ensure that when HMAC verification is disabled, streaming operations
		// continue to work normally without any HMAC-related processing or errors.
		// This maintains backward compatibility with deployments that don't use HMAC.
		//
		// **Test Flow:**
		// 1. Configure system with HMAC verification disabled ("off" mode)
		// 2. Create and encrypt test data (no HMAC should be generated)
		// 3. Verify no HMAC is present in metadata
		// 4. Create DecryptionReader and read entire stream
		// 5. Verify no HMAC verification occurs and no errors are generated
		//
		// **Expected Result:**
		// - No HMAC is generated during encryption when disabled
		// - No HMAC verification occurs during decryption when disabled
		// - Streaming operations work normally without HMAC overhead
		// - Data integrity is maintained through encryption alone (no additional HMAC layer)
		cfg := &config.Config{
			Encryption: config.EncryptionConfig{
				EncryptionMethodAlias: "aes-streaming",
				IntegrityVerification: "off", // HMAC disabled
				MetadataKeyPrefix:     &[]string{"s3ep-"}[0],
				Providers: []config.EncryptionProvider{
					{
						Alias: "aes-streaming",
						Type:  "aes",
						Config: map[string]interface{}{
							"aes_key": "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=", // 32-byte key
						},
					},
				},
			},
			Optimizations: config.OptimizationsConfig{
				StreamingSegmentSize: 1024, // 1KB segments
			},
		}

		sop, err := createHMACTestStreamingOperations(cfg)
		require.NoError(t, err)

		// Generate test data
		testData := make([]byte, 1536) // 1.5KB
		_, err = rand.Read(testData)
		require.NoError(t, err)

		// Encrypt the data (no HMAC should be generated)
		encryptedData, metadata, err := sop.EncryptStream(context.Background(), bytes.NewReader(testData), "test-no-hmac")
		require.NoError(t, err)

		// Verify no HMAC in metadata
		_, hasHMAC := metadata["s3ep-hmac"]
		assert.False(t, hasHMAC, "HMAC should not be present when disabled")

		// Create decryption reader
		decReader, err := sop.CreateDecryptionReader(context.Background(), bytes.NewReader(encryptedData), metadata)
		require.NoError(t, err)

		// Read the entire stream - no HMAC verification should occur
		decryptedData, err := io.ReadAll(decReader)
		require.NoError(t, err, "Decryption should succeed without HMAC verification")

		// Verify data integrity
		assert.Equal(t, testData, decryptedData, "Decrypted data should match original")

		t.Logf("✅ Streaming decryption successful with HMAC verification disabled")
	})
}
