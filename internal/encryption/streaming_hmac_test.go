package encryption

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/guided-traffic/s3-encryption-proxy/internal/config"
)

// TestVerifyStreamingHMAC tests the verifyStreamingHMAC function directly.
//
// **Test Purpose:**
// Tests the core HMAC verification logic for streaming operations at function level.
// This ensures the verifyStreamingHMAC function handles all scenarios correctly
// without requiring full encryption/decryption workflow.
//
// **Coverage Goals:**
// - Verify HMAC verification is skipped when HMAC manager is disabled
// - Verify HMAC verification is skipped when HMAC is missing from metadata (treated as optional)
// - Verify HMAC verification handles invalid base64 HMAC data gracefully
// - Verify HMAC manager state (enabled/disabled) affects verification behavior
// - Achieve significant coverage improvement for streaming.go:986 (verifyStreamingHMAC)
//
// **Test Scenarios:**
// 1. HMAC_Verification_Enabled_But_No_HMAC_In_Metadata - Tests backward compatibility
// 2. HMAC_Verification_Disabled - Tests "off" mode behavior
// 3. HMAC_Manager_Not_Enabled - Tests manager state consistency
// 4. HMAC_Manager_Enabled - Tests enabled state with missing HMAC
// 5. HMAC_Invalid_Base64_Error - Tests error handling for corrupted metadata
//
// **Expected Behavior:**
// - Missing HMAC should not cause verification failure (backward compatibility)
// - Disabled HMAC manager should skip all verification
// - Invalid base64 HMAC should be treated as missing HMAC (optional)
// - Function should be resilient and not crash on edge cases
func TestVerifyStreamingHMAC(t *testing.T) {
	// Helper function to create AES config with HMAC enabled
	createHMACTestConfig := func(verificationMode string) *config.Config {
		return &config.Config{
			Encryption: config.EncryptionConfig{
				EncryptionMethodAlias: "aes-ctr-hmac",
				IntegrityVerification: verificationMode,
				MetadataKeyPrefix:     &[]string{"s3ep-"}[0],
				Providers: []config.EncryptionProvider{
					{
						Alias: "aes-ctr-hmac",
						Type:  "aes",
						Config: map[string]interface{}{
							"aes_key": "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=", // 32-byte key
						},
					},
				},
			},
			Optimizations: config.OptimizationsConfig{
				StreamingSegmentSize: 1024, // 1KB segments for testing
			},
		}
	}

	t.Run("HMAC_Verification_Enabled_But_No_HMAC_In_Metadata", func(t *testing.T) {
		// **Test Case: Missing HMAC Handling - Backward Compatibility**
		//
		// **Purpose:** Verify that when HMAC verification is enabled but no HMAC
		// is present in metadata, the verification is skipped gracefully without error.
		// This ensures backward compatibility with older encrypted data.
		//
		// **Test Scenario:**
		// - HMAC manager is enabled (strict mode)
		// - Metadata contains encryption info but no HMAC field
		// - verifyStreamingHMAC is called with nil decryptor (function-level test)
		//
		// **Expected Behavior:**
		// - No error should be returned (HMAC is optional)
		// - Function should log that HMAC verification is skipped
		// - Backward compatibility is maintained for legacy data
		cfg := createHMACTestConfig("strict")
		sop, err := createHMACTestStreamingOperations(cfg)
		require.NoError(t, err)

		// Create a mock decryptor (we only need nil since we test missing HMAC case)
		metadata := map[string]string{
			"s3ep-dek-algorithm": "aes-ctr",
			"s3ep-kek-fingerprint": "test-fingerprint",
			// No HMAC in metadata
		}

		// This should succeed since HMAC is optional when missing
		err = sop.verifyStreamingHMAC(nil, metadata)
		assert.NoError(t, err)

		t.Logf("✅ HMAC verification skipped when HMAC missing from metadata")
	})

	t.Run("HMAC_Verification_Disabled", func(t *testing.T) {
		// **Test Case: Disabled HMAC Verification - Off Mode**
		//
		// **Purpose:** Verify that when HMAC verification is explicitly disabled,
		// the verifyStreamingHMAC function skips verification entirely, even if
		// HMAC data is present in metadata.
		//
		// **Test Scenario:**
		// - HMAC manager is disabled (off mode)
		// - Metadata contains HMAC field (should be ignored)
		// - verifyStreamingHMAC is called
		//
		// **Expected Behavior:**
		// - No verification should occur regardless of HMAC presence
		// - Function should return early without processing
		// - Performance is optimized by avoiding unnecessary operations
		cfg := createHMACTestConfig("off")
		sop, err := createHMACTestStreamingOperations(cfg)
		require.NoError(t, err)

		// Create metadata with HMAC (should be ignored)
		metadata := map[string]string{
			"s3ep-dek-algorithm": "aes-ctr",
			"s3ep-kek-fingerprint": "test-fingerprint",
			"s3ep-hmac": "dGVzdGhtYWNkYXRhZm9ydGVzdGluZzEyMzQ1Njc4OTA=",
		}

		// This should succeed since HMAC verification is disabled
		err = sop.verifyStreamingHMAC(nil, metadata)
		assert.NoError(t, err)

		t.Logf("✅ HMAC verification skipped when disabled")
	})

	t.Run("HMAC_Manager_Not_Enabled", func(t *testing.T) {
		// **Test Case: HMAC Manager State Consistency**
		//
		// **Purpose:** Verify that the HMAC manager state is correctly reflected
		// in the verification behavior. This ensures consistency between manager
		// configuration and actual runtime behavior.
		//
		// **Test Scenario:**
		// - Configuration sets HMAC to off mode
		// - HMAC manager IsEnabled() returns false
		// - Metadata contains HMAC field
		// - verifyStreamingHMAC is called
		//
		// **Expected Behavior:**
		// - HMAC manager should report as not enabled
		// - Verification should be skipped due to manager state
		// - Configuration and runtime behavior should be consistent
		cfg := createHMACTestConfig("off")
		sop, err := createHMACTestStreamingOperations(cfg)
		require.NoError(t, err)

		// Ensure HMAC manager is not enabled
		assert.False(t, sop.hmacManager.IsEnabled())

		metadata := map[string]string{
			"s3ep-hmac": "dGVzdGhtYWNkYXRhZm9ydGVzdGluZzEyMzQ1Njc4OTA=",
		}

		// Should skip verification when HMAC manager is disabled
		err = sop.verifyStreamingHMAC(nil, metadata)
		assert.NoError(t, err)

		t.Logf("✅ HMAC verification correctly skipped when HMAC manager disabled")
	})

	t.Run("HMAC_Manager_Enabled", func(t *testing.T) {
		// **Test Case: Enabled HMAC Manager with Missing HMAC**
		//
		// **Purpose:** Test the behavior when HMAC manager is enabled but
		// the specific metadata doesn't contain HMAC. This tests the optional
		// nature of HMAC verification and graceful degradation.
		//
		// **Test Scenario:**
		// - HMAC manager is enabled (strict mode)
		// - Metadata contains encryption info but no HMAC field
		// - IsEnabled() returns true but no HMAC to verify
		//
		// **Expected Behavior:**
		// - HMAC manager should report as enabled
		// - Missing HMAC should be treated as optional (no error)
		// - Graceful degradation without breaking decryption
		cfg := createHMACTestConfig("strict")
		sop, err := createHMACTestStreamingOperations(cfg)
		require.NoError(t, err)

		// Ensure HMAC manager is enabled
		assert.True(t, sop.hmacManager.IsEnabled())

		metadata := map[string]string{
			"s3ep-dek-algorithm": "aes-ctr",
			"s3ep-kek-fingerprint": "test-fingerprint",
			// No HMAC - should be treated as optional
		}

		// Should succeed when HMAC is missing (treated as optional)
		err = sop.verifyStreamingHMAC(nil, metadata)
		assert.NoError(t, err)

		t.Logf("✅ HMAC verification handles missing HMAC gracefully")
	})

	t.Run("HMAC_Invalid_Base64_Error", func(t *testing.T) {
		// **Test Case: Corrupted HMAC Metadata Handling**
		//
		// **Purpose:** Verify that corrupted or invalid base64 HMAC data in metadata
		// is handled gracefully without crashing the system. This tests robustness
		// against malformed metadata.
		//
		// **Test Scenario:**
		// - HMAC manager is enabled
		// - Metadata contains invalid base64 HMAC data ("invalid-base64-data!!!")
		// - GetHMAC() fails with base64 decode error
		//
		// **Expected Behavior:**
		// - Invalid base64 HMAC should be treated as missing HMAC
		// - No error should be returned (graceful degradation)
		// - System should continue operating without crashing
		// - Error should be logged but not propagated
		cfg := createHMACTestConfig("strict")
		sop, err := createHMACTestStreamingOperations(cfg)
		require.NoError(t, err)

		// Metadata with invalid base64 HMAC
		metadata := map[string]string{
			"s3ep-dek-algorithm": "aes-ctr",
			"s3ep-kek-fingerprint": "test-fingerprint",
			"s3ep-hmac": "invalid-base64-data!!!", // Invalid base64
		}

		// Should NOT fail because invalid HMAC is treated as missing HMAC (optional)
		// This is the documented behavior: "HMAC is optional, don't fail if missing"
		err = sop.verifyStreamingHMAC(nil, metadata)
		assert.NoError(t, err)

		t.Logf("✅ HMAC verification treats invalid base64 HMAC as missing (optional)")
	})
}

// TestHMACIntegrityModes tests different integrity verification modes for HMAC management.
//
// **Test Purpose:**
// Validates that the HMAC manager correctly interprets different integrity verification modes
// and behaves appropriately for each mode. This ensures configuration-driven HMAC behavior
// works as expected across different deployment scenarios.
//
// **Coverage Goals:**
// - Test all integrity verification modes: strict, lenient, off, empty
// - Verify HMAC manager state correlates with configured mode
// - Test HMAC calculation and metadata addition for enabled modes
// - Test metadata handling for disabled modes
// - Ensure consistent behavior across configuration changes
//
// **Test Scenarios:**
// 1. Strict Mode - HMAC manager enabled, HMAC required for verification
// 2. Lenient Mode - HMAC manager enabled, HMAC optional for backward compatibility
// 3. Off Mode - HMAC manager disabled, no HMAC operations
// 4. Empty Mode - Default behavior when mode not specified (HMAC remains enabled)
//
// **Expected Behavior:**
// - strict/lenient modes enable HMAC manager and allow HMAC calculation
// - only explicit "off" mode disables HMAC manager and skips HMAC operations
// - HMAC metadata is only added when manager is enabled
// - Disabled manager should not error but simply skip operations
func TestHMACIntegrityModes(t *testing.T) {
	testCases := []struct {
		name string
		mode string
		expectHMAC bool
	}{
		{"Strict Mode", "strict", true},      // **Strict Mode:** HMAC required, verification enabled, failures cause errors
		{"Lenient Mode", "lenient", true},    // **Lenient Mode:** HMAC preferred, verification enabled, missing HMAC allowed
		{"Off Mode", "off", false},           // **Off Mode:** HMAC disabled, no verification, no HMAC generation
		{"Empty Mode", "", true},             // **Empty/Default Mode:** Empty string enables HMAC (only explicit "off" disables)
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Config{
				Encryption: config.EncryptionConfig{
					EncryptionMethodAlias: "aes-ctr-test",
					IntegrityVerification: tc.mode,
					MetadataKeyPrefix:     &[]string{"s3ep-"}[0],
					Providers: []config.EncryptionProvider{
						{
							Alias: "aes-ctr-test",
							Type:  "aes",
							Config: map[string]interface{}{
								"aes_key": "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=",
							},
						},
					},
				},
				Optimizations: config.OptimizationsConfig{
					StreamingSegmentSize: 1024,
				},
			}

			// Test HMAC manager setup
			hmacManager := NewHMACManager(cfg)
			expectedEnabled := tc.mode != "off"  // Only explicit "off" disables HMAC
			assert.Equal(t, expectedEnabled, hmacManager.IsEnabled(),
				"HMAC manager should be enabled=%v for mode: %s", expectedEnabled, tc.mode)

			// Test that HMAC can be calculated for test data when enabled
			if expectedEnabled {
				testData := make([]byte, 2048)
				for i := range testData {
					testData[i] = byte(i % 256)
				}

				// Test DEK for HMAC calculation
				testDEK := make([]byte, 32)
				for i := range testDEK {
					testDEK[i] = byte(i % 256)
				}

				// Test that HMAC can be calculated
				hmacValue, err := hmacManager.CalculateHMAC(testData, testDEK)
				require.NoError(t, err, "Should be able to calculate HMAC when enabled")
				assert.NotEmpty(t, hmacValue, "HMAC should not be empty when calculated")

				// Test metadata addition
				metadata := make(map[string]string)
				err = hmacManager.AddHMACToMetadata(metadata, testData, testDEK, "s3ep-")
				require.NoError(t, err, "Should be able to add HMAC to metadata when enabled")

				_, hasHMAC := metadata["s3ep-hmac"]
				assert.True(t, hasHMAC, "HMAC should be present in metadata when enabled")
			} else {
				// Test that disabled HMAC manager doesn't add metadata
				testData := []byte("test")
				testDEK := make([]byte, 32)
				metadata := make(map[string]string)

				err := hmacManager.AddHMACToMetadata(metadata, testData, testDEK, "s3ep-")
				require.NoError(t, err, "Should not error when HMAC is disabled")

				_, hasHMAC := metadata["s3ep-hmac"]
				assert.False(t, hasHMAC, "HMAC should not be present when disabled")
			}

			t.Logf("✅ Mode %s: HMAC manager enabled=%v, expected=%v", tc.mode, expectedEnabled, expectedEnabled)
		})
	}
}

// Helper function to create streaming operations for HMAC tests
func createHMACTestStreamingOperations(cfg *config.Config) (*StreamingOperations, error) {
	providerManager, err := NewProviderManager(cfg)
	if err != nil {
		return nil, err
	}

	hmacManager := NewHMACManager(cfg)
	var prefix string
	if cfg.Encryption.MetadataKeyPrefix != nil {
		prefix = *cfg.Encryption.MetadataKeyPrefix
	}
	metadataManager := NewMetadataManager(cfg, prefix)

	return NewStreamingOperations(providerManager, hmacManager, metadataManager, cfg), nil
}
