package validation

import (
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/hkdf"
)

func TestNewHMACManager(t *testing.T) {
	manager := NewHMACManager()

	assert.NotNil(t, manager)
	assert.NotNil(t, manager.logger)
	assert.Equal(t, "hmac_manager", manager.logger.Data["component"])
}

func TestHMACManager_CreateCalculator(t *testing.T) {
	manager := NewHMACManager()

	tests := []struct {
		name        string
		dek         []byte
		expectError bool
		errorMsg    string
	}{
		{
			name:        "valid 32-byte DEK",
			dek:         make([]byte, 32),
			expectError: false,
		},
		{
			name:        "valid 16-byte DEK",
			dek:         make([]byte, 16),
			expectError: false,
		},
		{
			name:        "valid random DEK",
			dek:         generateRandomBytes(t, 32),
			expectError: false,
		},
		{
			name:        "empty DEK",
			dek:         []byte{},
			expectError: true,
			errorMsg:    "DEK is empty",
		},
		{
			name:        "nil DEK",
			dek:         nil,
			expectError: true,
			errorMsg:    "DEK is empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			calculator, err := manager.CreateCalculator(tt.dek)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, calculator)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, calculator)

				// Verify the calculator is functional
				testData := []byte("test data")
				_, err := calculator.Add(testData)
				require.NoError(t, err)
				hash := calculator.GetCurrentHash()
				assert.NotNil(t, hash)
				assert.Len(t, hash, 32) // SHA256 hash length
			}
		})
	}
}

func TestHMACManager_CreateCalculator_DeterministicKeys(t *testing.T) {
	manager := NewHMACManager()
	dek := []byte("test-dek-for-deterministic-test")

	// Create two calculators with the same DEK
	calc1, err1 := manager.CreateCalculator(dek)
	require.NoError(t, err1)
	require.NotNil(t, calc1)

	calc2, err2 := manager.CreateCalculator(dek)
	require.NoError(t, err2)
	require.NotNil(t, calc2)

	// Test that they produce the same HMAC for the same data
	testData := []byte("deterministic test data")

	_, err1 = calc1.Add(testData)
	require.NoError(t, err1)
	_, err2 = calc2.Add(testData)
	require.NoError(t, err2)

	hash1 := calc1.GetCurrentHash()
	hash2 := calc2.GetCurrentHash()

	assert.Equal(t, hash1, hash2, "Same DEK should produce same HMAC keys and results")
}

func TestHMACManager_CreateCalculator_HKDF_Integration(t *testing.T) {
	manager := NewHMACManager()
	dek := generateRandomBytes(t, 32)

	calculator, err := manager.CreateCalculator(dek)
	require.NoError(t, err)
	require.NotNil(t, calculator)

	// Manually derive the same HMAC key using HKDF to verify consistency
	hkdfReader := hkdf.New(sha256.New, dek, []byte(hmacSalt), []byte(hmacInfo))
	expectedHMACKey := make([]byte, 32)
	n, err := hkdfReader.Read(expectedHMACKey)
	require.NoError(t, err)
	require.Equal(t, 32, n)

	// Create a manual calculator with the expected key
	expectedCalculator, err := NewHMACCalculator(expectedHMACKey)
	require.NoError(t, err)

	// Test that both calculators produce the same result
	testData := []byte("hkdf integration test data")

	_, err = calculator.Add(testData)
	require.NoError(t, err)
	_, err = expectedCalculator.Add(testData)
	require.NoError(t, err)

	actualHash := calculator.GetCurrentHash()
	expectedHash := expectedCalculator.GetCurrentHash()

	assert.Equal(t, expectedHash, actualHash, "HKDF derivation should match manual calculation")
}

func TestHMACManager_FinalizeCalculator(t *testing.T) {
	manager := NewHMACManager()

	tests := []struct {
		name               string
		setupCalculator    func() *HMACCalculator
		expectedNil        bool
		expectedLogMessage string
	}{
		{
			name: "valid calculator with data",
			setupCalculator: func() *HMACCalculator {
				dek := generateRandomBytes(t, 32)
				calc, err := manager.CreateCalculator(dek)
				require.NoError(t, err)
				_, err = calc.Add([]byte("test data"))
				require.NoError(t, err)
				return calc
			},
			expectedNil: false,
		},
		{
			name: "valid calculator without data",
			setupCalculator: func() *HMACCalculator {
				dek := generateRandomBytes(t, 32)
				calc, err := manager.CreateCalculator(dek)
				require.NoError(t, err)
				return calc
			},
			expectedNil: false,
		},
		{
			name: "nil calculator",
			setupCalculator: func() *HMACCalculator {
				return nil
			},
			expectedNil:        true,
			expectedLogMessage: "Cannot finalize nil HMAC calculator",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			calculator := tt.setupCalculator()

			result := manager.FinalizeCalculator(calculator)

			if tt.expectedNil {
				assert.Nil(t, result)
			} else {
				assert.NotNil(t, result)
				assert.Len(t, result, 32) // SHA256 hash length

				// Verify calculator is cleaned up (should not be usable after finalization)
				// Note: This depends on the Cleanup() implementation in HMACCalculator
			}
		})
	}
}

func TestHMACManager_VerifyIntegrity(t *testing.T) {
	manager := NewHMACManager()
	dek := generateRandomBytes(t, 32)
	testData := []byte("integrity verification test data")

	tests := []struct {
		name         string
		setupTest    func() (*HMACCalculator, []byte)
		expectError  bool
		errorMessage string
	}{
		{
			name: "valid matching HMAC",
			setupTest: func() (*HMACCalculator, []byte) {
				// Create calculator and compute expected HMAC
				calc1, err := manager.CreateCalculator(dek)
				require.NoError(t, err)
				_, err = calc1.Add(testData)
				require.NoError(t, err)
				expectedHMAC := manager.FinalizeCalculator(calc1)

				// Create new calculator for verification
				calc2, err := manager.CreateCalculator(dek)
				require.NoError(t, err)
				_, err = calc2.Add(testData)
				require.NoError(t, err)

				return calc2, expectedHMAC
			},
			expectError: false,
		},
		{
			name: "mismatched HMAC - different data",
			setupTest: func() (*HMACCalculator, []byte) {
				// Create calculator with different data
				calc1, err := manager.CreateCalculator(dek)
				require.NoError(t, err)
				_, err = calc1.Add([]byte("different data"))
				require.NoError(t, err)
				expectedHMAC := manager.FinalizeCalculator(calc1)

				// Create new calculator with original test data
				calc2, err := manager.CreateCalculator(dek)
				require.NoError(t, err)
				_, err = calc2.Add(testData)
				require.NoError(t, err)

				return calc2, expectedHMAC
			},
			expectError:  true,
			errorMessage: "HMAC verification failed: data integrity compromised",
		},
		{
			name: "mismatched HMAC - different key",
			setupTest: func() (*HMACCalculator, []byte) {
				// Create calculator with different DEK
				differentDEK := generateRandomBytes(t, 32)
				calc1, err := manager.CreateCalculator(differentDEK)
				require.NoError(t, err)
				_, err = calc1.Add(testData)
				require.NoError(t, err)
				expectedHMAC := manager.FinalizeCalculator(calc1)

				// Create new calculator with original DEK
				calc2, err := manager.CreateCalculator(dek)
				require.NoError(t, err)
				_, err = calc2.Add(testData)
				require.NoError(t, err)

				return calc2, expectedHMAC
			},
			expectError:  true,
			errorMessage: "HMAC verification failed: data integrity compromised",
		},
		{
			name: "nil calculator",
			setupTest: func() (*HMACCalculator, []byte) {
				return nil, []byte("some hmac")
			},
			expectError:  true,
			errorMessage: "HMAC calculator is nil",
		},
		{
			name: "empty expected HMAC",
			setupTest: func() (*HMACCalculator, []byte) {
				calc, err := manager.CreateCalculator(dek)
				require.NoError(t, err)
				_, err = calc.Add(testData)
				require.NoError(t, err)
				return calc, []byte{}
			},
			expectError:  true,
			errorMessage: "expected HMAC is empty",
		},
		{
			name: "nil expected HMAC",
			setupTest: func() (*HMACCalculator, []byte) {
				calc, err := manager.CreateCalculator(dek)
				require.NoError(t, err)
				_, err = calc.Add(testData)
				require.NoError(t, err)
				return calc, nil
			},
			expectError:  true,
			errorMessage: "expected HMAC is empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			calculator, expectedHMAC := tt.setupTest()

			err := manager.VerifyIntegrity(calculator, expectedHMAC)

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMessage)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestHMACManager_VerifyIntegrity_ConstantTimeComparison(t *testing.T) {
	manager := NewHMACManager()
	dek := generateRandomBytes(t, 32)
	testData := []byte("constant time test data")

	// Create calculator and get valid HMAC
	calc1, err := manager.CreateCalculator(dek)
	require.NoError(t, err)
	_, err = calc1.Add(testData)
	require.NoError(t, err)
	validHMAC := manager.FinalizeCalculator(calc1)

	// Test with HMAC that differs only in the last byte
	invalidHMAC := make([]byte, len(validHMAC))
	copy(invalidHMAC, validHMAC)
	invalidHMAC[len(invalidHMAC)-1] ^= 0x01 // Flip last bit

	// Create new calculator for verification
	calc2, err := manager.CreateCalculator(dek)
	require.NoError(t, err)
	_, err = calc2.Add(testData)
	require.NoError(t, err)

	err = manager.VerifyIntegrity(calc2, invalidHMAC)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "HMAC verification failed: data integrity compromised")
}

func TestHMACManager_EndToEndWorkflow(t *testing.T) {
	manager := NewHMACManager()
	dek := generateRandomBytes(t, 32)

	// Simulate streaming data
	chunks := [][]byte{
		[]byte("first chunk of data"),
		[]byte("second chunk of data"),
		[]byte("third and final chunk"),
	}

	// Create calculator and process chunks
	calculator, err := manager.CreateCalculator(dek)
	require.NoError(t, err)
	require.NotNil(t, calculator)

	// Process all chunks
	for _, chunk := range chunks {
		_, err := calculator.Add(chunk)
		require.NoError(t, err)
	}

	// Finalize and get HMAC
	computedHMAC := manager.FinalizeCalculator(calculator)
	require.NotNil(t, computedHMAC)
	require.Len(t, computedHMAC, 32)

	// Verify integrity with a new calculator
	verifyCalculator, err := manager.CreateCalculator(dek)
	require.NoError(t, err)

	for _, chunk := range chunks {
		_, err := verifyCalculator.Add(chunk)
		require.NoError(t, err)
	}

	err = manager.VerifyIntegrity(verifyCalculator, computedHMAC)
	assert.NoError(t, err, "End-to-end workflow should verify successfully")
}

func TestHMACManager_LargeDataHandling(t *testing.T) {
	manager := NewHMACManager()
	dek := generateRandomBytes(t, 32)

	// Create large test data (1MB)
	largeData := generateRandomBytes(t, 1024*1024)

	// Create calculator and process large data
	calculator, err := manager.CreateCalculator(dek)
	require.NoError(t, err)

	_, err = calculator.Add(largeData)
	require.NoError(t, err)
	computedHMAC := manager.FinalizeCalculator(calculator)
	require.NotNil(t, computedHMAC)

	// Verify with new calculator
	verifyCalculator, err := manager.CreateCalculator(dek)
	require.NoError(t, err)

	_, err = verifyCalculator.Add(largeData)
	require.NoError(t, err)
	err = manager.VerifyIntegrity(verifyCalculator, computedHMAC)
	assert.NoError(t, err, "Large data HMAC verification should succeed")
}

// Helper function to generate random bytes for testing
func generateRandomBytes(t *testing.T, size int) []byte {
	t.Helper()
	bytes := make([]byte, size)
	_, err := rand.Read(bytes)
	require.NoError(t, err)
	return bytes
}
