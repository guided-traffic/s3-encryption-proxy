//go:build integration
// +build integration

package integration

import (
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

// calculateSHA256 calculates the SHA256 hash of the given data
func calculateSHA256(data []byte) string {
	hash := sha256.Sum256(data)
	return fmt.Sprintf("%x", hash)
}

// assertDataHashesEqual compares two byte slices by their SHA256 hashes
// This avoids flooding console output with large hex dumps while still ensuring data integrity
func assertDataHashesEqual(t *testing.T, expected, actual []byte, msgAndArgs ...interface{}) {
	t.Helper()

	expectedHash := calculateSHA256(expected)
	actualHash := calculateSHA256(actual)

	// First check lengths for better error messages
	if !assert.Equal(t, len(expected), len(actual), "Data lengths should match") {
		t.Logf("Expected length: %d, Actual length: %d", len(expected), len(actual))
		return
	}

	// Then compare hashes
	if !assert.Equal(t, expectedHash, actualHash, msgAndArgs...) {
		t.Logf("Data content mismatch detected via SHA256 hash comparison")
		t.Logf("Expected SHA256: %s", expectedHash)
		t.Logf("Actual SHA256: %s", actualHash)
		return
	}

	t.Logf("✅ Data integrity verified via SHA256 hash: %s", expectedHash)
}

// assertDataHashesNotEqual compares two byte slices by their SHA256 hashes to ensure they are different
// This is useful for verifying encryption without flooding console output
func assertDataHashesNotEqual(t *testing.T, expected, actual []byte, msgAndArgs ...interface{}) {
	t.Helper()

	expectedHash := calculateSHA256(expected)
	actualHash := calculateSHA256(actual)

	// Compare hashes to ensure they are different
	if !assert.NotEqual(t, expectedHash, actualHash, msgAndArgs...) {
		t.Logf("Data hashes unexpectedly match - encryption may not be working")
		t.Logf("Both SHA256 hashes: %s", expectedHash)
		return
	}

	t.Logf("✅ Data successfully encrypted - hashes differ (Original: %s...)", expectedHash[:16])
}
