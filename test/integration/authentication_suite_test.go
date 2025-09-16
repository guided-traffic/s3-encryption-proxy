//go:build integration
// +build integration

package integration

import (
	"testing"
)

// TestAuthentication is the main authentication test suite that groups all authentication-related tests
func TestAuthentication(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping authentication tests in short mode")
	}

	// Run all authentication-related tests as subtests
	t.Run("S3ClientAuthentication", func(t *testing.T) {
		// This will run all tests from s3_client_auth_test.go
		TestS3ClientAuthentication(t)
	})

	t.Run("RobustS3Authentication", func(t *testing.T) {
		// This will run all tests from s3_robust_auth_test.go
		TestRobustS3Authentication(t)
	})

	t.Run("EnterpriseSecurityConfiguration", func(t *testing.T) {
		// This will run all tests from enterprise_security_test.go
		TestEnterpriseSecurityConfiguration(t)
	})
}
