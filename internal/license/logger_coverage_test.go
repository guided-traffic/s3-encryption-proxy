package license

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// LiclevelOf returns the level of the first entry containing the substring.
func LiclevelOf(t *testing.T, entries []*logrus.Entry, substr string) logrus.Level {
	t.Helper()
	for _, entry := range entries {
		if strings.Contains(entry.Message, substr) {
			return entry.Level
		}
	}
	t.Fatalf("no log entry containing %q", substr)
	return logrus.PanicLevel
}

// TestLicLogLicenseInfoInvalidResult asserts the unlicensed banner is written
// with warning severity and points the operator at the licensing page.
func TestLicLogLicenseInfoInvalidResult(t *testing.T) {
	t.Run("with error", func(t *testing.T) {
		hook := LiccaptureLogs(t)
		LogLicenseInfo(&ValidationResult{
			Valid:   false,
			Error:   errors.New("signature is invalid"),
			Message: "License validation failed - invalid token",
		})

		entries := hook.AllEntries()
		require.NotEmpty(t, entries)
		assert.Equal(t, logrus.WarnLevel, entries[0].Level)
		assert.Equal(t, "License validation failed", entries[0].Message)
		assert.EqualError(t, entries[0].Data[logrus.ErrorKey].(error), "signature is invalid")

		assert.True(t, Liclogged(hook, "License validation failed - invalid token"))
		assert.True(t, Liclogged(hook, "Encryption disabled - only decryption of existing data available"))
		assert.True(t, Liclogged(hook, "https://s3ep.com"))
	})

	t.Run("without error", func(t *testing.T) {
		hook := LiccaptureLogs(t)
		LogLicenseInfo(&ValidationResult{
			Valid:   false,
			Message: "No license token provided - running in read-only mode (encryption disabled)",
		})

		entries := hook.AllEntries()
		require.NotEmpty(t, entries)
		for _, entry := range entries {
			assert.Equal(t, logrus.WarnLevel, entry.Level)
			assert.NotContains(t, entry.Data, logrus.ErrorKey)
		}
		assert.True(t, Liclogged(hook, "No license token provided"))
	})
}

// TestLicLogLicenseInfoWithoutClaims covers the defensive branches where a
// result is marked valid but carries no usable payload.
func TestLicLogLicenseInfoWithoutClaims(t *testing.T) {
	tests := []struct {
		name   string
		result *ValidationResult
	}{
		{name: "nil info", result: &ValidationResult{Valid: true}},
		{name: "nil claims", result: &ValidationResult{Valid: true, Info: &LicenseInfo{Valid: true}}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hook := LiccaptureLogs(t)
			LogLicenseInfo(tt.result)

			entries := hook.AllEntries()
			require.Len(t, entries, 1)
			assert.Equal(t, logrus.WarnLevel, entries[0].Level)
			assert.Equal(t, "No license information available", entries[0].Message)
		})
	}
}

// TestLicLogLicenseInfoFullDetails asserts every optional claim is rendered and
// that a long-lived license produces no renewal warning.
func TestLicLogLicenseInfoFullDetails(t *testing.T) {
	hook := LiccaptureLogs(t)

	expires := time.Now().Add(400 * 24 * time.Hour)
	LogLicenseInfo(&ValidationResult{
		Valid: true,
		Info: &LicenseInfo{
			Valid:     true,
			ExpiresAt: expires,
			Claims: &LicenseClaims{
				LicenseeName:        "John Doe",
				LicenseeCompany:     "Acme Corp",
				LicenseNote:         "Production License",
				KubernetesClusterID: "cluster-prod-01",
			},
			TimeRemaining: TimeRemaining{Years: 1, Days: 35, Total: 400 * 24 * time.Hour},
		},
	})

	assert.True(t, Liclogged(hook, "Licensed to: John Doe"))
	assert.True(t, Liclogged(hook, "Company: Acme Corp"))
	assert.True(t, Liclogged(hook, "License Note: Production License"))
	assert.True(t, Liclogged(hook, "Kubernetes Cluster: cluster-prod-01"))
	assert.True(t, Liclogged(hook, "Kubernetes Cluster ID validation not yet implemented"))
	assert.True(t, Liclogged(hook, "License expires: "+expires.Format("2006-01-02 15:04:05 MST")))
	assert.True(t, Liclogged(hook, "Time remaining: 1 year, 35 days"))
	assert.False(t, Liclogged(hook, "License expires soon"))
}

// TestLicLogLicenseInfoMinimalClaims asserts optional lines are skipped when
// the corresponding claims are empty.
func TestLicLogLicenseInfoMinimalClaims(t *testing.T) {
	hook := LiccaptureLogs(t)

	LogLicenseInfo(&ValidationResult{
		Valid: true,
		Info: &LicenseInfo{
			Valid:  true,
			Claims: &LicenseClaims{LicenseeName: "Solo User"},
		},
	})

	assert.True(t, Liclogged(hook, "Licensed to: Solo User"))
	assert.False(t, Liclogged(hook, "Company:"))
	assert.False(t, Liclogged(hook, "License Note:"))
	assert.False(t, Liclogged(hook, "Kubernetes Cluster:"))
	assert.True(t, Liclogged(hook, "License: No expiration date"))
}

// TestLicLogLicenseInfoExpiringSoon asserts the renewal warning fires inside
// the 30 day window and is logged at warning level.
func TestLicLogLicenseInfoExpiringSoon(t *testing.T) {
	hook := LiccaptureLogs(t)

	LogLicenseInfo(&ValidationResult{
		Valid: true,
		Info: &LicenseInfo{
			Valid:         true,
			ExpiresAt:     time.Now().Add(72 * time.Hour),
			Claims:        &LicenseClaims{LicenseeName: "Soon Expired"},
			TimeRemaining: TimeRemaining{Days: 3, Total: 72 * time.Hour},
		},
	})

	assert.True(t, Liclogged(hook, "Time remaining: 3 days"))
	assert.True(t, Liclogged(hook, "License expires soon"))
	assert.Equal(t, logrus.WarnLevel, LiclevelOf(t, hook.AllEntries(), "License expires soon"))
}

// TestLicLogLicenseInfoExhaustedTimeRemaining covers the branch where an
// expiration date exists but no time is left to report.
func TestLicLogLicenseInfoExhaustedTimeRemaining(t *testing.T) {
	hook := LiccaptureLogs(t)

	expires := time.Now().Add(-time.Hour)
	LogLicenseInfo(&ValidationResult{
		Valid: true,
		Info: &LicenseInfo{
			Valid:     true,
			ExpiresAt: expires,
			Claims:    &LicenseClaims{LicenseeName: "Past Due"},
		},
	})

	assert.True(t, Liclogged(hook, "License expires: "+expires.Format("2006-01-02 15:04:05 MST")))
	assert.False(t, Liclogged(hook, "Time remaining:"))
	assert.False(t, Liclogged(hook, "License expires soon"))
}

// TestLicFormatTimeRemainingSubHour covers the branches below one day.
func TestLicFormatTimeRemainingSubHour(t *testing.T) {
	tests := []struct {
		name      string
		remaining TimeRemaining
		want      string
	}{
		{name: "one hour", remaining: TimeRemaining{Total: time.Hour}, want: "1 hour"},
		{name: "just under an hour", remaining: TimeRemaining{Total: 59 * time.Minute}, want: "Less than 1 hour"},
		{name: "one second", remaining: TimeRemaining{Total: time.Second}, want: "Less than 1 hour"},
		{name: "exactly zero", remaining: TimeRemaining{}, want: "Expired"},
		{name: "years only", remaining: TimeRemaining{Years: 3, Total: 3 * 365 * 24 * time.Hour}, want: "3 years"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, formatTimeRemaining(tt.remaining))
		})
	}
}

// TestLicLogProviderRestriction asserts the severity of each provider decision:
// an unlicensed encryption provider must be reported as an error.
func TestLicLogProviderRestriction(t *testing.T) {
	tests := []struct {
		name         string
		providerType string
		alias        string
		licensed     bool
		wantLevel    logrus.Level
		wantMessage  string
	}{
		{
			name:         "licensed encryption provider",
			providerType: "aes",
			alias:        "current-provider",
			licensed:     true,
			wantLevel:    logrus.InfoLevel,
			wantMessage:  "Encryption provider 'current-provider' (type: aes) - ✅ Licensed",
		},
		{
			name:         "unlicensed pass-through provider",
			providerType: "none",
			alias:        "default",
			licensed:     false,
			wantLevel:    logrus.InfoLevel,
			wantMessage:  "Pass-through provider 'default' (type: none) - ✅ Available without license",
		},
		{
			name:         "unlicensed encryption provider",
			providerType: "rsa",
			alias:        "rsa-envelope",
			licensed:     false,
			wantLevel:    logrus.ErrorLevel,
			wantMessage:  "Encryption provider 'rsa-envelope' (type: rsa) - ❌ License required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hook := LiccaptureLogs(t)
			LogProviderRestriction(tt.providerType, tt.alias, tt.licensed)

			entries := hook.AllEntries()
			require.Len(t, entries, 1)
			assert.Equal(t, tt.wantLevel, entries[0].Level)
			assert.Equal(t, tt.wantMessage, entries[0].Message)
		})
	}
}
