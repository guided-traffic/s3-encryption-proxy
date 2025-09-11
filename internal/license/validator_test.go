package license

import (
	"os"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewValidator(t *testing.T) {
	validator := NewValidator()
	assert.NotNil(t, validator)
	assert.NotNil(t, validator.stopChan)
	assert.NotNil(t, validator.doneChan)
}

func TestValidateLicense_EmptyToken(t *testing.T) {
	validator := NewValidator()
	result := validator.ValidateLicense("")

	assert.False(t, result.Valid)
	assert.Contains(t, result.Message, "No license token provided")
	assert.Nil(t, result.Error)
}

func TestValidateLicense_InvalidToken(t *testing.T) {
	validator := NewValidator()
	result := validator.ValidateLicense("invalid.jwt.token")

	assert.False(t, result.Valid)
	assert.Contains(t, result.Message, "License validation failed")
	assert.NotNil(t, result.Error)
}

func TestValidateProviderType_NoLicense(t *testing.T) {
	validator := NewValidator()

	// None provider should be allowed
	err := validator.ValidateProviderType("none")
	assert.NoError(t, err)

	// AES provider should be rejected
	err = validator.ValidateProviderType("aes")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "license required")
	assert.Contains(t, err.Error(), "https://guided-traffic.com")
}

func TestValidateProviderType_WithLicense(t *testing.T) {
	validator := NewValidator()

	// Simulate valid license
	validator.info = &LicenseInfo{
		Valid: true,
		Claims: &LicenseClaims{
			LicenseeName:    "Test User",
			LicenseeCompany: "Test Company",
		},
	}

	// Both none and encryption providers should be allowed
	err := validator.ValidateProviderType("none")
	assert.NoError(t, err)

	err = validator.ValidateProviderType("aes")
	assert.NoError(t, err)

	err = validator.ValidateProviderType("rsa")
	assert.NoError(t, err)
}

func TestCalculateTimeRemaining(t *testing.T) {
	now := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name     string
		expires  time.Time
		expected TimeRemaining
	}{
		{
			name:    "1 year 31 days",
			expires: now.AddDate(1, 1, 0), // 1 year 1 month = ~396 days
			expected: TimeRemaining{
				Years: 1,
				Days:  31, // 31 days in January (396 - 365)
			},
		},
		{
			name:    "100 days",
			expires: now.AddDate(0, 0, 100),
			expected: TimeRemaining{
				Years: 0,
				Days:  100,
			},
		},
		{
			name:    "Expired",
			expires: now.AddDate(0, 0, -1),
			expected: TimeRemaining{
				Years: 0,
				Days:  0,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := calculateTimeRemaining(now, tt.expires)
			assert.Equal(t, tt.expected.Years, result.Years)
			assert.Equal(t, tt.expected.Days, result.Days)
		})
	}
}

func TestFormatTimeRemaining(t *testing.T) {
	tests := []struct {
		name      string
		remaining TimeRemaining
		expected  string
	}{
		{
			name: "Years and days",
			remaining: TimeRemaining{
				Years: 2,
				Days:  30,
				Total: time.Hour * 24 * 760, // Just to have positive duration
			},
			expected: "2 years, 30 days",
		},
		{
			name: "One year one day",
			remaining: TimeRemaining{
				Years: 1,
				Days:  1,
				Total: time.Hour * 24 * 366,
			},
			expected: "1 year, 1 day",
		},
		{
			name: "Days only",
			remaining: TimeRemaining{
				Years: 0,
				Days:  15,
				Total: time.Hour * 24 * 15,
			},
			expected: "15 days",
		},
		{
			name: "Hours only",
			remaining: TimeRemaining{
				Years: 0,
				Days:  0,
				Total: time.Hour * 5,
			},
			expected: "5 hours",
		},
		{
			name: "Expired",
			remaining: TimeRemaining{
				Years: 0,
				Days:  0,
				Total: -time.Hour,
			},
			expected: "Expired",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatTimeRemaining(tt.remaining)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestLoadLicenseFromEnv(t *testing.T) {
	// Clean environment
	os.Unsetenv("S3EP_LICENSE_TOKEN")

	// Test empty
	token := LoadLicenseFromEnv()
	assert.Empty(t, token)

	// Test with value
	expectedToken := "test.jwt.token"
	os.Setenv("S3EP_LICENSE_TOKEN", expectedToken)
	defer os.Unsetenv("S3EP_LICENSE_TOKEN")

	token = LoadLicenseFromEnv()
	assert.Equal(t, expectedToken, token)
}

func TestParseEmbeddedPublicKey(t *testing.T) {
	key, err := parseEmbeddedPublicKey()
	require.NoError(t, err)
	assert.NotNil(t, key)

	// Verify it's an RSA key
	assert.NotNil(t, key.N)
	assert.NotZero(t, key.E)
}

// TestLicenseClaims verifies the JWT claims structure
func TestLicenseClaims(t *testing.T) {
	claims := &LicenseClaims{
		LicenseeName:        "John Doe",
		LicenseeCompany:     "Acme Corp",
		LicenseNote:         "Production License",
		KubernetesClusterID: "cluster-prod-01",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(365 * 24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "guided-traffic.com",
			Subject:   "s3-encryption-proxy",
		},
	}

	assert.Equal(t, "John Doe", claims.LicenseeName)
	assert.Equal(t, "Acme Corp", claims.LicenseeCompany)
	assert.Equal(t, "Production License", claims.LicenseNote)
	assert.Equal(t, "cluster-prod-01", claims.KubernetesClusterID)
	assert.NotNil(t, claims.ExpiresAt)
}
