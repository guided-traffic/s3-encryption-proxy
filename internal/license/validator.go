package license

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/sirupsen/logrus"
)

// Embedded public key for license validation
// This key is hardcoded and cannot be changed from outside
// Generated for s3ep.com license validation
// embeddedRSAPublicKey contains the RSA public key for JWT validation
// This is a 4096-bit RSA public key generated specifically for license validation
const embeddedRSAPublicKey = `-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAqaeOmsouqwfuvuuMYRev
n5uxBt0rRS0v24YW84Eg0JwfqrBwH/Yp7xHiNuBfQnGA7uR2pdipRyYvNtd+S+iI
XOUsYkEA2yaPzArYl5sTP/Zijv8gxH1PuC/AY19eGV9rob78IlZ8hlyBduPqr++3
n2/8b+rz6sJE2DT7ENkFWDRHtO2VK+FDLmlTEYXwqve1tlQUJN7wXfiJo+Wwsq8C
0uhpwS5AZ1jjPh7NpU5MwkhlgNkXlz36I3L/sCk/l7qoQOOrPws9EArHvoU3OSY3
XOI+uMMS5pm2DscKoeRIDIRJkqdzUFnC82RO/K4a5HFf48WTqHUEqGOYbQAdJvgy
vH0V6todZI6f6uaBlW93wGRcDjx4gIoSX/m9zGAtdqrCy6wLt7GvzXomkSD8fGEQ
kJPiqhc8Zvs7tbqgXCWxlmUeRIXA4JZ83qpyseSVDP7poiD/GLfGjAvIH+2V+z6h
Te0Lupwqk26jxrg55I+bNsEJyzV8SX2Ym0cOUcDS9Q0A0vks6IndCpeGFtHqzRlf
WWD7yJefjkQnJWQ8nrT1VHuoWJEvsxutcshR3S+R34m5C40je1cFc28hWZgzjPAO
j4xKCmYlYap1jBDGerod9ADPT+82bruX3SALDAWDxnhaS9XrlKDNnkWTggaFQ0SJ
8PvELzQClmErvr1Zvfi0A0UCAwEAAQ==
-----END PUBLIC KEY-----`

// NewValidator creates a new license validator instance
func NewValidator() *LicenseValidator {
	return &LicenseValidator{
		stopChan: make(chan struct{}),
		doneChan: make(chan struct{}),
	}
}

// ValidateLicense validates a JWT license token
func (v *LicenseValidator) ValidateLicense(tokenString string) *ValidationResult {
	if tokenString == "" {
		return &ValidationResult{
			Valid:   false,
			Message: "No license token provided - running in read-only mode (encryption disabled)",
		}
	}

	// Parse the public key
	publicKey, err := parseEmbeddedPublicKey()
	if err != nil {
		return &ValidationResult{
			Valid:   false,
			Error:   fmt.Errorf("failed to parse embedded public key: %w", err),
			Message: "License validation failed - invalid public key",
		}
	}

	// Parse and validate the token
	token, err := jwt.ParseWithClaims(tokenString, &LicenseClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Ensure the signing method is RS256
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return publicKey, nil
	})

	if err != nil {
		return &ValidationResult{
			Valid:   false,
			Error:   fmt.Errorf("failed to parse JWT token: %w", err),
			Message: "License validation failed - invalid token",
		}
	}

	// Extract claims
	claims, ok := token.Claims.(*LicenseClaims)
	if !ok || !token.Valid {
		return &ValidationResult{
			Valid:   false,
			Error:   fmt.Errorf("invalid token claims"),
			Message: "License validation failed - invalid claims",
		}
	}

	// Check expiration
	now := time.Now()
	if claims.ExpiresAt != nil && now.After(claims.ExpiresAt.Time) {
		return &ValidationResult{
			Valid:   false,
			Error:   fmt.Errorf("license expired on %s", claims.ExpiresAt.Time.Format("2006-01-02 15:04:05 MST")),
			Message: "License has expired",
		}
	}

	// Calculate time remaining
	var expiresAt time.Time
	var timeRemaining TimeRemaining
	if claims.ExpiresAt != nil {
		expiresAt = claims.ExpiresAt.Time
		timeRemaining = calculateTimeRemaining(now, expiresAt)
	}

	// Create license info
	info := &LicenseInfo{
		Claims:        claims,
		Valid:         true,
		ExpiresAt:     expiresAt,
		TimeRemaining: timeRemaining,
	}

	v.info = info

	return &ValidationResult{
		Valid:   true,
		Info:    info,
		Message: "License validated successfully",
	}
}

// ValidateProviderType checks if the provider type is allowed without a license
func (v *LicenseValidator) ValidateProviderType(providerType string) error {
	if v.info == nil || !v.info.Valid {
		if providerType != "none" {
			return fmt.Errorf(
				"license required for encryption provider type '%s'\n"+
					"Please obtain a license from https://s3ep.com\n"+
					"Or start with a provider of type 'none' for read-only mode",
				providerType,
			)
		}
	}
	return nil
}

// StartRuntimeMonitoring starts background monitoring of license validity
func (v *LicenseValidator) StartRuntimeMonitoring() {
	if v.info == nil || !v.info.Valid {
		logrus.Debug("No valid license - skipping runtime monitoring")
		return
	}

	logrus.Info("Starting license runtime monitoring (checks every 60 minutes)")

	ticker := time.NewTicker(60 * time.Minute)

	go func() {
		defer close(v.doneChan)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				now := time.Now()
				if now.After(v.info.ExpiresAt) {
					logrus.Error("License expired during runtime - initiating graceful shutdown")
					v.gracefulShutdown()
					return
				} else {
					// Update remaining time and log if approaching expiration
					remaining := calculateTimeRemaining(now, v.info.ExpiresAt)
					if remaining.Total < 30*24*time.Hour { // 30 days
						logrus.Warnf("License expires in %d days - please renew soon", remaining.Days)
					}
				}
			case <-v.stopChan:
				logrus.Debug("License monitoring stopped")
				return
			}
		}
	}()
}

// Stop gracefully stops the license validator
func (v *LicenseValidator) Stop() {
	close(v.stopChan)
	<-v.doneChan
}

// GetLicenseInfo returns the current license information
func (v *LicenseValidator) GetLicenseInfo() *LicenseInfo {
	return v.info
}

// gracefulShutdown initiates a graceful shutdown when license expires
func (v *LicenseValidator) gracefulShutdown() {
	logrus.Error("License has expired during runtime")
	logrus.Error("Shutting down to prevent unlicensed encryption operations")
	logrus.Info("Container will restart and perform normal license check")

	// Give some time for logging to complete
	time.Sleep(1 * time.Second)

	// Exit with code 1 to trigger container restart
	os.Exit(1)
}

// parseEmbeddedPublicKey parses the embedded RSA public key
func parseEmbeddedPublicKey() (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(embeddedRSAPublicKey))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is not RSA key")
	}

	return rsaPub, nil
}

// calculateTimeRemaining calculates years and days remaining until expiration
func calculateTimeRemaining(now, expires time.Time) TimeRemaining {
	if expires.IsZero() {
		return TimeRemaining{}
	}

	duration := expires.Sub(now)
	if duration <= 0 {
		return TimeRemaining{}
	}

	days := int(duration.Hours() / 24)
	years := days / 365
	remainingDays := days % 365

	return TimeRemaining{
		Years: years,
		Days:  remainingDays,
		Total: duration,
	}
}

// LoadLicenseFromEnv loads license token from environment variable
func LoadLicenseFromEnv() string {
	// Try multiple environment variable names
	envVars := []string{
		"S3EP_LICENSE",
		"S3EP_LICENSE_TOKEN",
		"S3_ENCRYPTION_PROXY_LICENSE",
	}

	for _, envVar := range envVars {
		if token := os.Getenv(envVar); token != "" {
			logrus.Debugf("License loaded from environment variable: %s", envVar)
			return strings.TrimSpace(token)
		}
	}

	return ""
}

// LoadLicenseFromFile loads license token from various file locations
func LoadLicenseFromFile(configuredPath string) string {
	// Try multiple file locations in order of preference
	possiblePaths := []string{}

	// If a specific path is configured, try it first
	if configuredPath != "" {
		possiblePaths = append(possiblePaths, configuredPath)
	}

	// Fallback paths
	fallbackPaths := []string{
		"license.jwt",           // Current directory
		"build/license.jwt",     // Build directory
		"/etc/s3ep/license.jwt", // System directory
		"/opt/s3ep/license.jwt", // Alternative system directory
		"/app/license.jwt",      // Docker container path
		"./config/license.jwt",  // Config directory
	}

	// Add fallback paths only if they're not already in the list
	for _, fallbackPath := range fallbackPaths {
		if fallbackPath != configuredPath {
			possiblePaths = append(possiblePaths, fallbackPath)
		}
	}

	// Get current working directory to make relative paths absolute
	cwd, _ := os.Getwd()

	for _, path := range possiblePaths {
		var fullPath string
		if filepath.IsAbs(path) {
			fullPath = path
		} else {
			fullPath = filepath.Join(cwd, path)
		}

		// #nosec G304 - License file paths are controlled and validated
		if data, err := os.ReadFile(fullPath); err == nil {
			token := strings.TrimSpace(string(data))
			if token != "" {
				logrus.Debugf("License loaded from file: %s", fullPath)
				return token
			}
		}
	}

	return ""
}

// LoadLicense attempts to load license from multiple sources in order of preference
func LoadLicense(configuredPath string) string {
	// 1. First try environment variables
	if token := LoadLicenseFromEnv(); token != "" {
		return token
	}

	// 2. Then try file locations (including configured path)
	if token := LoadLicenseFromFile(configuredPath); token != "" {
		return token
	}

	logrus.Debug("No license found in environment variables or files")
	return ""
}
