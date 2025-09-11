package license

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/sirupsen/logrus"
)

// Embedded public key for license validation
// This key is hardcoded and cannot be changed from outside
// Generated for guided-traffic.com license validation
const embeddedPublicKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA8RiERDhTfvYhyW+LwrA3
DmhWhDgW8yJzVfyABFm+qu5HkEbyyO7NDEj4wzoH7nzvClfG5s1kIu0p/E2dJNOT
GVAKW9T5AgWIeOZSYT5ioI/H2V1PDTKdWYDniOk1UMFsPopIXXacOF+ikjZ5ErCr
NCtcZJXGVOBkoXpPQk4Nle20XpQi/UYVpC9XBz4i71LSqe0+gqp8YOvV8mbYDhsy
I/Rq5pa6H9xBk6HEbaJ9bAm+4F3XCmuW4YBvnvcj/zG3djxHGc7BqM7HQdrt5+tS
PLngU1KwSYQ7mzhnBBimbPRTkh5ZlBZC4t1h+Q9tizeoS2Gy4gnen0uo0lXSn9nj
HQIDAQAB
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
					"Please obtain a license from https://guided-traffic.com\n"+
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
	block, _ := pem.Decode([]byte(embeddedPublicKey))
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
	return os.Getenv("S3EP_LICENSE_TOKEN")
}
