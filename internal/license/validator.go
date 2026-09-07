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
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAv3pVuxTBUCrXBQCE26rJ
qNwoe0P0DR9co5X165lLn9SToJwzjspYOc3Ms+hB7aOXvgHOfsz5twIaDItNCow8
79q7CRMlEkVD94FpdV5XTaBzfWqmf05RcX+vYVC6ENNLwGaJKru4NgMy7L72xEHu
ewZG5tcvbUe4zlcfnklagJQxtvHhNq1bllv9CLoOShZSjLuseV2nwydIQ/8io38A
/oPtOAFeUUGHjQhNRCnsmg/1g0qef2O/yNs4PGM8OXVfAoHFtSu9S7PTRDBApB21
TII4z9rwI/Pu86+IFfraVm+sj9Qhw6RrbXADO909+qzQVXuEHb5MkzwvcinGKYU5
QR8cjYs/0cS08ZIr/rhmHokifM25IfuiXlW2M7nnb1fBx2m9uaB83HRo/MXNMB+8
KYgzuLHceJ4ThLXUJrCdNXhTfSXEn1AHmpyA+61DhH1UGWeerTrnQU4+53W6BSMT
F9TPSUR3hefxDhZWs9UV2qCAltFtwy3HOh//iWXZ3JCjPGUMqR6c9wGV3skosgLl
3inTOPYNntBCh5rG7uI1HNzXhp9xZDbP7WF+cRSiFS0gWnCLoW0cdPPpeXXB5y1b
kqRHiSyfHQNh3MjKVi5iOeXty40Gt8qn81vf6cHrQpfWfJnAhvIvLTlA92T8/zJM
8mWFN0VNajEzeVKrEUPcvK8CAwEAAQ==
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

	now := time.Now()
	if rejection := checkClaims(now, claims); rejection != nil {
		return rejection
	}

	expiresAt := claims.ExpiresAt.Time

	// Create license info
	info := &LicenseInfo{
		Claims:        claims,
		Valid:         true,
		ExpiresAt:     expiresAt,
		TimeRemaining: calculateTimeRemaining(now, expiresAt),
	}

	v.info = info

	return &ValidationResult{
		Valid:   true,
		Info:    info,
		Message: "License validated successfully",
	}
}

// checkClaims applies the policy a signed token still has to satisfy. It
// returns nil when the token is acceptable, and the rejection otherwise.
//
// It is separate from ValidateLicense so it can be tested: the trust anchor is
// the public key compiled in above and its private half is not in this
// repository, so no test can produce a token that survives signature
// verification. Keeping the policy here means the rules below are covered
// without a seam that would let anything redirect that anchor.
func checkClaims(now time.Time, claims *LicenseClaims) *ValidationResult {
	// A token without an exp claim used to be accepted, leaving ExpiresAt at
	// the zero time - year 1 - so the hourly runtime check found it expired and
	// terminated the proxy after 60 minutes, logging an expiry that did not
	// exist. A perpetual license is a business decision and has to be an
	// explicit claim, never the consequence of an omission.
	if claims.ExpiresAt == nil {
		return &ValidationResult{
			Valid:   false,
			Error:   fmt.Errorf("license token has no 'exp' claim"),
			Message: "License validation failed - the token carries no expiry date",
		}
	}

	// jwt.ParseWithClaims already rejects an expired token. This is the same
	// rule stated independently of the library, so a parser option that changes
	// cannot silently switch expiry checking off.
	if now.After(claims.ExpiresAt.Time) {
		return &ValidationResult{
			Valid:   false,
			Error:   fmt.Errorf("license expired on %s", claims.ExpiresAt.Time.Format("2006-01-02 15:04:05 MST")),
			Message: "License has expired",
		}
	}

	return nil
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

	// Only one monitoring goroutine may ever run: its deferred close(doneChan)
	// would panic on a second one, and Stop reads this flag to decide whether
	// there is anything to wait for.
	if !v.monitoring.CompareAndSwap(false, true) {
		logrus.Debug("License runtime monitoring already running")
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

// Stop gracefully stops the license validator.
//
// Without a valid license StartRuntimeMonitoring returns before it launches the
// goroutine whose deferred close is the only thing that ever closes doneChan,
// so waiting on it unconditionally blocked forever. main calls Stop on the
// shutdown path, which made every unlicensed shutdown hang until SIGKILL -
// under Kubernetes that is every rollout, scale-down and node drain waiting out
// terminationGracePeriodSeconds, with in-flight multipart uploads left dangling
// on the backend. Stop now waits only when there is a goroutine to wait for,
// and is safe to call more than once.
func (v *LicenseValidator) Stop() {
	v.stopOnce.Do(func() { close(v.stopChan) })

	if v.monitoring.Load() {
		<-v.doneChan
	}
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
