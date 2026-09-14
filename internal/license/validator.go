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
			Message: "No license token provided - only the exit provider will start",
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
		if providerType != "exit" {
			return fmt.Errorf(
				"license required for encryption provider type '%s'\n"+
					"Please obtain a license from https://s3ep.com\n"+
					"Or switch the active provider to type 'exit', which needs no license: it "+
					"writes plaintext and still decrypts what this proxy encrypted earlier",
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

// SetExpiryHandler supplies what a licence that lapses at runtime does instead
// of ending the process on the spot. Call it before StartRuntimeMonitoring.
//
// The unlicensed state is fail-closed either way; what the handler buys is the
// order. Exiting from the monitoring goroutine skips the whole shutdown tail:
// readiness never goes false, requests in flight are cut mid-byte, and every
// multipart upload this process holds is left at the backend with nothing able
// to finish it (ADR 0029 D2). The handler hands the decision to the shutdown
// path that already knows how to do all three.
func (v *LicenseValidator) SetExpiryHandler(fn func()) {
	v.onExpiry = fn
}

func (v *LicenseValidator) gracefulShutdown() {
	logrus.Error("License has expired during runtime")
	logrus.Error("Shutting down to prevent unlicensed encryption operations")
	logrus.Info("Container will restart and perform normal license check")

	if v.onExpiry != nil {
		v.onExpiry()
		return
	}

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

// LicenseEnvVar is the one environment variable that carries the license token.
//
// One name and no alias: ADR 0016 D6 names a single variable, and three of them
// meant an operator could not tell which one a running proxy had taken its token
// from, so they could not tell which one to rotate.
const LicenseEnvVar = "S3EP_LICENSE_TOKEN"

// LoadLicenseFromEnv loads the license token from LicenseEnvVar.
func LoadLicenseFromEnv() string {
	if token := os.Getenv(LicenseEnvVar); token != "" {
		logrus.Debugf("License loaded from environment variable: %s", LicenseEnvVar)
		return strings.TrimSpace(token)
	}

	return ""
}

// LoadLicenseFromFile loads the license token from license_file.
//
// license_file is the one file: there is no search list behind it. The license
// is a startup gate (ADR 0016), and a gate that silently reads a different file
// than the one it was given is not one - an image carrying a token of its own
// would start happily while the mounted secret was missing, with nothing saying
// so.
//
// binding says whether the operator wrote the key. A path they wrote must yield
// a token or the start is refused naming it; the default path is an offer rather
// than a promise, because a proxy whose active provider needs no license starts
// without one.
func LoadLicenseFromFile(configuredPath string, binding bool) (string, error) {
	token, err := readLicenseFile(configuredPath)
	if err != nil {
		if binding {
			return "", fmt.Errorf("license_file %q: %w", configuredPath, err)
		}
		return "", nil
	}
	return token, nil
}

// readLicenseFile reads one token file. An empty file is an error rather than an
// empty token: it carries no license, and under a binding path the difference
// decides whether the start is refused.
func readLicenseFile(path string) (string, error) {
	fullPath := path
	if !filepath.IsAbs(path) {
		cwd, err := os.Getwd()
		if err != nil {
			return "", err
		}
		fullPath = filepath.Join(cwd, path)
	}

	// #nosec G304 - the path comes from the configuration, not from a request
	data, err := os.ReadFile(fullPath)
	if err != nil {
		return "", err
	}
	token := strings.TrimSpace(string(data))
	if token == "" {
		return "", fmt.Errorf("the file is empty")
	}
	logrus.Debugf("License loaded from file: %s", fullPath)
	return token, nil
}

// LoadLicense attempts to load the license from LicenseEnvVar first and from
// license_file second. binding says whether the configuration wrote that key:
// see LoadLicenseFromFile.
func LoadLicense(configuredPath string, binding bool) (string, error) {
	// 1. First the environment
	if token := LoadLicenseFromEnv(); token != "" {
		return token, nil
	}

	// 2. Then license_file
	token, err := LoadLicenseFromFile(configuredPath, binding)
	if err != nil {
		return "", err
	}
	if token != "" {
		return token, nil
	}

	logrus.Debug("No license found in the environment or in license_file")
	return "", nil
}
