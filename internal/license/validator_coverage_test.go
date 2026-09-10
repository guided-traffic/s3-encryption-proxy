package license

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// LicsigningKeyOnce guards the lazily generated foreign signing key.
var LicsigningKeyOnce sync.Once

// LicsigningKey is an RSA key that is deliberately NOT the embedded license
// key, so every token signed with it must be rejected by the validator.
var LicsigningKey *rsa.PrivateKey

// LicsigningKeyErr carries a key generation failure to the calling test.
var LicsigningKeyErr error

// LicforeignKey returns a process-wide RSA key that the validator does not trust.
func LicforeignKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	LicsigningKeyOnce.Do(func() {
		LicsigningKey, LicsigningKeyErr = rsa.GenerateKey(rand.Reader, 2048)
	})
	require.NoError(t, LicsigningKeyErr)
	return LicsigningKey
}

// LicclaimsFor builds license claims that expire after the given offset.
func LicclaimsFor(offset time.Duration) *LicenseClaims {
	return &LicenseClaims{
		LicenseeName:        "Unit Test",
		LicenseeCompany:     "Unit Test GmbH",
		LicenseNote:         "generated in-test",
		KubernetesClusterID: "cluster-unit-test",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "s3ep.com",
			Subject:   "s3-encryption-proxy",
			IssuedAt:  jwt.NewNumericDate(time.Now().Add(-time.Hour)),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(offset)),
		},
	}
}

// LicsignWith signs claims with the untrusted test key using the given method.
func LicsignWith(t *testing.T, method jwt.SigningMethod, claims jwt.Claims, key interface{}) string {
	t.Helper()
	signed, err := jwt.NewWithClaims(method, claims).SignedString(key)
	require.NoError(t, err)
	return signed
}

// LiccaptureLogs installs a capturing hook on the standard logger and restores
// the previous logger state when the test finishes.
func LiccaptureLogs(t *testing.T) *test.Hook {
	t.Helper()
	std := logrus.StandardLogger()
	prevHooks := std.Hooks
	prevOut := std.Out
	prevLevel := std.Level

	std.Hooks = make(logrus.LevelHooks)
	std.SetOutput(io.Discard)
	std.SetLevel(logrus.DebugLevel)
	hook := test.NewGlobal()

	t.Cleanup(func() {
		std.Hooks = prevHooks
		std.SetOutput(prevOut)
		std.SetLevel(prevLevel)
	})
	return hook
}

// Liclogged reports whether any captured log entry contains the substring.
func Liclogged(hook *test.Hook, substr string) bool {
	for _, entry := range hook.AllEntries() {
		if strings.Contains(entry.Message, substr) {
			return true
		}
	}
	return false
}

// LicclearLicenseEnv neutralises every environment variable the loader reads.
func LicclearLicenseEnv(t *testing.T) {
	t.Helper()
	for _, name := range []string{"S3EP_LICENSE", "S3EP_LICENSE_TOKEN", "S3_ENCRYPTION_PROXY_LICENSE"} {
		t.Setenv(name, "")
	}
}

// LictamperPayload rewrites one claim of a signed token and keeps the original
// signature, which is exactly what an attacker with a stolen license would do.
func LictamperPayload(t *testing.T, signed, field string, value interface{}) string {
	t.Helper()
	parts := strings.Split(signed, ".")
	require.Len(t, parts, 3)

	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)

	var payload map[string]interface{}
	require.NoError(t, json.Unmarshal(raw, &payload))
	payload[field] = value

	rewritten, err := json.Marshal(payload)
	require.NoError(t, err)

	parts[1] = base64.RawURLEncoding.EncodeToString(rewritten)
	return strings.Join(parts, ".")
}

// TestLicValidateLicenseRejectsUntrustedTokens covers every rejection path of
// ValidateLicense and asserts that a rejected license leaves the validator in
// the unlicensed state (encryption providers stay blocked).
func TestLicValidateLicenseRejectsUntrustedTokens(t *testing.T) {
	foreign := LicforeignKey(t)
	valid := LicsignWith(t, jwt.SigningMethodRS256, LicclaimsFor(365*24*time.Hour), foreign)

	tests := []struct {
		name        string
		build       func(t *testing.T) string
		wantMessage string
		wantErrText string
		wantJWTErr  error
	}{
		{
			name:        "empty token",
			build:       func(*testing.T) string { return "" },
			wantMessage: "No license token provided",
		},
		{
			name:        "not a jwt",
			build:       func(*testing.T) string { return "definitely-not-a-jwt" },
			wantMessage: "License validation failed - invalid token",
			wantJWTErr:  jwt.ErrTokenMalformed,
		},
		{
			name:        "foreign RS256 signature",
			build:       func(*testing.T) string { return valid },
			wantMessage: "License validation failed - invalid token",
			wantJWTErr:  jwt.ErrTokenSignatureInvalid,
		},
		{
			name: "expired token with foreign signature",
			build: func(t *testing.T) string {
				return LicsignWith(t, jwt.SigningMethodRS256, LicclaimsFor(-24*time.Hour), foreign)
			},
			wantMessage: "License validation failed - invalid token",
			wantJWTErr:  jwt.ErrTokenSignatureInvalid,
		},
		{
			name: "HS256 confusion attack",
			build: func(t *testing.T) string {
				return LicsignWith(t, jwt.SigningMethodHS256, LicclaimsFor(time.Hour), []byte("unit-test-material"))
			},
			wantMessage: "License validation failed - invalid token",
			wantErrText: "unexpected signing method: HS256",
			wantJWTErr:  jwt.ErrTokenUnverifiable,
		},
		{
			name: "alg none downgrade",
			build: func(t *testing.T) string {
				return LicsignWith(t, jwt.SigningMethodNone, LicclaimsFor(time.Hour), jwt.UnsafeAllowNoneSignatureType)
			},
			wantMessage: "License validation failed - invalid token",
			wantErrText: "unexpected signing method: none",
			wantJWTErr:  jwt.ErrTokenUnverifiable,
		},
		{
			name: "PS256 is not accepted either",
			build: func(t *testing.T) string {
				return LicsignWith(t, jwt.SigningMethodPS256, LicclaimsFor(time.Hour), foreign)
			},
			wantMessage: "License validation failed - invalid token",
			wantErrText: "unexpected signing method: PS256",
			wantJWTErr:  jwt.ErrTokenUnverifiable,
		},
		{
			name: "tampered expiry keeps original signature",
			build: func(t *testing.T) string {
				return LictamperPayload(t, valid, "exp", time.Now().Add(100*365*24*time.Hour).Unix())
			},
			wantMessage: "License validation failed - invalid token",
			wantJWTErr:  jwt.ErrTokenSignatureInvalid,
		},
		{
			name: "tampered licensee keeps original signature",
			build: func(t *testing.T) string {
				return LictamperPayload(t, valid, "licensee_name", "Somebody Else")
			},
			wantMessage: "License validation failed - invalid token",
			wantJWTErr:  jwt.ErrTokenSignatureInvalid,
		},
		{
			name: "truncated signature segment",
			build: func(*testing.T) string {
				parts := strings.Split(valid, ".")
				return parts[0] + "." + parts[1]
			},
			wantMessage: "License validation failed - invalid token",
			wantJWTErr:  jwt.ErrTokenMalformed,
		},
		{
			name: "unparsable claims segment",
			build: func(*testing.T) string {
				parts := strings.Split(valid, ".")
				return parts[0] + ".!!!not-base64!!!." + parts[2]
			},
			wantMessage: "License validation failed - invalid token",
			wantJWTErr:  jwt.ErrTokenMalformed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			validator := NewValidator()
			result := validator.ValidateLicense(tt.build(t))

			require.NotNil(t, result)
			assert.False(t, result.Valid, "untrusted token must never validate")
			assert.Nil(t, result.Info)
			assert.Contains(t, result.Message, tt.wantMessage)

			if tt.wantJWTErr == nil {
				assert.NoError(t, result.Error)
			} else {
				require.Error(t, result.Error)
				assert.True(t, errors.Is(result.Error, tt.wantJWTErr),
					"expected %v, got %v", tt.wantJWTErr, result.Error)
			}
			if tt.wantErrText != "" {
				require.Error(t, result.Error)
				assert.Contains(t, result.Error.Error(), tt.wantErrText)
			}

			// A rejected license must leave the proxy unlicensed.
			assert.Nil(t, validator.info)
			assert.Error(t, validator.ValidateProviderType("aes"))
			assert.NoError(t, validator.ValidateProviderType("exit"))
		})
	}
}

// TestLicValidateLicenseWhitespaceTokenIsRejected makes sure a file containing
// only blanks is not mistaken for a token.
func TestLicValidateLicenseWhitespaceTokenIsRejected(t *testing.T) {
	validator := NewValidator()
	result := validator.ValidateLicense("   ")

	assert.False(t, result.Valid)
	require.Error(t, result.Error)
	assert.True(t, errors.Is(result.Error, jwt.ErrTokenMalformed))
}

// TestLicValidateProviderTypeMessage checks the operator-facing guidance.
func TestLicValidateProviderTypeMessage(t *testing.T) {
	validator := NewValidator()

	// "none" is in the list on purpose: it is the old name of the exit provider
	// and carries none of its privileges.
	for _, providerType := range []string{"aes", "rsa", "tink", "none", ""} {
		err := validator.ValidateProviderType(providerType)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "license required for encryption provider type '"+providerType+"'")
		assert.Contains(t, err.Error(), "https://s3ep.com")
		assert.Contains(t, err.Error(), "type 'exit'", "the message must name the provider that needs no license")
	}

	// An invalidated license behaves exactly like a missing one.
	validator.info = &LicenseInfo{Valid: false}
	assert.Error(t, validator.ValidateProviderType("aes"))
	assert.NoError(t, validator.ValidateProviderType("exit"))
}

// TestLicParseEmbeddedPublicKey pins the shape of the embedded trust anchor.
func TestLicParseEmbeddedPublicKey(t *testing.T) {
	key, err := parseEmbeddedPublicKey()
	require.NoError(t, err)
	require.NotNil(t, key)

	assert.Equal(t, 4096, key.N.BitLen(), "embedded license key must stay 4096 bit")
	assert.Equal(t, 65537, key.E)

	// The freshly generated test key must differ from the trust anchor,
	// otherwise the rejection tests would prove nothing.
	assert.NotEqual(t, 0, key.N.Cmp(LicforeignKey(t).N))
}

// TestLicCalculateTimeRemainingBoundaries covers the zero value and the
// year/day rollover arithmetic.
func TestLicCalculateTimeRemainingBoundaries(t *testing.T) {
	now := time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)

	tests := []struct {
		name      string
		expires   time.Time
		wantYears int
		wantDays  int
		wantTotal time.Duration
	}{
		{name: "zero expiry", expires: time.Time{}},
		{name: "exactly now", expires: now},
		{name: "one second left", expires: now.Add(time.Second), wantTotal: time.Second},
		{name: "just under a day", expires: now.Add(23 * time.Hour), wantTotal: 23 * time.Hour},
		{name: "364 days", expires: now.Add(364 * 24 * time.Hour), wantDays: 364, wantTotal: 364 * 24 * time.Hour},
		{name: "365 days rolls over", expires: now.Add(365 * 24 * time.Hour), wantYears: 1, wantTotal: 365 * 24 * time.Hour},
		{name: "366 days", expires: now.Add(366 * 24 * time.Hour), wantYears: 1, wantDays: 1, wantTotal: 366 * 24 * time.Hour},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := calculateTimeRemaining(now, tt.expires)
			assert.Equal(t, tt.wantYears, got.Years)
			assert.Equal(t, tt.wantDays, got.Days)
			assert.Equal(t, tt.wantTotal, got.Total)
		})
	}
}

// TestLicStartRuntimeMonitoringWithoutLicense verifies no goroutine is started
// when there is nothing to monitor.
func TestLicStartRuntimeMonitoringWithoutLicense(t *testing.T) {
	hook := LiccaptureLogs(t)

	validator := NewValidator()
	validator.StartRuntimeMonitoring()
	assert.True(t, Liclogged(hook, "No valid license - skipping runtime monitoring"))

	validator.info = &LicenseInfo{Valid: false, ExpiresAt: time.Now().Add(time.Hour)}
	validator.StartRuntimeMonitoring()
	assert.False(t, Liclogged(hook, "Starting license runtime monitoring"))

	select {
	case <-validator.doneChan:
		t.Fatal("monitoring goroutine must not run without a valid license")
	default:
	}
}

// TestLicStartRuntimeMonitoringStops verifies the monitoring goroutine starts
// for a valid license and shuts down through Stop().
func TestLicStartRuntimeMonitoringStops(t *testing.T) {
	hook := LiccaptureLogs(t)

	validator := NewValidator()
	validator.info = &LicenseInfo{
		Valid:     true,
		Claims:    &LicenseClaims{LicenseeName: "Unit Test"},
		ExpiresAt: time.Now().Add(400 * 24 * time.Hour),
	}
	validator.StartRuntimeMonitoring()
	assert.True(t, Liclogged(hook, "Starting license runtime monitoring"))

	select {
	case <-validator.doneChan:
		t.Fatal("monitoring goroutine exited before Stop was called")
	default:
	}

	stopped := make(chan struct{})
	go func() {
		validator.Stop()
		close(stopped)
	}()

	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("Stop did not return")
	}

	select {
	case <-validator.doneChan:
	default:
		t.Fatal("Stop returned before the monitoring goroutine finished")
	}
	assert.True(t, Liclogged(hook, "License monitoring stopped"))
}

// TestLicGracefulShutdownExitsWithRestartCode verifies the fail-closed reaction
// to a license that expires while the proxy runs: the process must terminate
// with exit code 1 so the container restarts and re-runs the license check.
// gracefulShutdown ends in os.Exit, so it can only be exercised in a child
// process; its statements therefore never show up in the coverage profile.
func TestLicGracefulShutdownExitsWithRestartCode(t *testing.T) {
	if os.Getenv("LIC_GRACEFUL_SHUTDOWN_CHILD") == "1" {
		NewValidator().gracefulShutdown()
		t.Fatal("gracefulShutdown returned instead of terminating the process")
		return
	}

	// #nosec G702 G204 -- re-executes this very test binary, argv is a constant
	cmd := exec.Command(os.Args[0], "-test.run=^TestLicGracefulShutdownExitsWithRestartCode$")
	cmd.Env = append(os.Environ(), "LIC_GRACEFUL_SHUTDOWN_CHILD=1")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err := cmd.Run()

	var exitErr *exec.ExitError
	require.ErrorAs(t, err, &exitErr, "gracefulShutdown must terminate the process")
	assert.Equal(t, 1, exitErr.ExitCode(), "exit code 1 triggers the container restart")
	assert.Contains(t, stderr.String(), "Shutting down to prevent unlicensed encryption operations")
}

// TestLicLoadLicenseFromEnvPrecedence asserts the documented lookup order and
// that surrounding whitespace is stripped.
func TestLicLoadLicenseFromEnvPrecedence(t *testing.T) {
	LicclearLicenseEnv(t)
	assert.Empty(t, LoadLicenseFromEnv())

	t.Setenv("S3_ENCRYPTION_PROXY_LICENSE", "legacy-value")
	assert.Equal(t, "legacy-value", LoadLicenseFromEnv())

	t.Setenv("S3EP_LICENSE_TOKEN", "  token-value\n")
	assert.Equal(t, "token-value", LoadLicenseFromEnv(), "whitespace must be trimmed")

	t.Setenv("S3EP_LICENSE", "primary-value")
	assert.Equal(t, "primary-value", LoadLicenseFromEnv(), "S3EP_LICENSE has the highest precedence")
}

// TestLicLoadLicenseFromFile covers configured paths, fallback paths and the
// cases where nothing usable is found.
func TestLicLoadLicenseFromFile(t *testing.T) {
	tests := []struct {
		name       string
		configured string
		setup      func(t *testing.T, dir string) string
		want       string
	}{
		{
			name: "absolute configured path",
			setup: func(t *testing.T, dir string) string {
				path := filepath.Join(dir, "custom-license.jwt")
				require.NoError(t, os.WriteFile(path, []byte(" header.payload.signature \n"), 0o600))
				return path
			},
			want: "header.payload.signature",
		},
		{
			name:       "relative configured path resolved against cwd",
			configured: "relative-license.jwt",
			setup: func(t *testing.T, dir string) string {
				require.NoError(t, os.WriteFile(filepath.Join(dir, "relative-license.jwt"), []byte("relative-token"), 0o600))
				return ""
			},
			want: "relative-token",
		},
		{
			name: "fallback license.jwt in working directory",
			setup: func(t *testing.T, dir string) string {
				require.NoError(t, os.WriteFile(filepath.Join(dir, "license.jwt"), []byte("cwd-token"), 0o600))
				return ""
			},
			want: "cwd-token",
		},
		{
			name: "fallback config directory",
			setup: func(t *testing.T, dir string) string {
				require.NoError(t, os.MkdirAll(filepath.Join(dir, "config"), 0o750))
				require.NoError(t, os.WriteFile(filepath.Join(dir, "config", "license.jwt"), []byte("config-token"), 0o600))
				return ""
			},
			want: "config-token",
		},
		{
			name:       "configured path missing falls back",
			configured: "does-not-exist.jwt",
			setup: func(t *testing.T, dir string) string {
				require.NoError(t, os.WriteFile(filepath.Join(dir, "build", "license.jwt"), []byte("build-token"), 0o600))
				return ""
			},
			want: "build-token",
		},
		{
			name:       "blank file is ignored",
			configured: "blank.jwt",
			setup: func(t *testing.T, dir string) string {
				require.NoError(t, os.WriteFile(filepath.Join(dir, "blank.jwt"), []byte("   \n\t"), 0o600))
				return ""
			},
			want: "",
		},
		{
			name:  "nothing found",
			setup: func(_ *testing.T, _ string) string { return "" },
			want:  "",
		},
		{
			name:       "directory instead of file",
			configured: "license.jwt",
			setup: func(t *testing.T, dir string) string {
				require.NoError(t, os.MkdirAll(filepath.Join(dir, "license.jwt"), 0o750))
				return ""
			},
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			require.NoError(t, os.MkdirAll(filepath.Join(dir, "build"), 0o750))
			t.Chdir(dir)

			configured := tt.configured
			if produced := tt.setup(t, dir); produced != "" {
				configured = produced
			}

			assert.Equal(t, tt.want, LoadLicenseFromFile(configured))
		})
	}
}

// TestLicLoadLicensePrefersEnvironment verifies the source precedence of the
// combined loader.
func TestLicLoadLicensePrefersEnvironment(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	LicclearLicenseEnv(t)

	// Nothing configured at all.
	assert.Empty(t, LoadLicense(""))

	// File only.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "file-license.jwt"), []byte("file-token"), 0o600))
	assert.Equal(t, "file-token", LoadLicense("file-license.jwt"))

	// Environment wins over the configured file.
	t.Setenv("S3EP_LICENSE", "env-token")
	assert.Equal(t, "env-token", LoadLicense("file-license.jwt"))
}

// D-25 / A-1: without a valid license StartRuntimeMonitoring returns before it
// launches the goroutine whose deferred close is the only thing that ever
// closes doneChan. Stop used to wait on that channel unconditionally and
// blocked forever, and main calls Stop on the shutdown path - so every
// unlicensed shutdown had to be killed. Under Kubernetes that is every rollout
// waiting out its grace period with in-flight multipart uploads left dangling.
func TestLicStopReturnsWhenMonitoringNeverStarted(t *testing.T) {
	t.Run("Stop before StartRuntimeMonitoring was ever called", func(t *testing.T) {
		LicrequireStopReturns(t, NewValidator())
	})

	t.Run("Stop after the unlicensed early return", func(t *testing.T) {
		validator := NewValidator()
		validator.StartRuntimeMonitoring()
		LicrequireStopReturns(t, validator)
	})

	t.Run("Stop after an invalid license", func(t *testing.T) {
		validator := NewValidator()
		validator.info = &LicenseInfo{Valid: false, ExpiresAt: time.Now().Add(time.Hour)}
		validator.StartRuntimeMonitoring()
		LicrequireStopReturns(t, validator)
	})
}

// close(stopChan) panics on a second call, and a shutdown path is exactly where
// a double call is plausible.
func TestLicStopIsIdempotent(t *testing.T) {
	t.Run("without monitoring", func(t *testing.T) {
		validator := NewValidator()
		LicrequireStopReturns(t, validator)
		assert.NotPanics(t, validator.Stop)
		assert.NotPanics(t, validator.Stop)
	})

	t.Run("with monitoring running", func(t *testing.T) {
		validator := NewValidator()
		validator.info = &LicenseInfo{
			Valid:     true,
			Claims:    &LicenseClaims{LicenseeName: "Unit Test"},
			ExpiresAt: time.Now().Add(400 * 24 * time.Hour),
		}
		validator.StartRuntimeMonitoring()

		LicrequireStopReturns(t, validator)
		assert.NotPanics(t, validator.Stop)
	})
}

// A second StartRuntimeMonitoring would launch a second goroutine, and the two
// deferred close(doneChan) calls panic with "close of closed channel" at
// shutdown.
func TestLicStartRuntimeMonitoringIsStartedOnlyOnce(t *testing.T) {
	hook := LiccaptureLogs(t)

	validator := NewValidator()
	validator.info = &LicenseInfo{
		Valid:     true,
		Claims:    &LicenseClaims{LicenseeName: "Unit Test"},
		ExpiresAt: time.Now().Add(400 * 24 * time.Hour),
	}

	validator.StartRuntimeMonitoring()
	validator.StartRuntimeMonitoring()
	assert.True(t, Liclogged(hook, "License runtime monitoring already running"))

	LicrequireStopReturns(t, validator)
	assert.NotPanics(t, validator.Stop, "a second goroutine would have closed doneChan twice")
}

// LicrequireStopReturns fails the test if Stop blocks instead of returning.
func LicrequireStopReturns(t *testing.T, validator *LicenseValidator) {
	t.Helper()

	stopped := make(chan struct{})
	go func() {
		validator.Stop()
		close(stopped)
	}()

	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("Stop did not return")
	}
}

// D-25 / A-2: validation only checked expiry when the claim was present, so a
// token without exp was accepted, ExpiresAt kept the zero time - year 1 - and
// the hourly runtime check found now.After(year 1) true and called
// os.Exit(1). A perpetual license started the proxy cleanly and killed it 60
// minutes later, logging an expiry that did not exist.
func TestLicCheckClaimsRejectsATokenWithoutAnExpiryClaim(t *testing.T) {
	now := time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)

	t.Run("no exp claim is rejected, not treated as perpetual", func(t *testing.T) {
		rejection := checkClaims(now, &LicenseClaims{LicenseeName: "Perpetual"})

		require.NotNil(t, rejection)
		assert.False(t, rejection.Valid)
		assert.Nil(t, rejection.Info)
		require.Error(t, rejection.Error)
		assert.Contains(t, rejection.Error.Error(), "exp",
			"the error must name the claim that is missing")
		assert.Contains(t, rejection.Message, "no expiry date")
	})

	t.Run("an expired token is rejected", func(t *testing.T) {
		claims := &LicenseClaims{}
		claims.ExpiresAt = jwt.NewNumericDate(now.Add(-time.Second))

		rejection := checkClaims(now, claims)

		require.NotNil(t, rejection)
		assert.False(t, rejection.Valid)
		assert.Equal(t, "License has expired", rejection.Message)
		assert.Contains(t, rejection.Error.Error(), "2026-09-07")
	})

	t.Run("a token expiring in the future is accepted", func(t *testing.T) {
		claims := &LicenseClaims{}
		claims.ExpiresAt = jwt.NewNumericDate(now.Add(365 * 24 * time.Hour))

		assert.Nil(t, checkClaims(now, claims))
	})

	t.Run("the expiry boundary is inclusive", func(t *testing.T) {
		claims := &LicenseClaims{}
		claims.ExpiresAt = jwt.NewNumericDate(now)

		assert.Nil(t, checkClaims(now, claims),
			"a licence is valid up to and including its expiry instant")
	})
}
