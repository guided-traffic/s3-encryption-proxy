package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// LicTkeyOnce caches one RSA key for the whole package: key generation is the
// only slow operation in these tests and the key material itself is irrelevant
// to what is asserted.
var LicTkeyOnce = sync.OnceValues(func() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
})

// LicTkey returns a real 2048 bit RSA private key.
func LicTkey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := LicTkeyOnce()
	require.NoError(t, err)
	return key
}

// LicTsecondKeyOnce is a second, independent key used to prove that a token
// does not verify under a foreign public key.
var LicTsecondKeyOnce = sync.OnceValues(func() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
})

// LicTwritePEM writes a PEM file into the test temp dir and returns its path.
func LicTwritePEM(t *testing.T, dir, name, blockType string, der []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	encoded := pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
	require.NotNil(t, encoded)
	require.NoError(t, os.WriteFile(path, encoded, 0o600))
	return path
}

// LicTwithStdin replaces os.Stdin with a pipe carrying input and restores the
// original when the test ends. collectLicenseInfo reads os.Stdin directly, so
// this process global is the only seam available; the pipe keeps the test
// hermetic (no files, no terminal).
func LicTwithStdin(t *testing.T, input string) {
	t.Helper()
	reader, writer, err := os.Pipe()
	require.NoError(t, err)

	original := os.Stdin
	os.Stdin = reader
	t.Cleanup(func() {
		os.Stdin = original
		_ = reader.Close()
	})

	// The prompts consume far less than the pipe buffer, so a blocking write is
	// safe; closing the writer turns the next read into io.EOF.
	_, err = writer.WriteString(input)
	require.NoError(t, err)
	require.NoError(t, writer.Close())
}

// LicTcaptureStdout redirects os.Stdout for the duration of the test. The
// returned function restores it and yields everything that was printed.
func LicTcaptureStdout(t *testing.T) func() string {
	t.Helper()
	reader, writer, err := os.Pipe()
	require.NoError(t, err)

	original := os.Stdout
	os.Stdout = writer

	var once sync.Once
	var captured string
	restore := func() string {
		once.Do(func() {
			os.Stdout = original
			require.NoError(t, writer.Close())
			data, readErr := io.ReadAll(reader)
			require.NoError(t, readErr)
			require.NoError(t, reader.Close())
			captured = string(data)
		})
		return captured
	}
	t.Cleanup(func() { restore() })
	return restore
}

// LicTvalidStdin is a complete, well formed answer set for collectLicenseInfo.
const LicTvalidStdin = "Alice Example\nExample GmbH\nProduction License - 500TB\ncluster-abc-123\n1y\n"

func TestLicTParseDuration(t *testing.T) {
	const day = 24 * time.Hour

	tests := []struct {
		name    string
		input   string
		want    time.Duration
		wantErr string
	}{
		{name: "single year", input: "1y", want: 365 * day},
		{name: "multiple years", input: "10y", want: 3650 * day},
		{name: "single day", input: "1d", want: day},
		{name: "days only", input: "365d", want: 365 * day},
		{name: "years and days", input: "2y100d", want: 830 * day},
		{name: "thirty days", input: "30d", want: 30 * day},
		{name: "leading zeros", input: "01y007d", want: 372 * day},
		{name: "empty input", input: "", wantErr: "duration must be greater than 0"},
		{name: "letters only", input: "abc", wantErr: "duration must be greater than 0"},
		{name: "number without unit", input: "100", wantErr: "duration must be greater than 0"},
		{name: "unit before number", input: "d5", wantErr: "duration must be greater than 0"},
		{name: "negative days", input: "-5d", wantErr: "duration must be greater than 0"},
		{name: "leading whitespace", input: " 1y", wantErr: "duration must be greater than 0"},
		{name: "zero years", input: "0y", wantErr: "duration must be greater than 0"},
		{name: "zero days", input: "0d", wantErr: "duration must be greater than 0"},
		{name: "zero years and days", input: "0y0d", wantErr: "duration must be greater than 0"},
		{name: "unsupported hour unit", input: "12h", wantErr: "duration must be greater than 0"},
		{name: "years overflow strconv", input: "99999999999999999999y", wantErr: "value out of range"},
		{name: "days overflow strconv", input: "99999999999999999999d", wantErr: "value out of range"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseDuration(tc.input)

			if tc.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErr)
				assert.Equal(t, time.Duration(0), got)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

// TestLicTParseDurationAcceptsTrailingGarbage pins a defect: the regexp is not
// anchored and every group is optional, so the parser silently takes the
// leading match and drops the rest of the input instead of rejecting it.
func TestLicTParseDurationAcceptsTrailingGarbage(t *testing.T) {
	const day = 24 * time.Hour

	tests := []struct {
		input string
		want  time.Duration
	}{
		{input: "1y2y", want: 365 * day},       // second year group ignored
		{input: "2y100dJUNK", want: 830 * day}, // trailing text ignored
		{input: "5d something", want: 5 * day}, // everything after the match ignored
		{input: "1y garbage", want: 365 * day}, // silent truncation of the input
		{input: "3d3y", want: 3 * day},         // wrong order: only the days are read
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			got, err := parseDuration(tc.input)
			require.NoError(t, err, "parser accepts malformed input instead of rejecting it")
			assert.Equal(t, tc.want, got)
		})
	}
}

// TestLicTParseDurationOverflowsSilently pins a second defect: there is no
// upper bound, so a large year count wraps time.Duration and yields a NEGATIVE
// validity, i.e. a license that is already expired the moment it is signed.
// When a bound check is added, this test must be changed to expect an error.
func TestLicTParseDurationOverflowsSilently(t *testing.T) {
	got, err := parseDuration("100000y")

	require.NoError(t, err, "no overflow guard exists today")
	assert.Negative(t, int64(got), "36500000 days overflow int64 nanoseconds and wrap negative")
}

func TestLicTLoadPrivateKey(t *testing.T) {
	key := LicTkey(t)
	dir := t.TempDir()

	pkcs8DER, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)

	_, ed25519Key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	ed25519DER, err := x509.MarshalPKCS8PrivateKey(ed25519Key)
	require.NoError(t, err)

	t.Run("pkcs1 key loads", func(t *testing.T) {
		path := LicTwritePEM(t, dir, "pkcs1.pem", "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(key))

		loaded, err := loadPrivateKey(path)

		require.NoError(t, err)
		require.NotNil(t, loaded)
		assert.True(t, loaded.Equal(key), "loaded key must be the key that was written")
		assert.Equal(t, 2048, loaded.N.BitLen())
	})

	t.Run("pkcs8 rsa key loads via fallback", func(t *testing.T) {
		path := LicTwritePEM(t, dir, "pkcs8.pem", "PRIVATE KEY", pkcs8DER)

		loaded, err := loadPrivateKey(path)

		require.NoError(t, err)
		require.NotNil(t, loaded)
		assert.True(t, loaded.Equal(key))
	})

	t.Run("pem block type is not validated", func(t *testing.T) {
		// The block header is ignored entirely: only the DER payload decides.
		path := LicTwritePEM(t, dir, "mislabelled.pem", "PUBLIC KEY", x509.MarshalPKCS1PrivateKey(key))

		loaded, err := loadPrivateKey(path)

		require.NoError(t, err)
		assert.True(t, loaded.Equal(key))
	})

	t.Run("pkcs8 non rsa key is rejected", func(t *testing.T) {
		path := LicTwritePEM(t, dir, "ed25519.pem", "PRIVATE KEY", ed25519DER)

		loaded, err := loadPrivateKey(path)

		require.Error(t, err)
		assert.Nil(t, loaded)
		assert.Equal(t, "key is not an RSA private key", err.Error())
	})

	t.Run("missing file", func(t *testing.T) {
		loaded, err := loadPrivateKey(filepath.Join(dir, "does-not-exist.pem"))

		require.Error(t, err)
		assert.Nil(t, loaded)
		assert.True(t, os.IsNotExist(err), "expected a not-exist error, got %v", err)
	})

	t.Run("not pem encoded", func(t *testing.T) {
		path := filepath.Join(dir, "garbage.pem")
		require.NoError(t, os.WriteFile(path, []byte("this is not a PEM file"), 0o600))

		loaded, err := loadPrivateKey(path)

		require.Error(t, err)
		assert.Nil(t, loaded)
		assert.Equal(t, "failed to decode PEM block", err.Error())
	})

	t.Run("empty file", func(t *testing.T) {
		path := filepath.Join(dir, "empty.pem")
		require.NoError(t, os.WriteFile(path, nil, 0o600))

		loaded, err := loadPrivateKey(path)

		require.Error(t, err)
		assert.Nil(t, loaded)
		assert.Equal(t, "failed to decode PEM block", err.Error())
	})

	t.Run("pem block with undecodable der", func(t *testing.T) {
		path := LicTwritePEM(t, dir, "broken-der.pem", "RSA PRIVATE KEY", []byte{0x00, 0x01, 0x02, 0x03})

		loaded, err := loadPrivateKey(path)

		require.Error(t, err)
		assert.Nil(t, loaded)
		assert.Contains(t, err.Error(), "failed to parse private key")
	})
}

// TestLicTFindRSAKeys drives findRSAKeys, which resolves both file names
// relative to os.Executable() and offers no seam to redirect that. The test
// therefore places its fixtures next to the running test binary (a go-build
// temp directory) and removes them again in every subtest.
func TestLicTFindRSAKeys(t *testing.T) {
	exe, err := os.Executable()
	require.NoError(t, err)
	exeDir := filepath.Dir(exe)

	place := func(t *testing.T, name string) string {
		t.Helper()
		path := filepath.Join(exeDir, name)
		if _, statErr := os.Stat(path); statErr == nil {
			t.Fatalf("refusing to clobber pre-existing %s", path)
		}
		require.NoError(t, os.WriteFile(path, []byte("test fixture\n"), 0o600))
		t.Cleanup(func() { _ = os.Remove(path) })
		return path
	}

	t.Run("no key files present", func(t *testing.T) {
		priv, pub, err := findRSAKeys()

		require.Error(t, err)
		assert.Empty(t, priv)
		assert.Empty(t, pub)
		assert.Contains(t, err.Error(), "private key not found")
		assert.Contains(t, err.Error(), filepath.Join(exeDir, "license_private_key.pem"))
	})

	t.Run("public key missing", func(t *testing.T) {
		place(t, "license_private_key.pem")

		priv, pub, err := findRSAKeys()

		require.Error(t, err)
		assert.Empty(t, priv)
		assert.Empty(t, pub)
		assert.Contains(t, err.Error(), "public key not found")
		assert.Contains(t, err.Error(), filepath.Join(exeDir, "license_public_key.pem"))
	})

	t.Run("both key files present", func(t *testing.T) {
		wantPriv := place(t, "license_private_key.pem")
		wantPub := place(t, "license_public_key.pem")

		priv, pub, err := findRSAKeys()

		require.NoError(t, err)
		assert.Equal(t, wantPriv, priv)
		assert.Equal(t, wantPub, pub)
	})
}

func TestLicTCollectLicenseInfo(t *testing.T) {
	t.Run("complete input builds claims", func(t *testing.T) {
		LicTwithStdin(t, LicTvalidStdin)
		stdout := LicTcaptureStdout(t)

		before := time.Now()
		claims, err := collectLicenseInfo()
		after := time.Now()
		printed := stdout()

		require.NoError(t, err)
		require.NotNil(t, claims)

		assert.Equal(t, "Alice Example", claims.LicenseeName)
		assert.Equal(t, "Example GmbH", claims.LicenseeCompany)
		assert.Equal(t, "Production License - 500TB", claims.LicenseNote)
		assert.Equal(t, "cluster-abc-123", claims.KubernetesClusterID)

		assert.Equal(t, "s3ep.com", claims.Issuer)
		assert.Equal(t, "s3-encryption-proxy-license", claims.Subject)
		assert.Equal(t, jwt.ClaimStrings{"s3-encryption-proxy"}, claims.Audience)

		_, parseErr := uuid.Parse(claims.ID)
		require.NoError(t, parseErr, "license ID must be a UUID, got %q", claims.ID)

		require.NotNil(t, claims.IssuedAt)
		require.NotNil(t, claims.NotBefore)
		require.NotNil(t, claims.ExpiresAt)
		assert.False(t, claims.IssuedAt.Before(before.Truncate(time.Second)))
		assert.False(t, claims.NotBefore.After(after))
		// "1y" is 365 days, measured from the issuing instant.
		assert.WithinDuration(t, claims.IssuedAt.Add(365*24*time.Hour), claims.ExpiresAt.Time, time.Second)

		for _, prompt := range []string{"Licensee Name:", "Company Name:", "License Note", "Kubernetes Cluster ID", "License Duration"} {
			assert.Contains(t, printed, prompt)
		}
	})

	t.Run("fields are trimmed and optional cluster id may be empty", func(t *testing.T) {
		LicTwithStdin(t, "  Bob  \r\n\tACME\t\n  note  \n\n365d\n")
		LicTcaptureStdout(t)

		claims, err := collectLicenseInfo()

		require.NoError(t, err)
		assert.Equal(t, "Bob", claims.LicenseeName)
		assert.Equal(t, "ACME", claims.LicenseeCompany)
		assert.Equal(t, "note", claims.LicenseNote)
		// No validation exists: an unbound license (empty cluster ID) is accepted.
		assert.Empty(t, claims.KubernetesClusterID)
		assert.WithinDuration(t, claims.IssuedAt.Add(365*24*time.Hour), claims.ExpiresAt.Time, time.Second)
	})

	t.Run("empty licensee identity is accepted", func(t *testing.T) {
		LicTwithStdin(t, "\n\n\n\n1d\n")
		LicTcaptureStdout(t)

		claims, err := collectLicenseInfo()

		require.NoError(t, err)
		assert.Empty(t, claims.LicenseeName)
		assert.Empty(t, claims.LicenseeCompany)
		assert.Empty(t, claims.LicenseNote)
	})

	t.Run("truncated input", func(t *testing.T) {
		tests := []struct {
			name  string
			stdin string
		}{
			{name: "eof on licensee name", stdin: "Alice"},
			{name: "eof on company", stdin: "Alice\nExample"},
			{name: "eof on note", stdin: "Alice\nExample\nnote"},
			{name: "eof on cluster id", stdin: "Alice\nExample\nnote\ncluster"},
			{name: "eof on duration", stdin: "Alice\nExample\nnote\ncluster\n1y"},
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				LicTwithStdin(t, tc.stdin)
				LicTcaptureStdout(t)

				claims, err := collectLicenseInfo()

				require.Error(t, err)
				assert.Nil(t, claims)
				assert.True(t, errors.Is(err, io.EOF), "expected io.EOF, got %v", err)
			})
		}
	})

	t.Run("invalid duration", func(t *testing.T) {
		LicTwithStdin(t, "Alice\nExample\nnote\ncluster\nnot-a-duration\n")
		LicTcaptureStdout(t)

		claims, err := collectLicenseInfo()

		require.Error(t, err)
		assert.Nil(t, claims)
		assert.Contains(t, err.Error(), "invalid duration format")
	})
}

func TestLicTGenerateJWT(t *testing.T) {
	key := LicTkey(t)

	claims := &LicenseClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "s3ep.com",
			Subject:   "s3-encryption-proxy-license",
			Audience:  []string{"s3-encryption-proxy"},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(365 * 24 * time.Hour)),
			NotBefore: jwt.NewNumericDate(time.Now()),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ID:        "11111111-2222-3333-4444-555555555555",
		},
		LicenseeName:        "Alice Example",
		LicenseeCompany:     "Example GmbH",
		LicenseNote:         "Production License - 500TB",
		KubernetesClusterID: "cluster-abc-123",
	}

	t.Run("token verifies and carries the claims", func(t *testing.T) {
		token, err := generateJWT(key, claims)

		require.NoError(t, err)
		require.NotEmpty(t, token)
		assert.Len(t, strings.Split(token, "."), 3, "expected a compact JWS serialization")

		parsed, err := jwt.ParseWithClaims(token, &LicenseClaims{}, func(*jwt.Token) (interface{}, error) {
			return &key.PublicKey, nil
		})
		require.NoError(t, err)
		require.True(t, parsed.Valid)
		assert.Equal(t, "RS256", parsed.Method.Alg())
		assert.Equal(t, "RS256", parsed.Header["alg"])

		got, ok := parsed.Claims.(*LicenseClaims)
		require.True(t, ok)
		assert.Equal(t, claims.LicenseeName, got.LicenseeName)
		assert.Equal(t, claims.LicenseeCompany, got.LicenseeCompany)
		assert.Equal(t, claims.LicenseNote, got.LicenseNote)
		assert.Equal(t, claims.KubernetesClusterID, got.KubernetesClusterID)
		assert.Equal(t, claims.Issuer, got.Issuer)
		assert.Equal(t, claims.Subject, got.Subject)
		assert.Equal(t, claims.ID, got.ID)
		assert.Equal(t, claims.ExpiresAt.Unix(), got.ExpiresAt.Unix())
	})

	t.Run("tampered payload fails verification", func(t *testing.T) {
		token, err := generateJWT(key, claims)
		require.NoError(t, err)

		parts := strings.Split(token, ".")
		require.Len(t, parts, 3)
		payload := []byte(parts[1])
		payload[len(payload)-1] ^= 0x01 // flip one base64 character of the payload
		tampered := parts[0] + "." + string(payload) + "." + parts[2]
		require.NotEqual(t, token, tampered)

		_, err = jwt.ParseWithClaims(tampered, &LicenseClaims{}, func(*jwt.Token) (interface{}, error) {
			return &key.PublicKey, nil
		})
		require.Error(t, err)
	})

	t.Run("foreign public key rejects the token", func(t *testing.T) {
		other, err := LicTsecondKeyOnce()
		require.NoError(t, err)

		token, err := generateJWT(key, claims)
		require.NoError(t, err)

		_, err = jwt.ParseWithClaims(token, &LicenseClaims{}, func(*jwt.Token) (interface{}, error) {
			return &other.PublicKey, nil
		})
		require.Error(t, err)
		assert.ErrorIs(t, err, jwt.ErrTokenSignatureInvalid)
	})

	t.Run("unusable signing key returns an error", func(t *testing.T) {
		token, err := generateJWT(&rsa.PrivateKey{}, claims)

		require.Error(t, err)
		assert.Empty(t, token)
	})
}

// TestLicTEndToEnd walks the path main() takes once the key is loaded: typed
// answers in, verifiable license token out.
func TestLicTEndToEnd(t *testing.T) {
	key := LicTkey(t)
	LicTwithStdin(t, LicTvalidStdin)
	LicTcaptureStdout(t)

	claims, err := collectLicenseInfo()
	require.NoError(t, err)

	token, err := generateJWT(key, claims)
	require.NoError(t, err)

	parsed, err := jwt.ParseWithClaims(token, &LicenseClaims{}, func(*jwt.Token) (interface{}, error) {
		return &key.PublicKey, nil
	})
	require.NoError(t, err)
	require.True(t, parsed.Valid)

	got, ok := parsed.Claims.(*LicenseClaims)
	require.True(t, ok)
	assert.Equal(t, "Alice Example", got.LicenseeName)
	assert.Equal(t, "cluster-abc-123", got.KubernetesClusterID)
	assert.Equal(t, claims.ID, got.ID)
	assert.True(t, got.ExpiresAt.After(time.Now().Add(364*24*time.Hour)))
}

// TestLicTMainHappyPath runs main() itself. main() only ever calls os.Exit on
// an error path, so with a real key pair next to the test binary and answers on
// stdin it returns normally. Every precondition is asserted first: if one broke,
// main() would os.Exit(1) and take the whole test binary down with it.
func TestLicTMainHappyPath(t *testing.T) {
	key := LicTkey(t)

	exe, err := os.Executable()
	require.NoError(t, err)
	exeDir := filepath.Dir(exe)

	privatePath := filepath.Join(exeDir, "license_private_key.pem")
	publicPath := filepath.Join(exeDir, "license_public_key.pem")
	for _, path := range []string{privatePath, publicPath} {
		if _, statErr := os.Stat(path); statErr == nil {
			t.Fatalf("refusing to clobber pre-existing %s", path)
		}
	}

	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	require.NotNil(t, privatePEM)
	publicDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)
	publicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})
	require.NotNil(t, publicPEM)

	require.NoError(t, os.WriteFile(privatePath, privatePEM, 0o600))
	t.Cleanup(func() { _ = os.Remove(privatePath) })
	require.NoError(t, os.WriteFile(publicPath, publicPEM, 0o600))
	t.Cleanup(func() { _ = os.Remove(publicPath) })

	// Preconditions for the non-exiting path through main().
	foundPrivate, foundPublic, err := findRSAKeys()
	require.NoError(t, err)
	require.Equal(t, privatePath, foundPrivate)
	require.Equal(t, publicPath, foundPublic)
	loaded, err := loadPrivateKey(privatePath)
	require.NoError(t, err)
	require.True(t, loaded.Equal(key))

	LicTwithStdin(t, LicTvalidStdin)
	stdout := LicTcaptureStdout(t)

	main()

	printed := stdout()

	assert.Contains(t, printed, "S3 Encryption Proxy - License Generator")
	assert.Contains(t, printed, privatePath)
	assert.Contains(t, printed, publicPath)
	assert.Contains(t, printed, "License successfully generated!")
	assert.Contains(t, printed, "Licensee: Alice Example (Example GmbH)")
	assert.Contains(t, printed, "Note: Production License - 500TB")
	assert.Contains(t, printed, "K8s Cluster: cluster-abc-123")
	assert.Contains(t, printed, "export S3EP_LICENSE_TOKEN=")

	// The token main() printed must verify under the planted public key and
	// carry exactly the answers that were typed.
	token := LicTextractToken(t, printed)
	parsed, err := jwt.ParseWithClaims(token, &LicenseClaims{}, func(*jwt.Token) (interface{}, error) {
		return &key.PublicKey, nil
	})
	require.NoError(t, err)
	require.True(t, parsed.Valid)

	claims, ok := parsed.Claims.(*LicenseClaims)
	require.True(t, ok)
	assert.Equal(t, "Alice Example", claims.LicenseeName)
	assert.Equal(t, "Example GmbH", claims.LicenseeCompany)
	assert.Equal(t, "Production License - 500TB", claims.LicenseNote)
	assert.Equal(t, "cluster-abc-123", claims.KubernetesClusterID)
	assert.Equal(t, "s3ep.com", claims.Issuer)
	assert.Contains(t, printed, claims.ID)
	assert.WithinDuration(t, time.Now().Add(365*24*time.Hour), claims.ExpiresAt.Time, time.Minute)
}

// LicTextractToken pulls the JWT out of the trailing export line main() prints.
func LicTextractToken(t *testing.T, printed string) string {
	t.Helper()
	const marker = "export S3EP_LICENSE_TOKEN=\""
	idx := strings.Index(printed, marker)
	require.GreaterOrEqual(t, idx, 0, "output does not contain the export line")
	rest := printed[idx+len(marker):]
	end := strings.Index(rest, "\"")
	require.GreaterOrEqual(t, end, 0, "export line is not terminated")
	token := rest[:end]
	require.Len(t, strings.Split(token, "."), 3)
	return token
}
