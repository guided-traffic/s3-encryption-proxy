//go:build e2e

// Package harness holds what the client-driven end-to-end suites share: the
// coordinates of the demo compose stack, a process runner that keeps a client's
// own words, a backend client that reads MinIO directly, and the at-rest
// assertion that is main goal 1 of this product.
//
// A suite in this package's sense drives a REAL third-party S3 client binary —
// rclone, s3cmd — against the proxy and asserts what that client reports. The
// value of such a suite is precisely that it is not the AWS SDK: a client's own
// verification logic is what turns a documented deviation into a defect
// (ADR 0006 D5, ADR 0019 D1).
//
// The stack is created by ./start-demo.sh through each suite's up-script, not by
// TestMain: a bring-up inside a Go test turns every infrastructure problem into
// a test failure and prevents iterating against a warm stack.
package harness

import (
	"bufio"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// Env is a parsed KEY=VALUE file. Both bash and Go read the same files, so a
// rename cannot drift between an up-script and the suite it brings up.
type Env struct {
	values map[string]string
	origin string
}

// LoadEnv parses a KEY=VALUE file relative to the repository root.
func LoadEnv(t *testing.T, relPath ...string) Env {
	t.Helper()
	path := filepath.Join(append([]string{RepoRoot(t)}, relPath...)...)
	f, err := os.Open(path) // #nosec G304 - fixed path inside the repository
	require.NoErrorf(t, err, "%s", path)
	defer func() { _ = f.Close() }()

	values := map[string]string{}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		values[strings.TrimSpace(k)] = strings.Trim(strings.TrimSpace(v), `"`)
	}
	require.NoError(t, scanner.Err())
	return Env{values: values, origin: path}
}

// DemoStack loads the shared coordinates of the demo compose stack.
func DemoStack(t *testing.T) Env {
	t.Helper()
	return LoadEnv(t, "test", "e2e", "harness", "demo-stack.env")
}

// Get returns a value, failing the test when the file does not carry the key.
// An absent key is a drift between the file and the suite, never a default.
func (e Env) Get(t *testing.T, key string) string {
	t.Helper()
	v, ok := e.values[key]
	require.Truef(t, ok, "%s has no key %q", e.origin, key)
	return v
}

// GetInt is Get for a numeric value.
func (e Env) GetInt(t *testing.T, key string) int64 {
	t.Helper()
	n, err := strconv.ParseInt(e.Get(t, key), 10, 64)
	require.NoErrorf(t, err, "%s: %s is not a number", e.origin, key)
	return n
}

// RepoRoot walks up from the working directory until it finds go.mod.
func RepoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	require.NoError(t, err)
	for i := 0; i < 8; i++ {
		if _, statErr := os.Stat(filepath.Join(dir, "go.mod")); statErr == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		require.NotEqual(t, parent, dir, "go.mod not found above the working directory")
		dir = parent
	}
	t.Fatal("go.mod not found")
	return ""
}

// Binary resolves a client binary: the environment override if it is set,
// otherwise the path the suite's up-script installed it at.
func Binary(t *testing.T, envKey string, installed ...string) string {
	t.Helper()
	if v := os.Getenv(envKey); v != "" {
		return v
	}
	path := filepath.Join(append([]string{RepoRoot(t)}, installed...)...)
	_, err := os.Stat(path)
	require.NoErrorf(t, err,
		"%s is not installed and $%s is unset. Run the suite's up-script first.", path, envKey)
	return path
}

// CACert returns the absolute path of the test CA both TLS endpoints are signed
// by. Verification stays on in every suite: the proxy certificate is part of
// what an end-to-end run validates, and a client told to skip verification is
// not the client an operator runs.
func CACert(t *testing.T) string {
	t.Helper()
	path := filepath.Join(RepoRoot(t), DemoStack(t).Get(t, "S3EP_CA_CERT"))
	_, err := os.Stat(path)
	require.NoErrorf(t, err, "test CA not found at %s; run test/ssl-setup/gen-certs.sh", path)
	return path
}
