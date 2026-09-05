//go:build e2e

package velero

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// env holds the pinned names and versions from versions.env. The Go suite and
// the bring-up script read the same file so a rename cannot drift between them.
type env struct {
	values map[string]string
}

var testEnv env

// loadVersionsEnv parses test/e2e/velero/versions.env. It is a plain KEY=VALUE
// file so both bash and Go can read it without a dependency.
func loadVersionsEnv(t *testing.T) env {
	t.Helper()
	if testEnv.values != nil {
		return testEnv
	}
	path := filepath.Join(repoRoot(t), "test", "e2e", "velero", "versions.env")
	f, err := os.Open(path) // #nosec G304 - fixed path inside the repository
	require.NoError(t, err, "versions.env")
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
	testEnv = env{values: values}
	return testEnv
}

func (e env) get(t *testing.T, key string) string {
	t.Helper()
	v, ok := e.values[key]
	require.Truef(t, ok, "versions.env has no key %q", key)
	return v
}

// repoRoot walks up from the working directory until it finds go.mod.
func repoRoot(t *testing.T) string {
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

func binary(envKey, fallback string) string {
	if v := os.Getenv(envKey); v != "" {
		return v
	}
	return fallback
}

func kubectlBin() string { return binary("KUBECTL_BIN", "kubectl") }
func veleroBin() string  { return binary("VELERO_BIN", "velero") }

// run executes a command and fails the test with the combined output attached.
// Every helper funnels through here so a failure always carries the real stderr
// instead of an opaque exit status.
func run(t *testing.T, ctx context.Context, bin string, args ...string) string {
	t.Helper()
	out, err := tryRun(ctx, bin, args...)
	require.NoErrorf(t, err, "%s %s failed:\n%s", bin, strings.Join(args, " "), out)
	return out
}

// tryRun is run without the assertion, for callers that expect failure.
func tryRun(ctx context.Context, bin string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, bin, args...) // #nosec G204 - test harness, arguments are built in-tree
	cmd.Env = os.Environ()
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// kubectl runs kubectl against the e2e cluster context.
func kubectl(t *testing.T, ctx context.Context, args ...string) string {
	t.Helper()
	return run(t, ctx, kubectlBin(), append([]string{"--context", kubeContext(t)}, args...)...)
}

func tryKubectl(t *testing.T, ctx context.Context, args ...string) (string, error) {
	t.Helper()
	return tryRun(ctx, kubectlBin(), append([]string{"--context", kubeContext(t)}, args...)...)
}

// velero runs the velero CLI against the e2e cluster, namespace pre-applied.
func velero(t *testing.T, ctx context.Context, args ...string) string {
	t.Helper()
	e := loadVersionsEnv(t)
	full := append([]string{"--kubecontext", kubeContext(t), "-n", e.get(t, "VELERO_NAMESPACE")}, args...)
	return run(t, ctx, veleroBin(), full...)
}

func tryVelero(t *testing.T, ctx context.Context, args ...string) (string, error) {
	t.Helper()
	e := loadVersionsEnv(t)
	full := append([]string{"--kubecontext", kubeContext(t), "-n", e.get(t, "VELERO_NAMESPACE")}, args...)
	return tryRun(ctx, veleroBin(), full...)
}

func kubeContext(t *testing.T) string {
	t.Helper()
	return "kind-" + loadVersionsEnv(t).get(t, "KIND_CLUSTER_NAME")
}

// kubectlJSON runs kubectl with -o json and unmarshals into out.
func kubectlJSON(t *testing.T, ctx context.Context, out interface{}, args ...string) {
	t.Helper()
	raw := kubectl(t, ctx, append(args, "-o", "json")...)
	require.NoErrorf(t, json.Unmarshal([]byte(raw), out), "kubectl %s returned unparseable JSON:\n%s",
		strings.Join(args, " "), raw)
}

// eventually polls fn until it returns true, failing with msg on timeout. It is
// a thin wrapper so every wait in the suite has the same cadence and reports the
// last observed state.
func eventually(t *testing.T, timeout time.Duration, interval time.Duration, msg string, fn func() (bool, string)) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var last string
	for time.Now().Before(deadline) {
		ok, state := fn()
		last = state
		if ok {
			return
		}
		time.Sleep(interval)
	}
	t.Fatalf("%s (timed out after %s, last state: %s)", msg, timeout, last)
}

// applyManifest pipes a rendered manifest into kubectl apply.
func applyManifest(t *testing.T, ctx context.Context, manifest string) {
	t.Helper()
	cmd := exec.CommandContext(ctx, kubectlBin(), "--context", kubeContext(t), "apply", "-f", "-") // #nosec G204
	cmd.Stdin = strings.NewReader(manifest)
	out, err := cmd.CombinedOutput()
	require.NoErrorf(t, err, "kubectl apply failed:\n%s\nmanifest:\n%s", out, manifest)
}

// uniqueName produces a DNS-safe name unique to this run.
func uniqueName(prefix string) string {
	return fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano()%1_000_000_000)
}
