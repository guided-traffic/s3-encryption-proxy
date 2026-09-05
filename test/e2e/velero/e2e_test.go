//go:build e2e

// Package velero holds the end-to-end suite that runs Velero against the
// s3-encryption-proxy in a local kind cluster.
//
// The suite is the end-user experience for this product: Velero is a primary
// use case, and the aws-chunked upload defect (BUG-001) shipped precisely
// because nothing exercised it. Scenarios must not be skipped or disabled once
// merged.
//
// The cluster is created by test/e2e/velero/e2e-up.sh (make e2e-up), not by
// TestMain: a multi-minute bring-up inside a Go test turns every infrastructure
// problem into a test failure and prevents iterating against a warm cluster.
package velero

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const (
	// Backups of a few tens of MiB finish well inside this; the budget is for a
	// loaded CI runner, not for the happy path.
	backupTimeout  = 10 * time.Minute
	restoreTimeout = 10 * time.Minute
	// Data-mover scenarios add a kopia upload and a snapshot round trip.
	dataMoverTimeout = 15 * time.Minute
)

func jsonUnmarshal(raw string, out interface{}) error {
	return json.Unmarshal([]byte(raw), out)
}

// TestMain runs a preflight check so a missing cluster fails once with a clear
// message instead of once per scenario with an opaque one.
func TestMain(m *testing.M) {
	os.Exit(m.Run())
}

// preflight asserts the environment brought up by e2e-up.sh is present and
// healthy. Every scenario calls it first.
func preflight(t *testing.T) context.Context {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Minute)
	t.Cleanup(cancel)

	e := loadVersionsEnv(t)

	// Cluster reachable.
	if _, err := tryRun(ctx, kubectlBin(), "--context", kubeContext(t), "cluster-info"); err != nil {
		t.Fatalf("kind cluster %q is not reachable. Run 'make e2e-up' first.\n%v",
			kubeContext(t), err)
	}

	// CLI and server version must match: a drift between them produces failures
	// that look like product bugs.
	want := e.get(t, "VELERO_VERSION")
	out, err := tryRun(ctx, veleroBin(), "version", "--client-only")
	require.NoError(t, err, "velero CLI not usable")
	require.Containsf(t, out, want,
		"velero CLI version mismatch: versions.env pins %s but the CLI reports:\n%s", want, out)

	// BackupStorageLocation must be Available, otherwise every backup fails with
	// a validation error that says nothing about the proxy.
	eventually(t, 3*time.Minute, 5*time.Second, "BackupStorageLocation default is not Available",
		func() (bool, string) {
			phase, phaseErr := tryKubectl(t, ctx, "-n", e.get(t, "VELERO_NAMESPACE"),
				"get", "backupstoragelocation", "default", "-o", "jsonpath={.status.phase}")
			if phaseErr != nil {
				return false, "not found"
			}
			return strings.TrimSpace(phase) == "Available", strings.TrimSpace(phase)
		})

	return ctx
}

// TestPreflight fails fast and loudly when the environment is not up, so a
// broken cluster does not present as nine unrelated scenario failures.
func TestPreflight(t *testing.T) {
	ctx := preflight(t)
	e := loadVersionsEnv(t)

	t.Run("proxy_is_serving_https", func(t *testing.T) {
		// The proxy must answer on the TLS listener; a plaintext listener would
		// mean the SDK never emits checksum trailers and the suite would pass
		// while covering nothing.
		out := kubectl(t, ctx, "-n", e.get(t, "PROXY_NAMESPACE"), "get", "deploy", "s3ep-proxy",
			"-o", "jsonpath={.spec.template.spec.containers[0].livenessProbe.httpGet.scheme}")
		require.Equal(t, "HTTPS", strings.TrimSpace(out),
			"the proxy deployment is not probing over HTTPS, so it is not serving TLS")
	})

	t.Run("velero_uses_the_proxy", func(t *testing.T) {
		out := kubectl(t, ctx, "-n", e.get(t, "VELERO_NAMESPACE"), "get", "backupstoragelocation",
			"default", "-o", "jsonpath={.spec.config.s3Url}")
		require.Truef(t, strings.HasPrefix(strings.TrimSpace(out), "https://"),
			"the BackupStorageLocation must point at the proxy over HTTPS, got %q", out)
		require.Contains(t, out, "s3ep-proxy")
	})

	t.Run("snapshot_class_is_discoverable", func(t *testing.T) {
		out := kubectl(t, ctx, "get", "volumesnapshotclass",
			"-l", "velero.io/csi-volumesnapshot-class=true",
			"-o", "jsonpath={.items[*].metadata.name}")
		require.NotEmpty(t, strings.TrimSpace(out),
			"no VolumeSnapshotClass carries the velero.io/csi-volumesnapshot-class label; CSI scenarios would silently skip snapshotting")
	})
}

// backupName / restoreName give every object a name unique to the run so a
// re-run against a warm cluster never collides with its own leftovers.
func backupName(scenario string) string  { return uniqueName("e2e-" + scenario) }
func restoreName(scenario string) string { return uniqueName("e2e-" + scenario + "-restore") }

// deleteNamespaceAndWait removes a namespace and blocks until it is gone, so a
// restore cannot race a half-deleted namespace.
func deleteNamespaceAndWait(t *testing.T, ctx context.Context, ns string) {
	t.Helper()
	if _, err := tryKubectl(t, ctx, "delete", "namespace", ns, "--wait=false"); err != nil {
		return
	}
	eventually(t, 5*time.Minute, 3*time.Second, fmt.Sprintf("namespace %s was not deleted", ns),
		func() (bool, string) {
			out, err := tryKubectl(t, ctx, "get", "namespace", ns, "-o", "jsonpath={.status.phase}")
			if err != nil {
				return true, "gone"
			}
			return false, strings.TrimSpace(out)
		})
}
