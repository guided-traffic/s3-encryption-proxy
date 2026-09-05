//go:build e2e

package velero

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestV5_BackupDownload downloads a finished backup through the velero CLI.
//
// This is the pre-signed URL path: the Velero server mints a signed URL against
// the BackupStorageLocation publicUrl and the CLI, which holds no credentials,
// fetches it. The proxy only supported header-based SigV4 before, so every
// download returned 403 while the backup itself succeeded.
func TestV5_BackupDownload(t *testing.T) {
	ctx := preflight(t)
	guard := beginScenario(t, ctx)

	ns := uniqueName("e2e-v5")
	t.Cleanup(func() { cleanupNamespace(t, ns) })

	applyManifest(t, ctx, namespaceManifest(ns))
	waitDeploymentReady(t, ctx, ns, "app", 5*minute)

	backup := backupName("v5")
	velero(t, ctx, "backup", "create", backup, "--include-namespaces", ns, "--wait")
	waitBackupCompleted(t, ctx, backup, backupTimeout)

	dir := t.TempDir()
	out := filepath.Join(dir, backup+".tar.gz")
	velero(t, ctx, "backup", "download", backup, "--output", out, "--force")

	info, err := os.Stat(out)
	require.NoError(t, err, "the downloaded archive is missing")
	require.Positive(t, info.Size(), "the downloaded archive is empty")

	// It must be a real gzip stream: a decryption failure would produce bytes
	// of the right length that are not gzip.
	data, err := os.ReadFile(out) // #nosec G304 - path built by the test
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(data), 2)
	require.Equalf(t, []byte{0x1f, 0x8b}, data[:2],
		"the downloaded backup is not a gzip stream: it did not decrypt correctly")

	t.Logf("downloaded backup archive: %d bytes", info.Size())
	guard.assertHealthy(t, ctx)
}

// TestV10_PresignedLogAccess covers the rest of the pre-signed surface: the
// backup and restore logs, and the results fetch inside `velero backup
// describe`. E2E-001 lists all three as mandatory health checks, so they have to
// work rather than be worked around.
func TestV10_PresignedLogAccess(t *testing.T) {
	ctx := preflight(t)
	guard := beginScenario(t, ctx)

	ns := uniqueName("e2e-v10")
	t.Cleanup(func() { cleanupNamespace(t, ns) })

	applyManifest(t, ctx, namespaceManifest(ns))
	waitDeploymentReady(t, ctx, ns, "app", 5*minute)

	backup := backupName("v10")
	velero(t, ctx, "backup", "create", backup, "--include-namespaces", ns, "--wait")
	waitBackupCompleted(t, ctx, backup, backupTimeout)

	t.Run("backup_logs", func(t *testing.T) {
		logs := velero(t, ctx, "backup", "logs", backup)
		require.NotEmpty(t, strings.TrimSpace(logs), "backup logs came back empty")
		require.Contains(t, logs, "Backup", "backup logs do not look like Velero output")
	})

	t.Run("backup_describe_details", func(t *testing.T) {
		// describe --details fetches several artefacts through pre-signed URLs.
		// --colorized=false keeps ANSI escapes out of the output so the
		// assertions match text rather than terminal formatting.
		out := velero(t, ctx, "backup", "describe", backup, "--details", "--colorized=false")
		require.Contains(t, out, "Completed")
		require.NotContains(t, out, "AccessDenied",
			"describe hit an authorisation error fetching a backup artefact")
		require.NotContains(t, out, "<error getting",
			"describe could not fetch one of the backup artefacts")
	})

	restore := restoreName("v10")
	deleteNamespaceAndWait(t, ctx, ns)
	velero(t, ctx, "restore", "create", restore, "--from-backup", backup, "--wait")
	waitRestoreCompleted(t, ctx, restore, restoreTimeout)

	t.Run("restore_logs", func(t *testing.T) {
		logs := velero(t, ctx, "restore", "logs", restore)
		require.NotEmpty(t, strings.TrimSpace(logs), "restore logs came back empty")
		require.Contains(t, logs, "restore", "restore logs do not look like Velero output")
	})

	guard.assertHealthy(t, ctx)
}

// TestV6_ScheduleAndDelete exercises the object lifecycle: a schedule produces
// several backups, deleting one has to remove its objects from the bucket, and
// the surviving backup must stay intact.
//
// Coverage: ListObjectsV2 with a prefix, and DeleteObject, both through the
// proxy rather than only against MinIO.
func TestV6_ScheduleAndDelete(t *testing.T) {
	ctx := preflight(t)
	guard := beginScenario(t, ctx)

	ns := uniqueName("e2e-v6")
	t.Cleanup(func() { cleanupNamespace(t, ns) })

	applyManifest(t, ctx, namespaceManifest(ns))
	waitDeploymentReady(t, ctx, ns, "app", 5*minute)

	// Two backups from the same source, created directly rather than by cron:
	// a schedule would add minutes of waiting for nothing this test asserts.
	first := backupName("v6-first")
	velero(t, ctx, "backup", "create", first, "--include-namespaces", ns, "--wait")
	waitBackupCompleted(t, ctx, first, backupTimeout)

	second := backupName("v6-second")
	velero(t, ctx, "backup", "create", second, "--include-namespaces", ns, "--wait")
	waitBackupCompleted(t, ctx, second, backupTimeout)

	require.NotEmpty(t, listBackendObjects(t, ctx, "backups/"+first+"/"))
	require.NotEmpty(t, listBackendObjects(t, ctx, "backups/"+second+"/"))

	velero(t, ctx, "backup", "delete", first, "--confirm")

	// Deletion is asynchronous: Velero creates a DeleteBackupRequest and the
	// controller removes the objects through the proxy.
	eventually(t, 5*minute, 5*time.Second, "backup objects were not removed from the bucket",
		func() (bool, string) {
			remaining := listBackendObjects(t, ctx, "backups/"+first+"/")
			return len(remaining) == 0, itoa(len(remaining)) + " objects left"
		})

	require.NotEmpty(t, listBackendObjects(t, ctx, "backups/"+second+"/"),
		"deleting one backup removed another one's objects")

	// And the surviving backup must still be usable.
	deleteNamespaceAndWait(t, ctx, ns)
	restore := restoreName("v6")
	velero(t, ctx, "restore", "create", restore, "--from-backup", second, "--wait")
	waitRestoreCompleted(t, ctx, restore, restoreTimeout)
	waitDeploymentReady(t, ctx, ns, "app", 5*minute)

	guard.assertHealthy(t, ctx)
}

// TestV9_ProviderRotation switches the active write provider and requires that
// objects written under the previous one still decrypt.
//
// This is what the per-object kek-fingerprint metadata exists for: on read the
// proxy has to select the provider that wrapped that object's DEK, not the one
// currently configured for writes. A regression here is silent until someone
// rotates a key, at which point every older backup becomes unreadable.
func TestV9_ProviderRotation(t *testing.T) {
	ctx := preflight(t)
	guard := beginScenario(t, ctx)

	ns := uniqueName("e2e-v9")
	t.Cleanup(func() { cleanupNamespace(t, ns) })

	applyManifest(t, ctx, namespaceManifest(ns))
	waitDeploymentReady(t, ctx, ns, "app", 5*minute)

	// Backup under the original provider.
	backup := backupName("v9")
	velero(t, ctx, "backup", "create", backup, "--include-namespaces", ns, "--wait")
	waitBackupCompleted(t, ctx, backup, backupTimeout)

	fingerprintBefore := backupKEKFingerprint(t, ctx, backup)
	require.NotEmpty(t, fingerprintBefore, "the backup objects carry no KEK fingerprint")

	// Rotate: add a second provider and make it the active one for writes. The
	// chart has no config checksum annotation, so the rollout has to be forced.
	t.Cleanup(func() { restoreProxyConfig(t) })
	rotateProxyProvider(t, ctx)

	// The old backup must still restore: its objects name the old provider.
	deleteNamespaceAndWait(t, ctx, ns)
	restore := restoreName("v9")
	velero(t, ctx, "restore", "create", restore, "--from-backup", backup, "--wait")
	waitRestoreCompleted(t, ctx, restore, restoreTimeout)
	waitDeploymentReady(t, ctx, ns, "app", 5*minute)

	// A new backup must be written under the new provider.
	backup2 := backupName("v9-rotated")
	velero(t, ctx, "backup", "create", backup2, "--include-namespaces", ns, "--wait")
	waitBackupCompleted(t, ctx, backup2, backupTimeout)

	fingerprintAfter := backupKEKFingerprint(t, ctx, backup2)
	require.NotEmpty(t, fingerprintAfter)
	require.NotEqual(t, fingerprintBefore, fingerprintAfter,
		"after rotation new objects are still wrapped with the old KEK: the rotation did not take effect")

	guard.assertHealthy(t, ctx)
}

// backupKEKFingerprint returns the KEK fingerprint recorded on the backup's
// objects, requiring it to be consistent across them.
func backupKEKFingerprint(t *testing.T, ctx context.Context, backup string) string {
	t.Helper()
	const metadataPrefix = "s3ep-"

	var fingerprint string
	for _, obj := range listBackendObjects(t, ctx, "backups/"+backup+"/") {
		if obj.Size == 0 {
			continue
		}
		value, ok := metadataValue(obj.Metadata, metadataPrefix, "kek-fingerprint")
		require.Truef(t, ok, "object %s has no KEK fingerprint", obj.Key)
		if fingerprint == "" {
			fingerprint = value
			continue
		}
		require.Equalf(t, fingerprint, value,
			"objects of one backup were wrapped with different KEKs (%s)", obj.Key)
	}
	return fingerprint
}

// rotateProxyProvider adds a second AES provider to the proxy ConfigMap and
// makes it the active one for writes.
//
// The edit is indentation-driven rather than a fixed-string replace: the config
// lives inside the chart values as a block scalar and is re-indented on the way
// into the ConfigMap, so the literal spacing here and there differ.
func rotateProxyProvider(t *testing.T, ctx context.Context) {
	t.Helper()
	e := loadVersionsEnv(t)
	ns := e.get(t, "PROXY_NAMESPACE")

	current := kubectl(t, ctx, "-n", ns, "get", "configmap", "s3ep-proxy-config",
		"-o", "jsonpath={.data.config\\.yaml}")
	require.Contains(t, current, "encryption_method_alias", "unexpected proxy ConfigMap layout")

	rotated := addRotatedProvider(t, current)
	require.Contains(t, rotated, `alias: "aes-rotated"`,
		"the second provider was not added, so the proxy would start with an alias that names no provider")

	rotated = strings.Replace(rotated,
		`encryption_method_alias: "aes-envelope"`,
		`encryption_method_alias: "aes-rotated"`, 1)
	require.Contains(t, rotated, `encryption_method_alias: "aes-rotated"`,
		"could not switch the active encryption alias")

	patchProxyConfig(t, ctx, rotated)
}

// addRotatedProvider appends a second aes provider as a sibling of the existing
// one, reusing its indentation. Both stay registered: the old provider is what
// decrypts the objects written before the rotation.
func addRotatedProvider(t *testing.T, config string) string {
	t.Helper()

	lines := strings.Split(config, "\n")
	aliasIdx := -1
	for i, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), `- alias: "aes-envelope"`) {
			aliasIdx = i
			break
		}
	}
	require.Positivef(t, aliasIdx+1, "no provider entry found in the config:\n%s", config)

	itemIndent := lineIndent(lines[aliasIdx])
	// Fields of the entry sit two spaces further in than the list dash.
	fieldIndent := itemIndent + "  "

	// The entry ends at the next line indented no deeper than the dash.
	end := len(lines)
	for i := aliasIdx + 1; i < len(lines); i++ {
		if strings.TrimSpace(lines[i]) == "" {
			continue
		}
		if len(lineIndent(lines[i])) <= len(itemIndent) {
			end = i
			break
		}
	}

	// A second 32-byte key, so the KEK fingerprint really changes.
	entry := []string{
		itemIndent + `- alias: "aes-rotated"`,
		fieldIndent + `type: "aes"`,
		fieldIndent + `description: "Rotated AES envelope encryption"`,
		fieldIndent + `config:`,
		fieldIndent + `  aes_key: "b1RoZXJLZXlGb3JSb3RhdGlvblRlc3RpbmcxMjM0NTY3OD0="`,
	}

	out := make([]string, 0, len(lines)+len(entry))
	out = append(out, lines[:end]...)
	out = append(out, entry...)
	out = append(out, lines[end:]...)
	return strings.Join(out, "\n")
}

// lineIndent returns the leading whitespace of a line.
func lineIndent(line string) string {
	return line[:len(line)-len(strings.TrimLeft(line, " \t"))]
}

// patchProxyConfig replaces the proxy config and restarts it.
func patchProxyConfig(t *testing.T, ctx context.Context, config string) {
	t.Helper()
	e := loadVersionsEnv(t)
	ns := e.get(t, "PROXY_NAMESPACE")

	tmp := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(tmp, []byte(config), 0o600))

	patched := kubectl(t, ctx, "-n", ns, "create", "configmap", "s3ep-proxy-config",
		"--from-file=config.yaml="+tmp, "--dry-run=client", "-o", "yaml")
	applyManifest(t, ctx, patched)

	// The chart has no checksum/config annotation, so a ConfigMap change alone
	// leaves the old configuration running.
	kubectl(t, ctx, "-n", ns, "rollout", "restart", "deploy/s3ep-proxy")
	if out, err := tryKubectl(t, ctx, "-n", ns, "rollout", "status", "deploy/s3ep-proxy", "--timeout=3m"); err != nil {
		// A rejected config crashloops the pod. Surface why instead of leaving a
		// bare rollout timeout.
		logs, _ := tryKubectl(t, ctx, "-n", ns, "logs", "deploy/s3ep-proxy", "--tail=20", "--all-containers")
		t.Fatalf("the proxy did not come up with the patched config: %v\n%s\nproxy logs:\n%s\nconfig:\n%s",
			err, out, logs, config)
	}
}

// restoreProxyConfig puts the chart's config back so a rotated proxy does not
// leak into later scenarios.
func restoreProxyConfig(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*minute)
	defer cancel()

	e := loadVersionsEnv(t)
	_, _ = tryRun(ctx, "helm", "--kube-context", kubeContext(t), "upgrade", "--install",
		e.get(t, "PROXY_RELEASE"), filepath.Join(repoRoot(t), "deploy", "helm", "s3-encryption-proxy"),
		"-n", e.get(t, "PROXY_NAMESPACE"),
		"-f", filepath.Join(repoRoot(t), "test", "e2e", "velero", "values-proxy.yaml"),
		"--wait", "--timeout", "5m")
	_, _ = tryKubectl(t, ctx, "-n", e.get(t, "PROXY_NAMESPACE"), "rollout", "restart", "deploy/s3ep-proxy")
	_, _ = tryKubectl(t, ctx, "-n", e.get(t, "PROXY_NAMESPACE"), "rollout", "status", "deploy/s3ep-proxy", "--timeout=5m")
}
