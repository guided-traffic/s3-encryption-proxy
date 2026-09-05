//go:build e2e

package velero

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const (
	hostPathStorageClass = "csi-hostpath-sc"
	// 64 MiB PVC holds the 27 MiB of test files with room for filesystem
	// overhead and kopia's working state.
	pvcSize = "64Mi"
)

// TestV2_CSISnapshotDataMover backs a PVC up with a CSI snapshot and the data
// mover, so the volume contents travel to the object store through kopia.
//
// Coverage: kopia writes pack files of a few MiB up to the repository blob
// size, which lands on PutObject above streaming_threshold (AES-CTR) and on
// multipart for the larger blobs. Note that kopia uses minio-go rather than
// aws-sdk-go-v2, so it does not emit checksum trailers; this scenario covers
// the size-based routing and the streaming paths, not the aws-chunked framing.
func TestV2_CSISnapshotDataMover(t *testing.T) {
	ctx := preflight(t)
	guard := beginScenario(t, ctx)

	ns := uniqueName("e2e-v2")
	t.Cleanup(func() { cleanupNamespace(t, ns) })

	before := setupDataVolume(t, ctx, ns)

	backup := backupName("v2")
	velero(t, ctx, "backup", "create", backup,
		"--include-namespaces", ns,
		"--snapshot-move-data",
		"--wait")
	waitBackupCompleted(t, ctx, backup, dataMoverTimeout)

	// The data mover runs as an asynchronous item operation; the backup is only
	// really finished once those complete.
	waitBackupOperationsComplete(t, ctx, backup, dataMoverTimeout)

	deleteNamespaceAndWait(t, ctx, ns)

	restore := restoreName("v2")
	velero(t, ctx, "restore", "create", restore, "--from-backup", backup, "--wait")
	waitRestoreCompleted(t, ctx, restore, dataMoverTimeout)

	pod := podNameByLabel(t, ctx, ns, "app=e2e-data")
	waitPodReady(t, ctx, ns, pod, 10*minute)

	require.Equal(t, before, treeSHA(t, ctx, ns, pod, "/data/files"),
		"restored volume contents differ from the backup")

	guard.assertHealthy(t, ctx)
}

// TestV3_FileSystemBackup backs the same data up through the node-agent
// file-system backup path instead of a snapshot.
//
// It produces a different object-size distribution than V2 because kopia sees
// the files directly rather than a snapshot mount, which is why both are worth
// running.
func TestV3_FileSystemBackup(t *testing.T) {
	ctx := preflight(t)
	guard := beginScenario(t, ctx)

	ns := uniqueName("e2e-v3")
	t.Cleanup(func() { cleanupNamespace(t, ns) })

	before := setupDataVolume(t, ctx, ns)

	backup := backupName("v3")
	velero(t, ctx, "backup", "create", backup,
		"--include-namespaces", ns,
		"--default-volumes-to-fs-backup",
		"--wait")
	waitBackupCompleted(t, ctx, backup, dataMoverTimeout)

	deleteNamespaceAndWait(t, ctx, ns)

	restore := restoreName("v3")
	velero(t, ctx, "restore", "create", restore, "--from-backup", backup, "--wait")
	waitRestoreCompleted(t, ctx, restore, dataMoverTimeout)

	pod := podNameByLabel(t, ctx, ns, "app=e2e-data")
	waitPodReady(t, ctx, ns, pod, 10*minute)

	require.Equal(t, before, treeSHA(t, ctx, ns, pod, "/data/files"),
		"restored volume contents differ from the file-system backup")

	guard.assertHealthy(t, ctx)
}

// TestV4_CSISnapshotOnly takes a CSI snapshot without moving the data, so only
// metadata reaches the object store.
//
// It verifies the CSI plumbing itself: if this fails, V2's failure would be
// ambiguous between the snapshot machinery and the proxy.
func TestV4_CSISnapshotWithoutDataMover(t *testing.T) {
	ctx := preflight(t)
	guard := beginScenario(t, ctx)

	ns := uniqueName("e2e-v4")
	t.Cleanup(func() { cleanupNamespace(t, ns) })

	before := setupDataVolume(t, ctx, ns)

	backup := backupName("v4")
	velero(t, ctx, "backup", "create", backup, "--include-namespaces", ns, "--wait")
	waitBackupCompleted(t, ctx, backup, backupTimeout)

	// A CSI snapshot must actually have been taken; otherwise the restore below
	// would succeed for the wrong reason (an empty volume recreated by the
	// StorageClass).
	requireVolumeSnapshotTaken(t, ctx, ns)

	deleteNamespaceAndWait(t, ctx, ns)

	restore := restoreName("v4")
	velero(t, ctx, "restore", "create", restore, "--from-backup", backup, "--wait")
	waitRestoreCompleted(t, ctx, restore, restoreTimeout)

	pod := podNameByLabel(t, ctx, ns, "app=e2e-data")
	waitPodReady(t, ctx, ns, pod, 10*minute)

	require.Equal(t, before, treeSHA(t, ctx, ns, pod, "/data/files"),
		"restored volume contents differ from the snapshot")

	guard.assertHealthy(t, ctx)
}

// setupDataVolume creates a namespace with a PVC and a pod, fills it with files
// that straddle the proxy's size thresholds, and returns their hashes.
func setupDataVolume(t *testing.T, ctx context.Context, ns string) map[string]string {
	t.Helper()
	const pvc, pod = "data", "data-pod"

	applyManifest(t, ctx, pvcPodManifest(ns, pvc, pod, hostPathStorageClass, pvcSize))
	waitPodReady(t, ctx, ns, pod, 10*minute)

	hashes := writeTestFiles(t, ctx, ns, pod)
	require.Len(t, hashes, 4, "expected 4 test files on the volume")
	return hashes
}

// waitBackupOperationsComplete blocks until every asynchronous backup item
// operation has finished. Without it a data-mover backup can report Completed
// while the upload is still in flight, and the restore then races it.
func waitBackupOperationsComplete(t *testing.T, ctx context.Context, name string, timeout time.Duration) {
	t.Helper()
	eventually(t, timeout, 5*time.Second,
		"backup item operations did not complete for "+name,
		func() (bool, string) {
			var obj struct {
				Status backupStatus `json:"status"`
			}
			raw, err := tryKubectl(t, ctx, "-n", loadVersionsEnv(t).get(t, "VELERO_NAMESPACE"),
				"get", "backup", name, "-o", "json")
			if err != nil {
				return false, "unavailable"
			}
			if jsonUnmarshal(raw, &obj) != nil {
				return false, "unparseable"
			}
			st := obj.Status
			require.Zerof(t, st.BackupItemOperationsFailed,
				"backup %s had %d failed item operations", name, st.BackupItemOperationsFailed)
			done := st.BackupItemOperationsCompleted >= st.BackupItemOperationsAttempted
			return done, fmt.Sprintf("%d/%d", st.BackupItemOperationsCompleted, st.BackupItemOperationsAttempted)
		})
}

// requireVolumeSnapshotTaken asserts a CSI VolumeSnapshot exists and is ready.
func requireVolumeSnapshotTaken(t *testing.T, ctx context.Context, ns string) {
	t.Helper()
	eventually(t, 5*minute, 3*time.Second, "no ready VolumeSnapshot was created for "+ns,
		func() (bool, string) {
			out, err := tryKubectl(t, ctx, "-n", ns, "get", "volumesnapshot",
				"-o", "jsonpath={range .items[*]}{.status.readyToUse}{' '}{end}")
			if err != nil {
				return false, "error"
			}
			trimmed := strings.TrimSpace(out)
			return strings.Contains(trimmed, "true"), trimmed
		})
}
