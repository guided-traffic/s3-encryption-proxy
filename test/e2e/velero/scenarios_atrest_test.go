//go:build e2e

package velero

import (
	"bytes"
	"crypto/sha256"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// gzipMagic is the two-byte header every gzip stream starts with. Velero writes
// velero-backup.json.gz and the resource tarball as gzip, so its presence in the
// raw stored bytes means the object was not encrypted.
var gzipMagic = []byte{0x1f, 0x8b}

// TestV8_EncryptionAtRest is the assertion for main goal 1: whatever Velero
// wrote, the backend holds ciphertext.
//
// It reads objects twice — once straight from MinIO with the backend root
// credentials, once through the proxy — and requires the two to differ while
// only the proxy read produces recognisable plaintext.
func TestV8_EncryptionAtRest(t *testing.T) {
	ctx := preflight(t)
	guard := beginScenario(t, ctx)

	ns := uniqueName("e2e-v8")
	t.Cleanup(func() { cleanupNamespace(t, ns) })

	applyManifest(t, ctx, namespaceManifest(ns))
	waitDeploymentReady(t, ctx, ns, "app", 5*minute)

	backup := backupName("v8")
	velero(t, ctx, "backup", "create", backup, "--include-namespaces", ns, "--wait")
	waitBackupCompleted(t, ctx, backup, backupTimeout)

	objects := listBackendObjects(t, ctx, "backups/"+backup+"/")
	require.NotEmpty(t, objects, "the backup wrote no objects to the backend")
	t.Logf("backup %s produced %d objects on the backend", backup, len(objects))

	const metadataPrefix = "s3ep-"

	t.Run("every_object_carries_encryption_metadata", func(t *testing.T) {
		for _, obj := range objects {
			if obj.Size == 0 {
				continue // an empty object has no ciphertext to describe
			}
			require.Truef(t, hasEncryptionMetadata(obj.Metadata, metadataPrefix),
				"object %s (%d bytes) has no %s metadata, so it was stored unencrypted: %v",
				obj.Key, obj.Size, metadataPrefix, obj.Metadata)

			algo, ok := metadataValue(obj.Metadata, metadataPrefix, "dek-algorithm")
			require.Truef(t, ok, "object %s has no dek-algorithm", obj.Key)
			require.Containsf(t, []string{"aes-gcm", "aes-ctr"}, algo,
				"object %s has an unexpected DEK algorithm %q", obj.Key, algo)

			_, ok = metadataValue(obj.Metadata, metadataPrefix, "encrypted-dek")
			require.Truef(t, ok, "object %s has no wrapped DEK", obj.Key)

			_, ok = metadataValue(obj.Metadata, metadataPrefix, "kek-fingerprint")
			require.Truef(t, ok, "object %s has no KEK fingerprint, so it could never be decrypted", obj.Key)
		}
	})

	t.Run("gzip_objects_are_not_readable_at_rest", func(t *testing.T) {
		checked := 0
		for _, obj := range objects {
			if !strings.HasSuffix(obj.Key, ".gz") || obj.Size == 0 {
				continue
			}
			checked++
			stored := readBackendObject(t, ctx, obj.Key)
			require.Falsef(t, bytes.HasPrefix(stored, gzipMagic),
				"object %s starts with the gzip magic bytes at rest: it was stored as plaintext", obj.Key)

			plain := readViaProxy(t, ctx, obj.Key)
			require.Truef(t, bytes.HasPrefix(plain, gzipMagic),
				"object %s does not decrypt back to gzip through the proxy", obj.Key)
			require.NotEqualf(t, sha256.Sum256(stored), sha256.Sum256(plain),
				"object %s is byte-identical at rest and through the proxy: nothing was encrypted", obj.Key)
		}
		require.Positive(t, checked, "the backup contained no .gz objects to check")
		t.Logf("verified %d gzip objects are ciphertext at rest", checked)
	})

	t.Run("backup_json_is_not_readable_at_rest", func(t *testing.T) {
		// velero-backup.json is the object Velero reads first on every sync. If
		// it were stored in the clear, so is everything else.
		key := "backups/" + backup + "/velero-backup.json"
		stored := readBackendObject(t, ctx, key)
		require.NotContains(t, string(stored), `"kind":"Backup"`,
			"velero-backup.json is stored as readable JSON")
		require.NotContains(t, string(stored), backup,
			"the backup name appears verbatim in the stored bytes")

		plain := readViaProxy(t, ctx, key)
		require.Contains(t, string(plain), backup,
			"the object does not decrypt back to the original JSON through the proxy")
	})

	guard.assertHealthy(t, ctx)
}

// TestV8b_DataMoverPayloadEncryptedAtRest extends the at-rest assertion to the
// kopia repository objects a data-mover backup writes, which take a different
// path through the proxy (streaming AES-CTR and multipart rather than the
// buffered AES-GCM path the metadata uses).
func TestV8b_DataMoverPayloadEncryptedAtRest(t *testing.T) {
	ctx := preflight(t)
	guard := beginScenario(t, ctx)

	ns := uniqueName("e2e-v8b")
	t.Cleanup(func() { cleanupNamespace(t, ns) })

	setupDataVolume(t, ctx, ns)

	backup := backupName("v8b")
	velero(t, ctx, "backup", "create", backup,
		"--include-namespaces", ns, "--snapshot-move-data", "--wait")
	waitBackupCompleted(t, ctx, backup, dataMoverTimeout)
	waitBackupOperationsComplete(t, ctx, backup, dataMoverTimeout)

	// kopia stores its repository under kopia/<namespace>/ in the same bucket.
	objects := listBackendObjects(t, ctx, "kopia/")
	require.NotEmpty(t, objects, "the data mover wrote no kopia objects")

	const metadataPrefix = "s3ep-"
	var large int
	for _, obj := range objects {
		if obj.Size == 0 {
			continue
		}
		require.Truef(t, hasEncryptionMetadata(obj.Metadata, metadataPrefix),
			"kopia object %s (%d bytes) was stored unencrypted", obj.Key, obj.Size)
		if obj.Size > 1<<20 {
			large++
		}
	}
	t.Logf("verified %d kopia objects are encrypted at rest (%d above 1 MiB)", len(objects), large)

	// kopia's repository format file is the one object whose plaintext structure
	// is predictable, so it is the clearest proof the blobs are not readable.
	for _, obj := range objects {
		if strings.HasSuffix(obj.Key, "kopia.repository") || strings.HasSuffix(obj.Key, "kopia.repository.f") {
			stored := readBackendObject(t, ctx, obj.Key)
			require.NotContains(t, string(stored), "kopia",
				"the kopia repository descriptor %s is readable at rest", obj.Key)
			break
		}
	}

	guard.assertHealthy(t, ctx)
}
