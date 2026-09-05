//go:build e2e

package velero

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestV1_NamespaceMetadataRoundTrip is the BUG-001 scenario.
//
// Velero writes its backup metadata (velero-backup.json.gz, the resource
// tarball, the item-operations list) through the proxy with aws-sdk-go-v2. Over
// HTTPS that SDK frames every non-empty body as aws-chunked with a CRC32
// trailer, and each file is small enough to take the buffered PutObject path.
// Before the fix the framing bytes were encrypted along with the payload, and
// Velero failed the next read with "gzip: invalid header".
//
// The restore is therefore the assertion: it can only succeed if every metadata
// object came back byte-identical.
func TestV1_NamespaceMetadataRoundTrip(t *testing.T) {
	ctx := preflight(t)
	guard := beginScenario(t, ctx)

	ns := uniqueName("e2e-v1")
	t.Cleanup(func() { cleanupNamespace(t, ns) })

	applyManifest(t, ctx, namespaceManifest(ns))
	waitDeploymentReady(t, ctx, ns, "app", 5*minute)

	before := namespaceFingerprint(t, ctx, ns)

	backup := backupName("v1")
	velero(t, ctx, "backup", "create", backup, "--include-namespaces", ns, "--wait")
	waitBackupCompleted(t, ctx, backup, backupTimeout)

	deleteNamespaceAndWait(t, ctx, ns)

	restore := restoreName("v1")
	velero(t, ctx, "restore", "create", restore, "--from-backup", backup, "--wait")
	waitRestoreCompleted(t, ctx, restore, restoreTimeout)

	waitDeploymentReady(t, ctx, ns, "app", 5*minute)
	after := namespaceFingerprint(t, ctx, ns)

	require.Equal(t, before, after,
		"restored namespace differs from the backed-up one: metadata did not round-trip through the proxy")

	guard.assertHealthy(t, ctx)
}

// TestV1b_MultipartMetadataRoundTrip drives the resource tarball past the AWS
// SDK uploader's part-size threshold so the Velero plugin switches to a
// multipart upload.
//
// This is the only scenario that reaches the UploadPart handler with
// aws-chunked framing. That branch shares the buffered ReadBody path with
// PutObject and had the same defect, but nothing in the integration suite ever
// sent it a framed body: a full run recorded 1466 UploadPart requests and zero
// with Content-Encoding: aws-chunked.
func TestV1b_MultipartMetadataRoundTrip(t *testing.T) {
	ctx := preflight(t)
	guard := beginScenario(t, ctx)

	ns := uniqueName("e2e-v1b")
	t.Cleanup(func() { cleanupNamespace(t, ns) })

	applyManifest(t, ctx, namespaceManifest(ns))
	// 24 x 700 KiB of incompressible data ~= 16 MiB of ConfigMap payload. The
	// tarball then exceeds the uploader's 5 MiB part size several times over,
	// so multiple parts are uploaded rather than one that happens to be large.
	applyManifest(t, ctx, bulkConfigMapsManifest(ns, 24, 700))
	waitDeploymentReady(t, ctx, ns, "app", 5*minute)

	before := namespaceFingerprint(t, ctx, ns)
	beforeBulk := bulkConfigMapHashes(t, ctx, ns)
	require.Len(t, beforeBulk, 24, "expected 24 bulk ConfigMaps before backup")

	backup := backupName("v1b")
	velero(t, ctx, "backup", "create", backup, "--include-namespaces", ns, "--wait")
	waitBackupCompleted(t, ctx, backup, backupTimeout)

	deleteNamespaceAndWait(t, ctx, ns)

	restore := restoreName("v1b")
	velero(t, ctx, "restore", "create", restore, "--from-backup", backup, "--wait")
	waitRestoreCompleted(t, ctx, restore, restoreTimeout)

	waitDeploymentReady(t, ctx, ns, "app", 5*minute)

	require.Equal(t, before, namespaceFingerprint(t, ctx, ns), "namespace metadata did not round-trip")
	require.Equal(t, beforeBulk, bulkConfigMapHashes(t, ctx, ns),
		"bulk ConfigMap payloads did not round-trip: the multipart metadata upload is corrupted")

	guard.assertHealthy(t, ctx)
}

// TestV7_RestoreIntoDifferentNamespace exercises the restore path with a
// namespace mapping. Cheap, and it proves the proxy serves the same objects to
// a second consumer of the same backup.
func TestV7_RestoreIntoDifferentNamespace(t *testing.T) {
	ctx := preflight(t)
	guard := beginScenario(t, ctx)

	src := uniqueName("e2e-v7-src")
	dst := uniqueName("e2e-v7-dst")
	t.Cleanup(func() { cleanupNamespace(t, src); cleanupNamespace(t, dst) })

	applyManifest(t, ctx, namespaceManifest(src))
	waitDeploymentReady(t, ctx, src, "app", 5*minute)
	before := namespaceFingerprint(t, ctx, src)

	backup := backupName("v7")
	velero(t, ctx, "backup", "create", backup, "--include-namespaces", src, "--wait")
	waitBackupCompleted(t, ctx, backup, backupTimeout)

	restore := restoreName("v7")
	velero(t, ctx, "restore", "create", restore, "--from-backup", backup,
		"--namespace-mappings", src+":"+dst, "--wait")
	waitRestoreCompleted(t, ctx, restore, restoreTimeout)

	waitDeploymentReady(t, ctx, dst, "app", 5*minute)

	// The fingerprint is namespace-scoped, so the two must match once the
	// namespace name itself is normalised out.
	after := namespaceFingerprint(t, ctx, dst)
	require.Equal(t, before, after, "namespace-mapped restore produced different content")

	// The source namespace must be untouched by the restore.
	require.Equal(t, before, namespaceFingerprint(t, ctx, src),
		"restore into a different namespace modified the source")

	guard.assertHealthy(t, ctx)
}

// namespaceFingerprint captures the content of every resource kind V1 creates,
// normalised so it can be compared across a delete/restore cycle and across
// namespaces.
//
// Server-populated fields (uid, resourceVersion, creationTimestamp, the
// namespace name itself) are excluded on purpose: Velero legitimately changes
// them, and including them would make the assertion fail for the wrong reason.
func namespaceFingerprint(t *testing.T, ctx context.Context, ns string) map[string]string {
	t.Helper()
	fingerprint := map[string]string{}

	var cms struct {
		Items []struct {
			Metadata struct {
				Name   string            `json:"name"`
				Labels map[string]string `json:"labels"`
			} `json:"metadata"`
			Data map[string]string `json:"data"`
		} `json:"items"`
	}
	kubectlJSON(t, ctx, &cms, "-n", ns, "get", "configmaps")
	for _, cm := range cms.Items {
		if cm.Metadata.Name == "kube-root-ca.crt" || cm.Metadata.Labels["e2e-bulk"] == "true" {
			continue // injected by the cluster / covered separately
		}
		fingerprint["configmap/"+cm.Metadata.Name] = hashStringMap(cm.Data)
	}

	var secrets struct {
		Items []struct {
			Metadata struct {
				Name string `json:"name"`
			} `json:"metadata"`
			Type string            `json:"type"`
			Data map[string]string `json:"data"`
		} `json:"items"`
	}
	kubectlJSON(t, ctx, &secrets, "-n", ns, "get", "secrets")
	for _, s := range secrets.Items {
		if s.Type == "kubernetes.io/service-account-token" {
			continue // regenerated per namespace
		}
		fingerprint["secret/"+s.Metadata.Name] = hashStringMap(s.Data)
	}

	for _, kind := range []string{"serviceaccount", "service", "role", "rolebinding", "deployment"} {
		out := kubectl(t, ctx, "-n", ns, "get", kind,
			"-o", "jsonpath={range .items[*]}{.metadata.name}{'\\n'}{end}")
		names := strings.Fields(out)
		if len(names) > 0 {
			fingerprint[kind+"s"] = strings.Join(names, ",")
		}
	}

	// The Service selector and the Deployment container image are the parts a
	// broken restore would most plausibly mangle.
	fingerprint["service/app.selector"] = strings.TrimSpace(
		kubectl(t, ctx, "-n", ns, "get", "svc", "app", "-o", "jsonpath={.spec.selector.app}"))
	fingerprint["deployment/app.image"] = strings.TrimSpace(
		kubectl(t, ctx, "-n", ns, "get", "deploy", "app",
			"-o", "jsonpath={.spec.template.spec.containers[0].image}"))

	return fingerprint
}

// bulkConfigMapHashes returns name -> SHA-256 of the blob for the V1b payload
// ConfigMaps. Hashes, not contents: the payloads are 700 KiB each.
func bulkConfigMapHashes(t *testing.T, ctx context.Context, ns string) map[string]string {
	t.Helper()
	var cms struct {
		Items []struct {
			Metadata struct {
				Name string `json:"name"`
			} `json:"metadata"`
			Data map[string]string `json:"data"`
		} `json:"items"`
	}
	kubectlJSON(t, ctx, &cms, "-n", ns, "get", "configmaps", "-l", "e2e-bulk=true")

	hashes := map[string]string{}
	for _, cm := range cms.Items {
		hashes[cm.Metadata.Name] = sha256Hex(cm.Data["blob"])
	}
	return hashes
}

// cleanupNamespace removes a scenario namespace, ignoring the case where it is
// already gone.
func cleanupNamespace(t *testing.T, ns string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*minute)
	defer cancel()
	_, _ = tryKubectl(t, ctx, "delete", "namespace", ns, "--ignore-not-found", "--wait=false")
}
