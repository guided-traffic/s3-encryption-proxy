//go:build e2e

package velero

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// busyboxImage is used for every data-carrying pod. It is already present on
// the kind node after the first pull and is multi-arch.
const busyboxImage = "busybox:1.37"

// namespaceManifest is the V1 workload: one of every resource kind Velero has to
// back up as metadata. Everything here travels through the proxy as gzipped JSON
// inside the backup tarball, which is the PutObject-below-threshold path.
func namespaceManifest(ns string) string {
	return fmt.Sprintf(`
apiVersion: v1
kind: Namespace
metadata:
  name: %[1]s
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: app
  namespace: %[1]s
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: app-config
  namespace: %[1]s
data:
  greeting: "hello from %[1]s"
  nested.yaml: |
    key: value
    list:
      - a
      - b
---
apiVersion: v1
kind: Secret
metadata:
  name: app-secret
  namespace: %[1]s
type: Opaque
stringData:
  username: e2e-user
  password: e2e-password-value-that-must-round-trip
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: app-role
  namespace: %[1]s
rules:
  - apiGroups: [""]
    resources: ["configmaps"]
    verbs: ["get", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: app-rolebinding
  namespace: %[1]s
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: app-role
subjects:
  - kind: ServiceAccount
    name: app
    namespace: %[1]s
---
apiVersion: v1
kind: Service
metadata:
  name: app
  namespace: %[1]s
spec:
  selector:
    app: e2e-app
  ports:
    - name: http
      port: 80
      targetPort: 8080
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: app
  namespace: %[1]s
spec:
  replicas: 1
  selector:
    matchLabels:
      app: e2e-app
  template:
    metadata:
      labels:
        app: e2e-app
    spec:
      serviceAccountName: app
      containers:
        - name: app
          image: %[2]s
          command: ["sh", "-c", "sleep infinity"]
          resources:
            requests:
              cpu: 10m
              memory: 16Mi
`, ns, busyboxImage)
}

// bulkConfigMapsManifest returns count ConfigMaps of roughly sizeKiB each of
// incompressible data.
//
// Purpose: push the backup resource tarball past the AWS SDK uploader's 5 MiB
// part size so the Velero plugin switches to multipart. That is the only way
// this suite reaches the UploadPart handler with aws-chunked framing, which is
// the second half of the BUG-001 surface and had zero coverage.
func bulkConfigMapsManifest(ns string, count, sizeKiB int) string {
	var b strings.Builder
	for i := 0; i < count; i++ {
		// Base64 alphabet with a per-ConfigMap rotation: compresses poorly, and
		// gzip cannot collapse the objects into each other.
		payload := incompressibleString(sizeKiB*1024, i)
		fmt.Fprintf(&b, `
apiVersion: v1
kind: ConfigMap
metadata:
  name: bulk-%03d
  namespace: %s
  labels:
    e2e-bulk: "true"
data:
  blob: %q
---`, i, ns, payload)
	}
	return strings.TrimSuffix(b.String(), "---")
}

// incompressibleString builds a deterministic, poorly-compressible payload.
// Deterministic on purpose: a re-run produces byte-identical objects, so a size
// change in the backup is a real change and not test noise.
func incompressibleString(n, seed int) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	b := make([]byte, n)
	// xorshift keeps this cheap and dependency-free while still defeating gzip.
	state := uint32(seed*2654435761 + 1)
	for i := range b {
		state ^= state << 13
		state ^= state >> 17
		state ^= state << 5
		b[i] = alphabet[state%uint32(len(alphabet))]
	}
	return string(b)
}

// pvcPodManifest creates a PVC on the CSI hostpath StorageClass plus a pod that
// mounts it and stays alive so the test can read and hash its files.
func pvcPodManifest(ns, pvcName, podName, storageClass, size string) string {
	return fmt.Sprintf(`
apiVersion: v1
kind: Namespace
metadata:
  name: %[1]s
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: %[2]s
  namespace: %[1]s
spec:
  accessModes: ["ReadWriteOnce"]
  storageClassName: %[4]s
  resources:
    requests:
      storage: %[5]s
---
apiVersion: v1
kind: Pod
metadata:
  name: %[3]s
  namespace: %[1]s
  labels:
    app: e2e-data
spec:
  containers:
    - name: data
      image: %[6]s
      command: ["sh", "-c", "sleep infinity"]
      volumeMounts:
        - name: data
          mountPath: /data
      resources:
        requests:
          cpu: 10m
          memory: 16Mi
  volumes:
    - name: data
      persistentVolumeClaim:
        claimName: %[2]s
`, ns, pvcName, podName, storageClass, size, busyboxImage)
}

// writeTestFiles fills /data in the pod with files whose sizes straddle the
// proxy's routing thresholds, so one PVC backup covers the AES-GCM path, the
// single-part AES-CTR path and the multipart path at once.
//
// sizes are given in MiB relative to the proxy defaults:
//   - 1 MiB   below streaming_threshold (5 MiB)  -> AES-GCM
//   - 6 MiB   above streaming_threshold          -> AES-CTR single part
//   - 20 MiB  above streaming_segment_size (12)  -> multipart
func writeTestFiles(t *testing.T, ctx context.Context, ns, pod string) map[string]string {
	t.Helper()

	// /dev/urandom keeps the payload incompressible, so kopia cannot dedupe the
	// files into nothing and the object sizes stay representative.
	script := strings.Join([]string{
		"set -e",
		"mkdir -p /data/files",
		"dd if=/dev/urandom of=/data/files/small.bin bs=1M count=1 2>/dev/null",
		"dd if=/dev/urandom of=/data/files/medium.bin bs=1M count=6 2>/dev/null",
		"dd if=/dev/urandom of=/data/files/large.bin bs=1M count=20 2>/dev/null",
		"printf 'tiny' > /data/files/tiny.txt",
		"sync",
	}, " && ")
	kubectl(t, ctx, "-n", ns, "exec", pod, "--", "sh", "-c", script)

	return treeSHA(t, ctx, ns, pod, "/data/files")
}

// treeSHA returns a path -> SHA-256 map for every file under dir.
//
// Comparing whole maps gives a readable diff on file names and hashes and never
// prints file contents, per the project work order: hash comparison, no hex
// dumps.
func treeSHA(t *testing.T, ctx context.Context, ns, pod, dir string) map[string]string {
	t.Helper()
	out := kubectl(t, ctx, "-n", ns, "exec", pod, "--", "sh", "-c",
		fmt.Sprintf("cd %s && find . -type f | sort | xargs sha256sum", dir))

	hashes := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 {
			hashes[fields[1]] = fields[0]
		}
	}
	require.NotEmptyf(t, hashes, "no files found under %s in %s/%s:\n%s", dir, ns, pod, out)
	return hashes
}

// waitPodReady blocks until the named pod is Ready.
func waitPodReady(t *testing.T, ctx context.Context, ns, pod string, timeout time.Duration) {
	t.Helper()
	eventually(t, timeout, 3*time.Second, fmt.Sprintf("pod %s/%s never became Ready", ns, pod),
		func() (bool, string) {
			out, err := tryKubectl(t, ctx, "-n", ns, "get", "pod", pod,
				"-o", "jsonpath={.status.conditions[?(@.type=='Ready')].status}")
			if err != nil {
				return false, "not found"
			}
			return strings.TrimSpace(out) == "True", strings.TrimSpace(out)
		})
}

// waitDeploymentReady blocks until a Deployment has its replicas available.
func waitDeploymentReady(t *testing.T, ctx context.Context, ns, name string, timeout time.Duration) {
	t.Helper()
	eventually(t, timeout, 3*time.Second, fmt.Sprintf("deployment %s/%s never became available", ns, name),
		func() (bool, string) {
			out, err := tryKubectl(t, ctx, "-n", ns, "get", "deploy", name,
				"-o", "jsonpath={.status.readyReplicas}")
			if err != nil {
				return false, "not found"
			}
			return strings.TrimSpace(out) == "1", strings.TrimSpace(out)
		})
}

// podNameByLabel returns the single pod matching a label selector.
func podNameByLabel(t *testing.T, ctx context.Context, ns, selector string) string {
	t.Helper()
	var name string
	eventually(t, 3*time.Minute, 2*time.Second, fmt.Sprintf("no pod matched %s in %s", selector, ns),
		func() (bool, string) {
			out, err := tryKubectl(t, ctx, "-n", ns, "get", "pods", "-l", selector,
				"-o", "jsonpath={.items[*].metadata.name}")
			if err != nil {
				return false, "error"
			}
			fields := strings.Fields(out)
			if len(fields) == 0 {
				return false, "none"
			}
			sort.Strings(fields)
			name = fields[0]
			return true, name
		})
	return name
}
