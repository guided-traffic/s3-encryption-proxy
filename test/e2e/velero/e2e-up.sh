#!/usr/bin/env bash
# Brings up the complete Velero e2e environment in a local kind cluster.
#
# Cluster lifecycle deliberately lives here and not in TestMain: a five minute
# bring-up inside a Go test makes every infrastructure problem look like a test
# failure, and it prevents iterating against a warm cluster.
#
# Idempotent: safe to re-run. Re-running rebuilds and reloads the proxy image.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"
# shellcheck disable=SC1091
source "$HERE/versions.env"

log() { printf '\033[0;34m==>\033[0m %s\n' "$*"; }

need() { command -v "$1" >/dev/null 2>&1 || { echo "missing required tool: $1" >&2; exit 1; }; }
for t in kind kubectl helm docker openssl velero; do need "$t"; done

export KUBECONFIG="${KUBECONFIG:-$HOME/.kube/config}"
KCTX="kind-${KIND_CLUSTER_NAME}"
k() { kubectl --context "$KCTX" "$@"; }

# --- 0. certificates -------------------------------------------------------
# The CA has to exist before the cluster: Velero validates the proxy chain
# against it, and the SAN list has to cover the in-cluster Service name.
if [ ! -f "$REPO/test/ssl-setup/ca.crt" ]; then
  log "generating test PKI"
  "$REPO/test/ssl-setup/gen-certs.sh"
fi

# --- 1. license ------------------------------------------------------------
# Any provider other than "none" hard-fails without a license, so the pod would
# crashloop with a message that looks nothing like a licensing problem.
if [ -z "${S3EP_LICENSE_TOKEN:-}" ]; then
  if [ -f "$REPO/config/license.jwt" ]; then
    S3EP_LICENSE_TOKEN="$(tr -d '\n' < "$REPO/config/license.jwt")"
  else
    echo "S3EP_LICENSE_TOKEN is unset and config/license.jwt is missing" >&2
    echo "run 'make setup-dev-license' or export S3EP_LICENSE_TOKEN" >&2
    exit 1
  fi
fi
export S3EP_LICENSE_TOKEN

# --- 2. cluster ------------------------------------------------------------
if kind get clusters 2>/dev/null | grep -qx "$KIND_CLUSTER_NAME"; then
  log "kind cluster $KIND_CLUSTER_NAME already exists"
else
  log "creating kind cluster $KIND_CLUSTER_NAME ($KIND_NODE_IMAGE)"
  sed "s|image: kindest/node:.*|image: ${KIND_NODE_IMAGE}|" "$HERE/kind-config.yaml" \
    | kind create cluster --name "$KIND_CLUSTER_NAME" --config -
fi

# On a CI runner that itself runs in a container and shares the host Docker
# socket, kind writes a kubeconfig pointing at 127.0.0.1 on the host, which is
# unreachable from in here. Repoint it at the control-plane container address.
if ! k cluster-info >/dev/null 2>&1; then
  log "kubeconfig unreachable, switching to the kind network address"
  docker network connect kind "$(hostname)" 2>/dev/null || true
  CP_IP="$(docker inspect -f '{{.NetworkSettings.Networks.kind.IPAddress}}' "${KIND_CLUSTER_NAME}-control-plane")"
  kubectl config set-cluster "$KCTX" --server="https://${CP_IP}:6443"
  k cluster-info >/dev/null
fi

# --- 3. proxy image --------------------------------------------------------
# The published image is amd64-only and kind nodes carry no binfmt emulation,
# so the image must be built for the node architecture and side-loaded.
ARCH="$(docker info --format '{{.Architecture}}')"
case "$ARCH" in
  x86_64|amd64) PLATFORM=linux/amd64 ;;
  aarch64|arm64) PLATFORM=linux/arm64 ;;
  *) echo "unsupported docker architecture: $ARCH" >&2; exit 1 ;;
esac
log "building proxy image $PROXY_IMAGE for $PLATFORM"
BUILD_ARGS=(
  --build-arg BUILD_NUMBER=e2e
  --build-arg "GIT_COMMIT=$(git -C "$REPO" rev-parse --short HEAD 2>/dev/null || echo unknown)"
  --build-arg "BUILD_TIME=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  -f "$REPO/Containerfile" -t "$PROXY_IMAGE" "$REPO"
)
if docker buildx version >/dev/null 2>&1; then
  docker buildx build --platform "$PLATFORM" --load "${BUILD_ARGS[@]}"
else
  # No buildx: the plain builder only produces the host architecture, which is
  # what the kind node needs anyway.
  docker build "${BUILD_ARGS[@]}"
fi
log "loading image into kind"
kind load docker-image "$PROXY_IMAGE" --name "$KIND_CLUSTER_NAME"

# --- 4. MinIO backend ------------------------------------------------------
log "installing MinIO"
k create namespace "$MINIO_NAMESPACE" --dry-run=client -o yaml | k apply -f -
# MinIO looks for public.crt/private.key in --certs-dir.
k -n "$MINIO_NAMESPACE" create secret generic minio-tls \
  --from-file=public.crt="$REPO/test/ssl-setup/public.crt" \
  --from-file=private.key="$REPO/test/ssl-setup/private.key" \
  --dry-run=client -o yaml | k apply -f -
# A Job spec is immutable, so a re-run has to replace it rather than apply over
# it. The bucket lives in an emptyDir, so the Job must run again anyway after a
# MinIO restart.
k -n "$MINIO_NAMESPACE" delete job minio-mkbucket --ignore-not-found --wait=true
k apply -f "$HERE/manifests/minio.yaml"
k -n "$MINIO_NAMESPACE" rollout status deploy/minio --timeout=5m
k -n "$MINIO_NAMESPACE" wait --for=condition=complete job/minio-mkbucket --timeout=3m

# --- 5. CSI hostpath driver + snapshotter ----------------------------------
RAW_SNAP="https://raw.githubusercontent.com/kubernetes-csi/external-snapshotter/${SNAPSHOTTER_VERSION}"
# kubernetes-latest and kubernetes-1.35 are git symlinks upstream; a raw URL to
# them returns the link target as plain text, not YAML.
RAW_HP="https://raw.githubusercontent.com/kubernetes-csi/csi-driver-host-path/${CSI_HOSTPATH_VERSION}"

log "installing snapshot CRDs and controller"
for c in volumesnapshotclasses volumesnapshotcontents volumesnapshots; do
  k apply --server-side -f "$RAW_SNAP/client/config/crd/snapshot.storage.k8s.io_${c}.yaml"
done
k apply -f "$RAW_SNAP/deploy/kubernetes/snapshot-controller/rbac-snapshot-controller.yaml"
k apply -f "$RAW_SNAP/deploy/kubernetes/snapshot-controller/setup-snapshot-controller.yaml"
k -n kube-system scale deploy/snapshot-controller --replicas=1
k -n kube-system rollout status deploy/snapshot-controller --timeout=5m

log "installing CSI sidecar RBAC"
k apply -f "https://raw.githubusercontent.com/kubernetes-csi/external-attacher/${CSI_ATTACHER_VERSION}/deploy/kubernetes/rbac.yaml"
k apply -f "https://raw.githubusercontent.com/kubernetes-csi/external-provisioner/${CSI_PROVISIONER_VERSION}/deploy/kubernetes/rbac.yaml"
k apply -f "https://raw.githubusercontent.com/kubernetes-csi/external-resizer/${CSI_RESIZER_VERSION}/deploy/kubernetes/rbac.yaml"
k apply -f "https://raw.githubusercontent.com/kubernetes-csi/external-health-monitor/${CSI_HEALTH_MONITOR_VERSION}/deploy/kubernetes/external-health-monitor-controller/rbac.yaml"
k apply -f "$RAW_SNAP/deploy/kubernetes/csi-snapshotter/rbac-csi-snapshotter.yaml"

log "installing csi-driver-host-path"
k apply -f "$RAW_HP/deploy/kubernetes-1.34/hostpath/csi-hostpath-driverinfo.yaml"
k apply -f "$RAW_HP/deploy/kubernetes-1.34/hostpath/csi-hostpath-plugin.yaml"
k -n default rollout status statefulset/csi-hostpathplugin --timeout=8m
k apply -f "$RAW_HP/examples/csi-storageclass.yaml"
k apply -f "$HERE/manifests/snapshotclass.yaml"

# --- 6. proxy --------------------------------------------------------------
log "installing s3-encryption-proxy"
k create namespace "$PROXY_NAMESPACE" --dry-run=client -o yaml | k apply -f -
k -n "$PROXY_NAMESPACE" create secret tls s3ep-tls \
  --cert="$REPO/test/ssl-setup/public.crt" \
  --key="$REPO/test/ssl-setup/private.key" \
  --dry-run=client -o yaml | k apply -f -
k -n "$PROXY_NAMESPACE" create secret generic s3ep-ca \
  --from-file=ca.crt="$REPO/test/ssl-setup/ca.crt" \
  --dry-run=client -o yaml | k apply -f -
k -n "$PROXY_NAMESPACE" create secret generic s3ep-license \
  --from-literal=license.jwt="$S3EP_LICENSE_TOKEN" \
  --dry-run=client -o yaml | k apply -f -

# A previous run that was interrupted mid-install leaves the release in
# pending-install and every later upgrade fails with "another operation is in
# progress". Clear that state rather than making the operator do it by hand.
if helm --kube-context "$KCTX" -n "$PROXY_NAMESPACE" list -a -o json 2>/dev/null \
     | grep -q '"status":"pending-'; then
  log "clearing a stuck helm release for $PROXY_RELEASE"
  helm --kube-context "$KCTX" -n "$PROXY_NAMESPACE" uninstall "$PROXY_RELEASE" --wait || true
fi

helm --kube-context "$KCTX" upgrade --install "$PROXY_RELEASE" "$REPO/deploy/helm/s3-encryption-proxy" \
  -n "$PROXY_NAMESPACE" -f "$HERE/values-proxy.yaml" \
  --set-string "image.tag=${PROXY_IMAGE##*:}" \
  --wait --timeout 5m
# The chart has no checksum/config annotation, so a config change on an existing
# release updates the ConfigMap without restarting the pods.
k -n "$PROXY_NAMESPACE" rollout restart deploy/s3ep-proxy
k -n "$PROXY_NAMESPACE" rollout status deploy/s3ep-proxy --timeout=5m
k apply -f "$HERE/manifests/proxy-nodeport.yaml"

# --- 7. Velero -------------------------------------------------------------
log "installing Velero ${VELERO_VERSION} (chart ${VELERO_CHART_VERSION})"
k create namespace "$VELERO_NAMESPACE" --dry-run=client -o yaml | k apply -f -

CREDS="$(mktemp)"
cat > "$CREDS" <<EOF
[default]
aws_access_key_id=${PROXY_CLIENT_ACCESS_KEY}
aws_secret_access_key=${PROXY_CLIENT_SECRET_KEY}
EOF
k -n "$VELERO_NAMESPACE" create secret generic velero-s3ep-credentials \
  --from-file=cloud="$CREDS" --dry-run=client -o yaml | k apply -f -

helm repo add vmware-tanzu https://vmware-tanzu.github.io/helm-charts >/dev/null 2>&1 || true
helm repo update vmware-tanzu >/dev/null

# Render the values file from versions.env rather than passing --set for list
# elements: --set on an index of a list defined in a values file replaces the
# whole element, which silently drops the volumeMounts of the plugin init
# container.
CA_B64="$(base64 < "$REPO/test/ssl-setup/ca.crt" | tr -d '\n')"
VELERO_VALUES="$(mktemp)"
trap 'rm -f "$CREDS" "$VELERO_VALUES"' EXIT
sed -e "s|^  tag: v.*|  tag: ${VELERO_VERSION}|" \
    -e "s|velero/velero-plugin-for-aws:.*|velero/velero-plugin-for-aws:${VELERO_AWS_PLUGIN_VERSION}|" \
    -e "s|^      bucket: .*|      bucket: ${VELERO_BUCKET}|" \
    -e "s|^      caCert: \"\"|      caCert: \"${CA_B64}\"|" \
    "$HERE/values-velero.yaml" > "$VELERO_VALUES"

grep -q "tag: ${VELERO_VERSION}" "$VELERO_VALUES" || { echo "velero image tag substitution failed" >&2; exit 1; }
grep -q "velero-plugin-for-aws:${VELERO_AWS_PLUGIN_VERSION}" "$VELERO_VALUES" || { echo "plugin tag substitution failed" >&2; exit 1; }
grep -q "caCert: \"${CA_B64}\"" "$VELERO_VALUES" || { echo "caCert substitution failed" >&2; exit 1; }

helm --kube-context "$KCTX" upgrade --install velero vmware-tanzu/velero \
  --version "$VELERO_CHART_VERSION" -n "$VELERO_NAMESPACE" \
  -f "$VELERO_VALUES" \
  --wait --timeout 10m

k -n "$VELERO_NAMESPACE" rollout status deploy/velero --timeout=5m
k -n "$VELERO_NAMESPACE" rollout status daemonset/node-agent --timeout=5m

log "waiting for the BackupStorageLocation to go Available"
for i in $(seq 1 60); do
  phase="$(k -n "$VELERO_NAMESPACE" get backupstoragelocation default -o jsonpath='{.status.phase}' 2>/dev/null || true)"
  [ "$phase" = "Available" ] && break
  if [ "$i" = 60 ]; then
    echo "BSL never became Available (last phase: ${phase:-<none>})" >&2
    k -n "$VELERO_NAMESPACE" get backupstoragelocation default -o yaml >&2 || true
    k -n "$VELERO_NAMESPACE" logs deploy/velero --tail=100 >&2 || true
    exit 1
  fi
  sleep 5
done

log "environment ready"
k get pods -A --field-selector=status.phase!=Running 2>/dev/null | head -20 || true
cat <<EOF

  cluster       kind-${KIND_CLUSTER_NAME}
  proxy         https://127.0.0.1:${PROXY_NODEPORT}  (in-cluster: https://s3ep-proxy.${PROXY_NAMESPACE}.svc.cluster.local:8443)
  minio         https://127.0.0.1:${MINIO_NODEPORT}
  velero        namespace ${VELERO_NAMESPACE}, BSL default Available

  run the suite:   make test-e2e-velero
  tear down:       make e2e-down
EOF
