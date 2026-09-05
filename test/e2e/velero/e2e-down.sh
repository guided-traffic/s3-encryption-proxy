#!/usr/bin/env bash
# Deletes the kind cluster created by e2e-up.sh.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck disable=SC1091
source "$HERE/versions.env"
if kind get clusters 2>/dev/null | grep -qx "$KIND_CLUSTER_NAME"; then
  echo "deleting kind cluster $KIND_CLUSTER_NAME"
  kind delete cluster --name "$KIND_CLUSTER_NAME"
else
  echo "kind cluster $KIND_CLUSTER_NAME does not exist"
fi
