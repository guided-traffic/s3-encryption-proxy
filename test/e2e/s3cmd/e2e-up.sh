#!/usr/bin/env bash
# Brings up everything the s3cmd e2e suite needs: the pinned s3cmd and the demo
# compose stack. See test/e2e/rclone/e2e-up.sh for why the environment lives in a
# script rather than in TestMain.
#
# Idempotent: safe to re-run.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"
# shellcheck disable=SC1091
source "$HERE/versions.env"

log() { printf '\033[0;34m==>\033[0m %s\n' "$*"; }

need() { command -v "$1" >/dev/null 2>&1 || { echo "missing required tool: $1" >&2; exit 1; }; }
for t in docker curl openssl python3; do need "$t"; done

# --- the client -------------------------------------------------------------

# s3cmd is a Python program and its one hard runtime dependency, python-dateutil,
# is not in the tarball. A virtual environment is therefore the reproducible
# install: it pins s3cmd and resolves that dependency, and it puts neither on the
# developer's system Python.
#
# python-magic is in s3cmd's install_requires but needs the libmagic C library,
# which pip does not ship. s3cmd falls back to extension-based MIME guessing and
# warns once per run; the suite passes --no-mime-magic instead of installing a
# system library for a MIME type no assertion looks at.
VENV="$HERE/venv"
BIN="$VENV/bin/s3cmd"
install_s3cmd() {
  if [ -x "$BIN" ] && "$BIN" --version 2>/dev/null | grep -qF "$S3CMD_VERSION"; then
    log "s3cmd $S3CMD_VERSION already installed"
    return
  fi
  log "installing s3cmd $S3CMD_VERSION into $VENV"
  rm -rf "$VENV"
  python3 -m venv "$VENV"
  local attempt
  for attempt in 1 2 3; do
    if "$VENV/bin/pip" install --quiet --disable-pip-version-check "s3cmd==$S3CMD_VERSION"; then break; fi
    if [ "$attempt" = 3 ]; then
      echo "could not install s3cmd==$S3CMD_VERSION after three attempts" >&2
      exit 1
    fi
    echo "pip install failed (attempt $attempt/3), retrying..." >&2
    sleep $((attempt * 5))
  done
  "$BIN" --version
}
install_s3cmd

# --- the stack --------------------------------------------------------------

log "ensuring test PKI"
"$REPO/test/ssl-setup/gen-certs.sh" --if-needed

log "ensuring local key material"
"$REPO/scripts/gen-keys.sh" --if-needed

if [ -z "${S3EP_LICENSE_TOKEN:-}" ]; then
  if [ -f "$REPO/config/license.jwt" ]; then
    S3EP_LICENSE_TOKEN="$(tr -d '\n' < "$REPO/config/license.jwt")"
  else
    echo "S3EP_LICENSE_TOKEN is unset and config/license.jwt is missing" >&2
    echo "export S3EP_LICENSE_TOKEN, or place a token at config/license.jwt" >&2
    exit 1
  fi
fi
export S3EP_LICENSE_TOKEN

log "starting the demo stack"
(cd "$REPO" && ./start-demo.sh)

# shellcheck disable=SC1091
source "$REPO/test/e2e/harness/demo-stack.env"

wait_for() {
  local name="$1" url="$2" ca="${3:-}" i
  for i in $(seq 1 60); do
    if [ -n "$ca" ]; then
      curl -fsS --cacert "$ca" -o /dev/null "$url" 2>/dev/null && { log "$name is up"; return; }
    else
      curl -fsS -o /dev/null "$url" 2>/dev/null && { log "$name is up"; return; }
    fi
    sleep 2
  done
  echo "$name did not answer at $url" >&2
  docker logs proxy 2>&1 | tail -30 >&2 || true
  docker logs proxy-tls 2>&1 | tail -30 >&2 || true
  exit 1
}

CA="$REPO/$S3EP_CA_CERT"
wait_for "the proxy (http)" "${S3EP_HTTP_ENDPOINT}/health"
wait_for "the proxy (tls)" "${S3EP_TLS_ENDPOINT}/health" "$CA"
wait_for "MinIO" "${S3EP_BACKEND_ENDPOINT}/minio/health/live" "$CA"

log "ready. Run: make test-e2e-s3cmd"
