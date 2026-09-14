#!/usr/bin/env bash
# Brings up everything the rclone e2e suite needs: the pinned rclone binary and
# the demo compose stack.
#
# The environment deliberately lives here and not in TestMain: a bring-up inside
# a Go test makes every infrastructure problem look like a test failure, and it
# prevents iterating against a warm stack.
#
# Idempotent: safe to re-run. It keeps an rclone that already matches the pin and
# hands the stack to ./start-demo.sh, which rebuilds the proxy image so a code
# change can be retested without recreating anything.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"
# shellcheck disable=SC1091
source "$HERE/versions.env"

log() { printf '\033[0;34m==>\033[0m %s\n' "$*"; }

need() { command -v "$1" >/dev/null 2>&1 || { echo "missing required tool: $1" >&2; exit 1; }; }
for t in docker curl unzip openssl; do need "$t"; done

# --- the client -------------------------------------------------------------

# rclone publishes darwin builds under "osx", not "darwin": the darwin-named
# asset does not exist and the download 404s.
case "$(uname -s)" in
  Linux)  RCLONE_OS=linux ;;
  Darwin) RCLONE_OS=osx ;;
  *) echo "unsupported operating system: $(uname -s)" >&2; exit 1 ;;
esac
case "$(uname -m)" in
  x86_64|amd64) RCLONE_ARCH=amd64 ;;
  arm64|aarch64) RCLONE_ARCH=arm64 ;;
  *) echo "unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

BIN="$HERE/bin/rclone"
install_rclone() {
  if [ -x "$BIN" ] && "$BIN" version 2>/dev/null | head -1 | grep -qF "$RCLONE_VERSION"; then
    log "rclone $RCLONE_VERSION already installed"
    return
  fi
  local name="rclone-${RCLONE_VERSION}-${RCLONE_OS}-${RCLONE_ARCH}"
  local url="https://downloads.rclone.org/${RCLONE_VERSION}/${name}.zip"
  local tmp
  tmp="$(mktemp -d)"

  log "installing rclone $RCLONE_VERSION ($RCLONE_OS/$RCLONE_ARCH)"
  # Three attempts: a download is the one step here that depends on a third
  # party being up, and a single 502 must not fail a release gate over something
  # unrelated to the change under test.
  local attempt
  for attempt in 1 2 3; do
    if curl -fsSL -o "$tmp/rclone.zip" "$url"; then break; fi
    if [ "$attempt" = 3 ]; then
      rm -rf "$tmp"
      echo "could not download $url after three attempts" >&2
      exit 1
    fi
    echo "download failed (attempt $attempt/3), retrying..." >&2
    sleep $((attempt * 5))
  done

  unzip -oq "$tmp/rclone.zip" -d "$tmp"
  mkdir -p "$HERE/bin"
  install -m 0755 "$tmp/$name/rclone" "$BIN"
  rm -rf "$tmp"
  "$BIN" version | head -1
}
install_rclone

# --- the stack --------------------------------------------------------------

log "ensuring test PKI"
"$REPO/test/ssl-setup/gen-certs.sh" --if-needed

log "ensuring local key material"
"$REPO/scripts/gen-keys.sh" --if-needed

# The proxy refuses to start under an encrypting provider without a licence, and
# the whole suite is about an encrypting provider. start-demo.sh only warns, so
# the abort belongs here.
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

log "ready. Run: make test-e2e-rclone"
