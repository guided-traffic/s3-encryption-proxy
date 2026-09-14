#!/usr/bin/env bash
# Generates the local key material the demo stack, the integration suite and the
# Velero e2e cluster need, and writes it to the repository's .env file, which is
# ignored (ADR 0021). No usable key is tracked in this repository, so a fresh
# clone has none and every consumer calls this first.
#
# Docker Compose loads .env from the project directory on its own, so the demo
# stack needs nothing beyond this file existing. Other consumers source it.
#
# Variables produced:
#   S3EP_AES_KEY          the key every example configuration and values file
#                         references as ${S3EP_AES_KEY}
#   S3EP_AES_KEY_RETIRED  the second key of the rotation example, which needs two
#                         providers to demonstrate reading under a retired key
#
# --if-needed: keep a variable that is already present. A restarted stack must
# still read what it wrote before, so regenerating unconditionally would make
# every previously stored object unreadable.
set -euo pipefail

cd "$(dirname "$0")/.."
ENV_FILE=".env"

IF_NEEDED=0
[ "${1:-}" = "--if-needed" ] && IF_NEEDED=1

touch "$ENV_FILE"

# A key is base64 of 32 random bytes; `make build-keygen && ./build/s3ep-keygen`
# produces the same thing for an operator who wants one by hand.
generate_key() {
  openssl rand -base64 32
}

ensure_var() {
  local name="$1"
  if grep -q "^${name}=" "$ENV_FILE" 2>/dev/null; then
    if [ "$IF_NEEDED" = "1" ]; then
      echo "${name} already present in ${ENV_FILE}, keeping it"
      return
    fi
    # Replacing a key makes every object written under it unreadable. Say so
    # rather than doing it silently.
    echo "${name} already present in ${ENV_FILE}; refusing to replace it." >&2
    echo "Remove the line by hand if you really mean to lose access to the data written under it." >&2
    exit 1
  fi
  printf '%s=%s\n' "$name" "$(generate_key)" >> "$ENV_FILE"
  echo "generated ${name}"
}

ensure_var S3EP_AES_KEY
ensure_var S3EP_AES_KEY_RETIRED

chmod 600 "$ENV_FILE"
