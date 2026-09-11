#!/usr/bin/env bash
#
# Run the conformance suite against one backend (ADR 0027).
#
#   scripts/conformance-run.sh <backend> [--seed|--clean]
#
#   minio        a standalone MinIO over TLS, started here. Free.
#   localstack   LocalStack community, started here. Free. It models AWS account
#                ids, which no other free backend here does
#   wasabi       a paid third-party backend, credentials from local_wasabi_s3.
#                THIS ONE COSTS MONEY: it bills every written byte for a minimum
#                of ninety days and refunds nothing on delete
#
#   (no flag)    read only, writes nothing
#   --seed       write the corpus first, then run. Idempotent: a seeded bucket
#                costs nothing on a second pass
#   --clean      abort multipart uploads left under the suite's prefix.
#                Irreversible, scoped to that prefix
#
# Every backend gets its own proxy port and its own container name, so several
# can run at once on one machine — which is also how they run in continuous
# integration, one runner per backend, in parallel.
#
# The proxy refuses a plain-HTTP backend under a provider that encrypts
# (ADR 0013 D5), so every backend here is addressed over TLS. The two local ones
# serve a self-signed certificate and the configuration says so explicitly rather
# than the suite turning verification off globally.
set -euo pipefail

cd "$(dirname "$0")/.."

BACKEND="${1:-}"
MODE="${2:-run}"
case "$MODE" in
  --seed)  MODE=seed ;;
  --clean) MODE=clean ;;
  run)     ;;
  *) echo "usage: $0 <minio|localstack|wasabi> [--seed|--clean]" >&2; exit 1 ;;
esac

CONTAINER=""
INSECURE=false

case "$BACKEND" in
  minio)
    PROXY_PORT=8090
    CONTAINER="s3ep-conf-minio"
    export S3EP_CONFORMANCE_BACKEND_ENDPOINT="https://127.0.0.1:9100"
    export S3EP_CONFORMANCE_BACKEND_REGION="us-east-1"
    export S3EP_CONFORMANCE_BACKEND_ACCESS_KEY="minioadmin"
    export S3EP_CONFORMANCE_BACKEND_SECRET_KEY="minioadmin123"
    export S3EP_CONFORMANCE_BUCKET="s3ep-conformance"
    INSECURE=true
    ;;
  localstack)
    PROXY_PORT=8091
    CONTAINER="s3ep-conf-localstack"
    export S3EP_CONFORMANCE_BACKEND_ENDPOINT="https://127.0.0.1:4566"
    export S3EP_CONFORMANCE_BACKEND_REGION="us-east-1"
    export S3EP_CONFORMANCE_BACKEND_ACCESS_KEY="test"
    export S3EP_CONFORMANCE_BACKEND_SECRET_KEY="test"
    export S3EP_CONFORMANCE_BUCKET="s3ep-conformance"
    INSECURE=true
    ;;
  wasabi)
    PROXY_PORT=8092
    # Credentials come from the environment when it carries them — that is how
    # continuous integration injects its secrets — and otherwise from a
    # gitignored file, which is how a workstation carries them. Neither is ever
    # written into this script or into the rendered proxy configuration.
    CRED_FILE="local_wasabi_s3"
    field() {
      local v
      [ -f "$CRED_FILE" ] || { echo "error: $CRED_FILE not found and \$$2 is not set." >&2; exit 1; }
      v="$(sed -n "s/^$1[[:space:]]*=[[:space:]]*//p" "$CRED_FILE" | head -n1 | tr -d '\r')"
      [ -n "$v" ] || { echo "error: $CRED_FILE has no '$1' and \$$2 is not set" >&2; exit 1; }
      printf '%s' "$v"
    }
    : "${S3EP_CONFORMANCE_BUCKET:=$(field bucket-name S3EP_CONFORMANCE_BUCKET)}"
    : "${S3EP_CONFORMANCE_BACKEND_REGION:=$(field region S3EP_CONFORMANCE_BACKEND_REGION)}"
    : "${S3EP_CONFORMANCE_BACKEND_ACCESS_KEY:=$(field access-key S3EP_CONFORMANCE_BACKEND_ACCESS_KEY)}"
    : "${S3EP_CONFORMANCE_BACKEND_SECRET_KEY:=$(field secret-key S3EP_CONFORMANCE_BACKEND_SECRET_KEY)}"
    : "${S3EP_CONFORMANCE_AES_KEY:=$(field aes-key S3EP_CONFORMANCE_AES_KEY)}"
    export S3EP_CONFORMANCE_BUCKET S3EP_CONFORMANCE_BACKEND_REGION
    export S3EP_CONFORMANCE_BACKEND_ACCESS_KEY S3EP_CONFORMANCE_BACKEND_SECRET_KEY
    export S3EP_CONFORMANCE_AES_KEY
    : "${S3EP_CONFORMANCE_BACKEND_ENDPOINT:=https://s3.${S3EP_CONFORMANCE_BACKEND_REGION}.wasabisys.com}"
    export S3EP_CONFORMANCE_BACKEND_ENDPOINT
    ;;
  *)
    echo "usage: $0 <minio|localstack|wasabi> [--seed|--clean]" >&2
    exit 1
    ;;
esac

export S3EP_CONFORMANCE_BACKEND_NAME="$BACKEND"
export S3EP_CONFORMANCE_PROXY_ENDPOINT="http://127.0.0.1:${PROXY_PORT}"

# A key encryption key that is stable for the life of the corpus. A stored object
# names the fingerprint of the key that wrapped it, so a fresh key would make an
# already seeded corpus unreadable. The two local backends are thrown away with
# their container, so a fixed development value is right for them; wasabi brings
# its own from the credential file.
: "${S3EP_CONFORMANCE_AES_KEY:=P2qLxK7vN8sR4tYwZ1aB3cD5eF6gH9jK0mN2pQ4rS6U=}"
export S3EP_CONFORMANCE_AES_KEY

WORK_DIR="build/conformance-${BACKEND}"
mkdir -p "$WORK_DIR"

echo "backend:  $BACKEND -> $S3EP_CONFORMANCE_BACKEND_ENDPOINT"
echo "bucket:   $S3EP_CONFORMANCE_BUCKET"
echo "proxy:    $S3EP_CONFORMANCE_PROXY_ENDPOINT"

PROXY_PID=""
cleanup() {
  [ -n "$PROXY_PID" ] && kill "$PROXY_PID" 2>/dev/null || true
  [ -n "$CONTAINER" ] && docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
}
trap cleanup EXIT

# --- the backend ------------------------------------------------------------
start_minio() {
  # MinIO serves TLS when it finds a certificate pair in its certs directory.
  # The test PKI is generated, never committed (ADR 0021).
  (cd test/ssl-setup && ./gen-certs.sh --if-needed >/dev/null)
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  docker run -d --name "$CONTAINER" -p 9100:9000 \
    -v "$PWD/test/ssl-setup/minio.crt:/root/.minio/certs/public.crt:ro" \
    -v "$PWD/test/ssl-setup/minio.key:/root/.minio/certs/private.key:ro" \
    -e MINIO_ROOT_USER=minioadmin -e MINIO_ROOT_PASSWORD=minioadmin123 \
    minio/minio:latest server /data >/dev/null
}

start_localstack() {
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  # Pinned to a community tag: localstack/localstack:latest now requires a
  # licence and exits on start without one.
  docker run -d --name "$CONTAINER" -p 4566:4566 -e SERVICES=s3 \
    localstack/localstack:3.8 >/dev/null
}

case "$BACKEND" in
  minio)      start_minio ;;
  localstack) start_localstack ;;
esac

if [ -n "$CONTAINER" ]; then
  for _ in $(seq 1 60); do
    if curl -sk -o /dev/null "$S3EP_CONFORMANCE_BACKEND_ENDPOINT" 2>/dev/null; then break; fi
    sleep 2
  done
  if ! curl -sk -o /dev/null "$S3EP_CONFORMANCE_BACKEND_ENDPOINT" 2>/dev/null; then
    echo "error: $BACKEND did not come up at $S3EP_CONFORMANCE_BACKEND_ENDPOINT" >&2
    docker logs "$CONTAINER" 2>&1 | tail -30 >&2
    exit 1
  fi
fi

# --- the proxy --------------------------------------------------------------
make build >/dev/null

# No secret is written into this file: every credential stays a ${VAR} reference
# that the proxy's own loader expands from the environment at startup.
cat > "$WORK_DIR/config.yaml" <<YAML
bind_address: "127.0.0.1:${PROXY_PORT}"
log_level: "info"
log_format: "text"
s3_backend:
  target_endpoint: "${S3EP_CONFORMANCE_BACKEND_ENDPOINT}"
  region: "${S3EP_CONFORMANCE_BACKEND_REGION}"
  access_key_id: "\${S3EP_CONFORMANCE_BACKEND_ACCESS_KEY}"
  secret_key: "\${S3EP_CONFORMANCE_BACKEND_SECRET_KEY}"
  insecure_skip_verify: ${INSECURE}
s3_clients:
  - type: "static"
    access_key_id: "username0"
    secret_key: "this-is-not-very-secure"
    description: "conformance suite"
optimizations:
  # The 5 MiB minimum rather than the 12 MiB default: it is the threshold above
  # which a PUT becomes the internal multipart producer, so lowering it halves
  # the bytes that path costs to exercise.
  streaming_segment_size: 5242880
encryption:
  encryption_method_alias: "conformance"
  providers:
    - alias: "conformance"
      type: "aes"
      config:
        aes_key: "\${S3EP_CONFORMANCE_AES_KEY}"
YAML

./build/s3-encryption-proxy --config "$WORK_DIR/config.yaml" > "$WORK_DIR/proxy.log" 2>&1 &
PROXY_PID=$!

for _ in $(seq 1 30); do
  curl -fsS "$S3EP_CONFORMANCE_PROXY_ENDPOINT/health" >/dev/null 2>&1 && break
  sleep 1
done
if ! curl -fsS "$S3EP_CONFORMANCE_PROXY_ENDPOINT/health" >/dev/null 2>&1; then
  echo "error: the proxy did not become healthy" >&2
  cat "$WORK_DIR/proxy.log" >&2
  exit 1
fi

# --- the suite --------------------------------------------------------------
GOTEST=(go test -tags=conformance -count=1 -v -timeout=30m ./test/integration/conformance)

if [ "$MODE" = "clean" ]; then
  echo
  echo "=== aborting multipart uploads under the suite's prefix (irreversible) ==="
  S3EP_CONFORMANCE_ABORT_DANGLING=1 "${GOTEST[@]}" -run TestAbortDanglingUploads
  exit 0
fi

if [ "$MODE" = "seed" ]; then
  echo
  if [ "$BACKEND" = "wasabi" ]; then
    echo "=== seeding $BACKEND (THIS WRITES BILLED BYTES; idempotent) ==="
  else
    echo "=== seeding $BACKEND ==="
  fi
  S3EP_CONFORMANCE_SEED=1 "${GOTEST[@]}" -run 'TestSeed$'
fi

echo
echo "=== conformance against $BACKEND (read only) ==="
"${GOTEST[@]}"
