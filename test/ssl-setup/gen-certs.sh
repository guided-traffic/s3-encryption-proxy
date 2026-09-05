#!/usr/bin/env bash
# Regenerates the self-signed PKI used by the demo compose stack, the
# integration suite and the Velero e2e cluster.
#
# A real CA is generated on purpose: Velero validates the BackupStorageLocation
# certificate against the caCert it is given, and Go only accepts a certificate
# in the root pool as its own issuer when BasicConstraints says CA:TRUE. A bare
# self-signed leaf therefore cannot be used as caCert.
#
# Outputs (all in this directory):
#   ca.crt / ca.key           the CA, handed to clients as the trust anchor
#   public.crt / private.key  server certificate, used by MinIO and by the proxy
#   minio.crt / minio.key     same certificate under the names MinIO documents
set -euo pipefail

cd "$(dirname "$0")"

DAYS_CA=3650
# Apple's platform policy rejects any leaf certificate with a validity longer
# than 398 days, and Go on darwin verifies through Security.framework. A longer
# leaf fails with "certificate is not standards compliant" on macOS while
# working fine on Linux, so keep it under the limit and regenerate yearly.
DAYS_LEAF=397

# --if-needed: regenerate only when the certificate is missing or expires within
# 30 days. Used by the e2e bring-up so a stale local checkout heals itself.
if [ "${1:-}" = "--if-needed" ] && [ -f public.crt ] && [ -f ca.crt ]; then
  if openssl x509 -in public.crt -noout -checkend $((30 * 86400)) >/dev/null 2>&1; then
    echo "certificates still valid for more than 30 days, keeping them"
    exit 0
  fi
  echo "certificate expires within 30 days, regenerating"
fi

cat > san.cnf <<'EOF'
[req]
distinguished_name = dn
req_extensions     = v3_req
prompt             = no

[dn]
C  = DE
ST = State
L  = City
O  = Organization
OU = Organizational Unit
CN = localhost

[v3_req]
basicConstraints = CA:FALSE
keyUsage         = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName   = @alt_names

[alt_names]
# demo compose stack
DNS.1  = localhost
DNS.2  = minio
DNS.3  = s3-encryption-proxy
DNS.4  = s3-encryption-proxy-tls
# kind e2e cluster: the proxy Service (fullnameOverride s3ep-proxy, namespace
# s3ep) in every form kube DNS resolves, plus the MinIO backend Service.
DNS.5  = s3ep-proxy
DNS.6  = s3ep-proxy.s3ep
DNS.7  = s3ep-proxy.s3ep.svc
DNS.8  = s3ep-proxy.s3ep.svc.cluster.local
DNS.9  = minio
DNS.10 = minio.minio
DNS.11 = minio.minio.svc
DNS.12 = minio.minio.svc.cluster.local
DNS.13 = *.s3ep.svc.cluster.local
DNS.14 = *.minio.svc.cluster.local
IP.1   = 127.0.0.1
EOF

# CA
openssl req -x509 -newkey rsa:2048 -nodes -days "$DAYS_CA" \
  -keyout ca.key -out ca.crt \
  -subj "/C=DE/ST=State/L=City/O=Organization/OU=Test CA/CN=s3ep-test-ca" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null

# Server certificate signed by that CA
openssl req -newkey rsa:2048 -nodes -keyout private.key -out server.csr \
  -config san.cnf 2>/dev/null
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out public.crt -days "$DAYS_LEAF" -sha256 \
  -extfile san.cnf -extensions v3_req 2>/dev/null

# MinIO documents certs as public.crt/private.key; the *.crt/*.key duplicates
# are kept because existing tooling references them.
cp public.crt minio.crt
cp private.key minio.key

rm -f server.csr ca.srl san.cnf
chmod 644 ./*.crt ./*.key

echo "Regenerated PKI in $(pwd):"
openssl x509 -in public.crt -noout -subject -dates -ext subjectAltName
