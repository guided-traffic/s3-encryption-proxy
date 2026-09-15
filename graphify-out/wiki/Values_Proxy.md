# Values Proxy

> 20 nodes · cohesion 0.12

## Key Concepts

- **Velero e2e Proxy Helm Values** (8 connections) — `test/e2e/velero/values-proxy.yaml`
- **In-Cluster MinIO Backend** (6 connections) — `test/e2e/velero/manifests/minio.yaml`
- **Embedded Proxy Configuration for the Velero Run** (5 connections) — `test/e2e/velero/values-proxy.yaml`
- **minio-root Credentials Secret** (3 connections) — `test/e2e/velero/manifests/minio.yaml`
- **UNSIGNED-PAYLOAD Requires TLS on the Backend Leg** (3 connections) — `test/e2e/velero/manifests/minio.yaml`
- **Probe Scheme Is Derived, Never Stated** (3 connections) — `test/e2e/velero/values-proxy.yaml`
- **minio-mkbucket Job (velero Bucket)** (2 connections) — `test/e2e/velero/manifests/minio.yaml`
- **minio-tls Certificate Secret** (2 connections) — `test/e2e/velero/manifests/minio.yaml`
- **AES Key via Chart Secret Wiring (s3ep-aes-key)** (2 connections) — `test/e2e/velero/values-proxy.yaml`
- **Backend CA Mount and SSL_CERT_FILE** (2 connections) — `test/e2e/velero/values-proxy.yaml`
- **S3EP_LICENSE_TOKEN from Secret s3ep-license** (2 connections) — `test/e2e/velero/values-proxy.yaml`
- **serviceTLS with the Test PKI Secret s3ep-tls** (2 connections) — `test/e2e/velero/values-proxy.yaml`
- **Missing License Token Blocks Every Instrument** (2 connections) — `test/perf/README.md`
- **minio-nodeport Service (30900)** (1 connections) — `test/e2e/velero/manifests/minio.yaml`
- **affinity Must Be null, Not {}** (1 connections) — `test/e2e/velero/values-proxy.yaml`
- **json log_format for Exact Error-Level Matching** (1 connections) — `test/e2e/velero/values-proxy.yaml`
- **livenessProbe /livez** (1 connections) — `test/e2e/velero/values-proxy.yaml`
- **NodePort 30443 for the Velero publicUrl** (1 connections) — `test/e2e/velero/values-proxy.yaml`
- **image.pullPolicy Never — Side-Loaded Local Image** (1 connections) — `test/e2e/velero/values-proxy.yaml`
- **readinessProbe /readyz** (1 connections) — `test/e2e/velero/values-proxy.yaml`

## Relationships

- [Cryptofloor](Cryptofloor.md) (1 shared connections)
- [Throughput](Throughput.md) (1 shared connections)
- [Readme](Readme.md) (1 shared connections)

## Source Files

- `test/e2e/velero/manifests/minio.yaml`
- `test/e2e/velero/values-proxy.yaml`
- `test/perf/README.md`

## Audit Trail

- EXTRACTED: 22 (85%)
- INFERRED: 4 (15%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*