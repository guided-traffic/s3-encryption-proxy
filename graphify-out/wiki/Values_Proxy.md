# Values Proxy

> 14 nodes · cohesion 0.15

## Key Concepts

- **Velero e2e Proxy Helm Values** (8 connections) — `test/e2e/velero/values-proxy.yaml`
- **Embedded Proxy Configuration for the Velero Run** (3 connections) — `test/e2e/velero/values-proxy.yaml`
- **Probe Scheme Is Derived, Never Stated** (3 connections) — `test/e2e/velero/values-proxy.yaml`
- **AES Key via Chart Secret Wiring (s3ep-aes-key)** (2 connections) — `test/e2e/velero/values-proxy.yaml`
- **S3EP_LICENSE_TOKEN from Secret s3ep-license** (2 connections) — `test/e2e/velero/values-proxy.yaml`
- **serviceTLS with the Test PKI Secret s3ep-tls** (2 connections) — `test/e2e/velero/values-proxy.yaml`
- **Missing License Token Blocks Every Instrument** (2 connections) — `test/perf/README.md`
- **affinity Must Be null, Not {}** (1 connections) — `test/e2e/velero/values-proxy.yaml`
- **Backend CA Mount and SSL_CERT_FILE** (1 connections) — `test/e2e/velero/values-proxy.yaml`
- **json log_format for Exact Error-Level Matching** (1 connections) — `test/e2e/velero/values-proxy.yaml`
- **livenessProbe /livez** (1 connections) — `test/e2e/velero/values-proxy.yaml`
- **NodePort 30443 for the Velero publicUrl** (1 connections) — `test/e2e/velero/values-proxy.yaml`
- **image.pullPolicy Never — Side-Loaded Local Image** (1 connections) — `test/e2e/velero/values-proxy.yaml`
- **readinessProbe /readyz** (1 connections) — `test/e2e/velero/values-proxy.yaml`

## Relationships

- [Readme](Readme.md) (1 shared connections)

## Source Files

- `test/e2e/velero/values-proxy.yaml`
- `test/perf/README.md`

## Audit Trail

- EXTRACTED: 14 (93%)
- INFERRED: 1 (7%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*