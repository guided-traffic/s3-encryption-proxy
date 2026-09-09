# Helm Chart Fix Ticket

> 27 nodes · cohesion 0.10

## Key Concepts

- **Ticket 016: Helm chart fixes** (12 connections) — `docs/tickets/016-helm-chart-fixes.md`
- **Helm values for the proxy under e2e test** (8 connections) — `test/e2e/velero/values-proxy.yaml`
- **In-cluster MinIO backend over HTTPS** (5 connections) — `test/e2e/velero/manifests/minio.yaml`
- **Velero Helm values for the e2e cluster** (5 connections) — `test/e2e/velero/values-velero.yaml`
- **D-6: refuse a plain-HTTP backend under an encrypting provider** (4 connections) — `docs/tickets/015-configuration-hygiene.md`
- **The e2e values file ships a committed working AES-256 KEK** (4 connections) — `docs/tickets/016-helm-chart-fixes.md`
- **s3ep-proxy-nodeport Service pinned to 30443** (4 connections) — `test/e2e/velero/manifests/proxy-nodeport.yaml`
- **Tier 6: honest measurement (baselines, parallel and small-object benchmarks)** (3 connections) — `docs/tickets/012-performance-audit-round2.md`
- **The example configs carry working key material by design** (3 connections) — `docs/tickets/022-s3-surface-fidelity.md`
- **Host port mappings 30443 (proxy HTTPS) and 30900 (MinIO S3)** (3 connections) — `test/e2e/velero/kind-config.yaml`
- **TLS is required because the SDK only allows UNSIGNED-PAYLOAD over TLS** (3 connections) — `test/e2e/velero/manifests/minio.yaml`
- **Committed aes_key literal in the e2e proxy config** (3 connections) — `test/e2e/velero/values-proxy.yaml`
- **BackupStorageLocation pointing s3Url at the proxy** (3 connections) — `test/e2e/velero/values-velero.yaml`
- **D-7: s3_security.max_presign_expiry_seconds** (2 connections) — `docs/tickets/015-configuration-hygiene.md`
- **Item 7: no workflow renders the chart, which is why items 2 and 6 survived** (2 connections) — `docs/tickets/016-helm-chart-fixes.md`
- **Items 8 and 9: the specified e2e health check and Velero log scan were never built** (2 connections) — `docs/tickets/016-helm-chart-fixes.md`
- **Item 5: the Service cannot pin a NodePort** (2 connections) — `docs/tickets/016-helm-chart-fixes.md`
- **Item 2: values-development.yaml and values-monitoring.yaml cannot be rendered** (2 connections) — `docs/tickets/016-helm-chart-fixes.md`
- **Item 3: probes have no scheme, so pod TLS means the pod never goes Ready** (2 connections) — `docs/tickets/016-helm-chart-fixes.md`
- **N-10: the Helm chart shipped a working AES-256 KEK as its default** (2 connections) — `docs/tickets/README.md`
- **emptyDir data volume so the backend does not depend on the CSI driver under test** (2 connections) — `test/e2e/velero/manifests/minio.yaml`
- **SSL_CERT_FILE points Go's root pool at the test CA instead of skipping verification** (2 connections) — `test/e2e/velero/values-proxy.yaml`
- **Probe scheme HTTPS, affinity null, pullPolicy Never** (2 connections) — `test/e2e/velero/values-proxy.yaml`
- **publicUrl 127.0.0.1:30443 for pre-signed URLs fetched by the host CLI** (2 connections) — `test/e2e/velero/values-velero.yaml`
- **kind cluster s3ep-e2e** (1 connections) — `test/e2e/velero/kind-config.yaml`
- *... and 2 more nodes in this community*

## Relationships

- [Configuration Hygiene Ticket](Configuration_Hygiene_Ticket.md) (4 shared connections)
- [S3 Surface Fidelity Ticket](S3_Surface_Fidelity_Ticket.md) (3 shared connections)
- [Filename Encryption Ticket](Filename_Encryption_Ticket.md) (3 shared connections)
- [Performance Audit Round Two](Performance_Audit_Round_Two.md) (2 shared connections)
- [Coverage Round Findings](Coverage_Round_Findings.md) (2 shared connections)
- [Major V5 Work List](Major_V5_Work_List.md) (1 shared connections)

## Source Files

- `docs/tickets/012-performance-audit-round2.md`
- `docs/tickets/015-configuration-hygiene.md`
- `docs/tickets/016-helm-chart-fixes.md`
- `docs/tickets/022-s3-surface-fidelity.md`
- `docs/tickets/README.md`
- `test/e2e/velero/kind-config.yaml`
- `test/e2e/velero/manifests/minio.yaml`
- `test/e2e/velero/manifests/proxy-nodeport.yaml`
- `test/e2e/velero/values-proxy.yaml`
- `test/e2e/velero/values-velero.yaml`

## Audit Trail

- EXTRACTED: 44 (88%)
- INFERRED: 6 (12%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*