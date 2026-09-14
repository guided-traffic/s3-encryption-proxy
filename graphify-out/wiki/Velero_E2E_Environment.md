# Velero E2E Environment

> 18 nodes · cohesion 0.13

## Key Concepts

- **Velero E2E Proxy Helm Values** (9 connections) — `test/e2e/velero/values-proxy.yaml`
- **In-cluster MinIO backend over HTTPS** (4 connections) — `test/e2e/velero/manifests/minio.yaml`
- **Velero Helm values for the e2e cluster** (4 connections) — `test/e2e/velero/values-velero.yaml`
- **Host port mappings 30443 (proxy HTTPS) and 30900 (MinIO S3)** (3 connections) — `test/e2e/velero/kind-config.yaml`
- **s3ep-proxy-nodeport Service pinned to 30443** (3 connections) — `test/e2e/velero/manifests/proxy-nodeport.yaml`
- **uploaderType kopia with EnableCSI and the node agent** (3 connections) — `test/e2e/velero/values-velero.yaml`
- **Velero E2E Suite in kind** (2 connections) — `CLAUDE.md`
- **Pod TLS Is Not a Chart Feature** (2 connections) — `deploy/helm/s3-encryption-proxy/README.md`
- **emptyDir data volume so the backend does not depend on the CSI driver under test** (2 connections) — `test/e2e/velero/manifests/minio.yaml`
- **csi-hostpath-snapclass with the Velero discovery label** (2 connections) — `test/e2e/velero/manifests/snapshotclass.yaml`
- **HTTPS Probe Scheme for the TLS Listener** (2 connections) — `test/e2e/velero/values-proxy.yaml`
- **BackupStorageLocation pointing s3Url at the proxy** (2 connections) — `test/e2e/velero/values-velero.yaml`
- **publicUrl 127.0.0.1:30443 for pre-signed URLs fetched by the host CLI** (2 connections) — `test/e2e/velero/values-velero.yaml`
- **Testing Strategy and Layers** (1 connections) — `CLAUDE.md`
- **kind cluster s3ep-e2e** (1 connections) — `test/e2e/velero/kind-config.yaml`
- **minio-mkbucket Job creating the velero bucket** (1 connections) — `test/e2e/velero/manifests/minio.yaml`
- **TLS is required because the SDK only allows UNSIGNED-PAYLOAD over TLS** (1 connections) — `test/e2e/velero/manifests/minio.yaml`
- **Explicit image.tag override so the chart appVersion cannot drift from versions.env** (1 connections) — `test/e2e/velero/values-velero.yaml`

## Relationships

- [Ranged Read Hardening](Ranged_Read_Hardening.md) (1 shared connections)
- [Dead Configuration Findings](Dead_Configuration_Findings.md) (1 shared connections)
- [Release Workflow](Release_Workflow.md) (1 shared connections)
- [Operator Documentation](Operator_Documentation.md) (1 shared connections)
- [Filename Encryption Ticket](Filename_Encryption_Ticket.md) (1 shared connections)

## Source Files

- `CLAUDE.md`
- `deploy/helm/s3-encryption-proxy/README.md`
- `test/e2e/velero/kind-config.yaml`
- `test/e2e/velero/manifests/minio.yaml`
- `test/e2e/velero/manifests/proxy-nodeport.yaml`
- `test/e2e/velero/manifests/snapshotclass.yaml`
- `test/e2e/velero/values-proxy.yaml`
- `test/e2e/velero/values-velero.yaml`

## Audit Trail

- EXTRACTED: 20 (80%)
- INFERRED: 5 (20%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*