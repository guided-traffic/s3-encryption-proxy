# Values Velero

> 6 nodes · cohesion 0.33

## Key Concepts

- **Velero Helm values for the e2e cluster** (4 connections) — `test/e2e/velero/values-velero.yaml`
- **uploaderType kopia with EnableCSI and the node agent** (2 connections) — `test/e2e/velero/values-velero.yaml`
- **csi-hostpath-snapclass with the Velero discovery label** (1 connections) — `test/e2e/velero/manifests/snapshotclass.yaml`
- **BackupStorageLocation pointing s3Url at the proxy** (1 connections) — `test/e2e/velero/values-velero.yaml`
- **Explicit image.tag override so the chart appVersion cannot drift from versions.env** (1 connections) — `test/e2e/velero/values-velero.yaml`
- **publicUrl 127.0.0.1:30443 for pre-signed URLs fetched by the host CLI** (1 connections) — `test/e2e/velero/values-velero.yaml`

## Relationships

- No strong cross-community connections detected

## Source Files

- `test/e2e/velero/manifests/snapshotclass.yaml`
- `test/e2e/velero/values-velero.yaml`

## Audit Trail

- EXTRACTED: 5 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*