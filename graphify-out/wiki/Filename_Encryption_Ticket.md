# Filename Encryption Ticket

> 11 nodes · cohesion 0.27

## Key Concepts

- **Ticket 017: Filename encryption, directory segments only** (11 connections) — `docs/tickets/017-filename-encryption.md`
- **AES-SIV-CMAC per directory segment with a chained AAD** (7 connections) — `docs/tickets/017-filename-encryption.md`
- **uploaderType kopia with EnableCSI and the node agent** (6 connections) — `test/e2e/velero/values-velero.yaml`
- **Object keys leak namespace, backup and restore names in cleartext** (3 connections) — `docs/tickets/017-filename-encryption.md`
- **A mapping index in the bucket is rejected** (3 connections) — `docs/tickets/017-filename-encryption.md`
- **K_name: a 64-byte name key wrapped by the active KEK** (3 connections) — `docs/tickets/017-filename-encryption.md`
- **N-4: Velero creates kopia repositories with a published default password** (3 connections) — `docs/tickets/README.md`
- **Item 10: the e2e runs kopia with the published default repository password** (2 connections) — `docs/tickets/016-helm-chart-fixes.md`
- **The boundary decorator between the proxy and the backend SDK client** (2 connections) — `docs/tickets/017-filename-encryption.md`
- **The leaf name stays clear so prefix listings survive** (2 connections) — `docs/tickets/017-filename-encryption.md`
- **csi-hostpath-snapclass with the Velero discovery label** (2 connections) — `test/e2e/velero/manifests/snapshotclass.yaml`

## Relationships

- [Segmented Storage Format V2](Segmented_Storage_Format_V2.md) (6 shared connections)
- [Helm Chart Fix Ticket](Helm_Chart_Fix_Ticket.md) (3 shared connections)
- [Coverage Round Findings](Coverage_Round_Findings.md) (2 shared connections)
- [Vault KMS Provider Ticket](Vault_KMS_Provider_Ticket.md) (1 shared connections)
- [S3 Surface Fidelity Ticket](S3_Surface_Fidelity_Ticket.md) (1 shared connections)
- [Major V5 Work List](Major_V5_Work_List.md) (1 shared connections)

## Source Files

- `docs/tickets/016-helm-chart-fixes.md`
- `docs/tickets/017-filename-encryption.md`
- `docs/tickets/README.md`
- `test/e2e/velero/manifests/snapshotclass.yaml`
- `test/e2e/velero/values-velero.yaml`

## Audit Trail

- EXTRACTED: 23 (79%)
- INFERRED: 6 (21%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*