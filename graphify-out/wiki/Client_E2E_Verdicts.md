# Client E2E Verdicts

> 21 nodes · cohesion 0.10

## Key Concepts

- **Entity tag is a change token with a -0 marker** (7 connections) — `docs/operations/integrity.md`
- **s3cmd** (5 connections) — `docs/operations/clients/s3cmd.md`
- **Supported clients (Velero, rclone, s3cmd)** (5 connections) — `docs/operations/README.md`
- **Velero** (4 connections) — `docs/operations/clients/velero.md`
- **Assert what is stored, compare by SHA-256** (3 connections) — `docs/developer/testing.md`
- **rclone** (3 connections) — `docs/operations/clients/rclone.md`
- **stored = plaintext + ceil(plaintext/65536)*28 + 40** (3 connections) — `docs/operations/integrity.md`
- **HEAD, GET and listings report the plaintext size** (3 connections) — `docs/operations/s3-api.md`
- **D-F The partial-directory prefix (the gate)** (3 connections) — `docs/tickets/017-filename-encryption.md`
- **A client suite asserts the target behaviour** (2 connections) — `docs/developer/testing.md`
- **use_multipart_etag = false** (2 connections) — `docs/operations/clients/rclone.md`
- **Listing parameters and the max-keys clamp** (2 connections) — `docs/operations/s3-api.md`
- **The Velero leaf census refutes the feature's value there** (2 connections) — `docs/tickets/017-filename-encryption.md`
- **One tool, one e2e job** (1 connections) — `docs/developer/testing.md`
- **e2e verdict table (Still broken section)** (1 connections) — `docs/developer/testing.md`
- **rclone's X-Amz-Meta-Md5chksum annotation** (1 connections) — `docs/operations/clients/rclone.md`
- **host_bucket must equal host_base (path style)** (1 connections) — `docs/operations/clients/s3cmd.md`
- **BackupStorageLocation over HTTPS with path style** (1 connections) — `docs/operations/clients/velero.md`
- **velero-repo-credentials static-passw0rd default** (1 connections) — `docs/operations/clients/velero.md`
- **Operator documentation map** (1 connections) — `docs/operations/README.md`
- **Conditional requests forwarded to the backend** (1 connections) — `docs/operations/s3-api.md`

## Relationships

- [Integrity](Integrity.md) (4 shared connections)
- [Segment Encrypt Reader Tests](Segment_Encrypt_Reader_Tests.md) (1 shared connections)
- [Segment Tamper](Segment_Tamper.md) (1 shared connections)
- [027 Whole Object Read](027_Whole_Object_Read.md) (1 shared connections)
- [Hardening History](Hardening_History.md) (1 shared connections)

## Source Files

- `docs/developer/testing.md`
- `docs/operations/README.md`
- `docs/operations/clients/rclone.md`
- `docs/operations/clients/s3cmd.md`
- `docs/operations/clients/velero.md`
- `docs/operations/integrity.md`
- `docs/operations/s3-api.md`
- `docs/tickets/017-filename-encryption.md`

## Audit Trail

- EXTRACTED: 26 (87%)
- INFERRED: 4 (13%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*