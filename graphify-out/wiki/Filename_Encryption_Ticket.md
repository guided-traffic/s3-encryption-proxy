# Filename Encryption Ticket

> 27 nodes · cohesion 0.10

## Key Concepts

- **Ticket 017: Filename encryption** (25 connections) — `docs/tickets/017-filename-encryption.md`
- **Where each secret lives** (6 connections) — `docs/security/key-management.md`
- **Filename encryption mode set off/drain/mixed/strict (F1, O1)** (6 connections) — `docs/tickets/017-filename-encryption.md`
- **Multi-source paged listing with proxy-minted continuation token (F3)** (6 connections) — `docs/tickets/017-filename-encryption.md`
- **Multipart abandoner closure calls raw SDK client outside the interface** (5 connections) — `docs/tickets/017-filename-encryption.md`
- **Exit provider accepts only off/drain; ADR 0025 carve-out (F10)** (5 connections) — `docs/tickets/017-filename-encryption.md`
- **Explicit S3BackendInterface forwarder with named inner field (F8)** (5 connections) — `docs/tickets/017-filename-encryption.md`
- **Partial-directory prefix fan-out (F9)** (5 connections) — `docs/tickets/017-filename-encryption.md`
- **Leaf encrypted with keyed 4-char head tag of first character (F17, L2)** (4 connections) — `docs/tickets/017-filename-encryption.md`
- **Filename encryption test plan (mixed bucket, leak unit test, gate)** (4 connections) — `docs/tickets/017-filename-encryption.md`
- **Gate: s3cmd sync must converge on a partial-directory prefix** (4 connections) — `docs/tickets/017-filename-encryption.md`
- **s3cmd e2e suite S1-S7** (3 connections) — `docs/operations/clients/s3cmd.md`
- **LRU DEK cache bounded at 1024 entries** (3 connections) — `docs/security/key-management.md`
- **Velero leaf census and name side channels** (3 connections) — `docs/tickets/017-filename-encryption.md`
- **Listing encoding asymmetry across one backend call** (3 connections) — `docs/tickets/017-filename-encryption.md`
- **Stored segment form: ! marker + 12-bit key fingerprint + key list (F4)** (3 connections) — `docs/tickets/017-filename-encryption.md`
- **Velero e2e suite in kind** (2 connections) — `docs/operations/clients/velero.md`
- **Hand-rolled RFC 5297 AES-SIV with 512-bit key (F5)** (2 connections) — `docs/tickets/017-filename-encryption.md`
- **Name key wrapped under own AAD label s3ep-name-wrap-v1** (2 connections) — `docs/tickets/017-filename-encryption.md`
- **Owner requirements: switchable, both name forms readable** (2 connections) — `docs/tickets/017-filename-encryption.md`
- **Per-request name memoisation, no process-wide LRU (F14, D-K)** (2 connections) — `docs/tickets/017-filename-encryption.md`
- **Refusal surface: delimiter, KeyTooLongError, forward prefix-bearing bodies (F12)** (2 connections) — `docs/tickets/017-filename-encryption.md`
- **Release label: minor, keys list shape final in first release (F15)** (2 connections) — `docs/tickets/017-filename-encryption.md`
- **S2V associated-data vector framing, bucket kept out of AAD (F6)** (2 connections) — `docs/tickets/017-filename-encryption.md`
- **Segment-length padding to 16 bytes (F7)** (2 connections) — `docs/tickets/017-filename-encryption.md`
- *... and 2 more nodes in this community*

## Relationships

- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (10 shared connections)
- [ADR Corpus and Release History](ADR_Corpus_and_Release_History.md) (9 shared connections)
- [Key Hierarchy and Threat Rules](Key_Hierarchy_and_Threat_Rules.md) (4 shared connections)
- [Integrity and Tail-First Read](Integrity_and_Tail-First_Read.md) (4 shared connections)
- [Client Library and Storage Format](Client_Library_and_Storage_Format.md) (3 shared connections)
- [Planned Work: SSE-C and HA](Planned_Work-_SSE-C_and_HA.md) (2 shared connections)
- [S3 API Behaviour](S3_API_Behaviour.md) (2 shared connections)
- [Key Material and Deployment Secrets](Key_Material_and_Deployment_Secrets.md) (1 shared connections)
- [Performance and Test Docs](Performance_and_Test_Docs.md) (1 shared connections)
- [Shutdown and Test Contexts](Shutdown_and_Test_Contexts.md) (1 shared connections)
- [Segmented Session Tests](Segmented_Session_Tests.md) (1 shared connections)
- [Monitoring and Licence Removal](Monitoring_and_Licence_Removal.md) (1 shared connections)

## Source Files

- `docs/operations/clients/s3cmd.md`
- `docs/operations/clients/velero.md`
- `docs/security/key-management.md`
- `docs/tickets/017-filename-encryption.md`
- `docs/tickets/037-multiple-backends.md`

## Audit Trail

- EXTRACTED: 67 (88%)
- INFERRED: 9 (12%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*