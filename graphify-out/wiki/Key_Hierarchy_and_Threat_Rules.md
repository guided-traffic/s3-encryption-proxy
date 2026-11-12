# Key Hierarchy and Threat Rules

> 68 nodes · cohesion 0.04

## Key Concepts

- **ADR 0002: One data key per object** (41 connections) — `CONTRIBUTING.md`
- **ADR 0005: A KMS key is a provider** (37 connections) — `docs/tickets/025-tink-kms-hcvault.md`
- **ADR 0004: One local key provider** (34 connections) — `README.md`
- **ADR 0021: Key material is generated, never committed** (23 connections) — `README.md`
- **Two KEK providers: aes and exit** (6 connections) — `CLAUDE.md`
- **s3ep-encrypted-dek metadata key** (4 connections) — `docs/adr/0002-one-data-key-per-object.md`
- **s3ep-kek-fingerprint metadata key** (4 connections) — `docs/adr/0002-one-data-key-per-object.md`
- **Bounded unwrapped data key cache** (4 connections) — `docs/adr/0002-one-data-key-per-object.md`
- **Tail-first whole-object read and x-amz-checksum-crc32c** (4 connections) — `docs/adr/0003-objects-are-an-authenticated-segment-chain.md`
- **aes_key admission: base64 of 32 bytes, not all printable, >=16 distinct values** (4 connections) — `docs/adr/0004-one-local-key-provider.md`
- **HKDF-SHA256 derived s3ep-kek-fingerprint** (4 connections) — `docs/adr/0004-one-local-key-provider.md`
- **KMS-backed key encryption key provider type (unbuilt)** (4 connections) — `docs/adr/0005-a-kms-key-is-a-provider.md`
- **S3EP_AES_KEY environment variable reference (D3)** (4 connections) — `docs/adr/0021-key-material-is-generated-never-committed.md`
- **Ticket 033: out-of-band recovery path for a damaged object** (4 connections) — `docs/tickets/033-out-of-band-recovery-path.md`
- **Out-of-band recovery tool for damaged objects** (4 connections) — `docs/tickets/033-out-of-band-recovery-path.md`
- **Adding a KEK provider checklist** (3 connections) — `DEVELOPER.md`
- **A read performs at most one unwrap** (3 connections) — `docs/adr/0002-one-data-key-per-object.md`
- **Wrapped key auth failure answers 403 InvalidObjectState** (3 connections) — `docs/adr/0003-objects-are-an-authenticated-segment-chain.md`
- **AES-256-GCM key wrap with per-wrap salt (76 bytes)** (3 connections) — `docs/adr/0004-one-local-key-provider.md`
- **Tampered wrapped key fails with its own error before any byte is decrypted** (3 connections) — `docs/adr/0004-one-local-key-provider.md`
- **Custody by injection vs custody in a KMS** (3 connections) — `docs/adr/0005-a-kms-key-is-a-provider.md`
- **Data key cache (1024 LRU, no expiry yet)** (3 connections) — `docs/adr/0005-a-kms-key-is-a-provider.md`
- **Stable key encryption key for the paid run (D8)** (3 connections) — `docs/adr/0027-conformance-is-asserted-against-a-backend-that-is-not-minio.md`
- **Minimal set of cryptographically load-bearing inputs** (3 connections) — `docs/tickets/033-out-of-band-recovery-path.md`
- **aes provider** (3 connections) — `README.md`
- *... and 43 more nodes in this community*

## Relationships

- [Integrity and Tail-First Read](Integrity_and_Tail-First_Read.md) (18 shared connections)
- [Monitoring and Licence Removal](Monitoring_and_Licence_Removal.md) (15 shared connections)
- [Exit Provider and Session Lifecycle](Exit_Provider_and_Session_Lifecycle.md) (7 shared connections)
- [Release Process and Doc Homes](Release_Process_and_Doc_Homes.md) (7 shared connections)
- [Client Library and Storage Format](Client_Library_and_Storage_Format.md) (6 shared connections)
- [ADR Corpus and Release History](ADR_Corpus_and_Release_History.md) (5 shared connections)
- [SigV4 Authentication Rules](SigV4_Authentication_Rules.md) (5 shared connections)
- [Performance and Test Docs](Performance_and_Test_Docs.md) (4 shared connections)
- [S3 API Behaviour](S3_API_Behaviour.md) (4 shared connections)
- [Whole-Object Read Window](Whole-Object_Read_Window.md) (4 shared connections)
- [Filename Encryption Ticket](Filename_Encryption_Ticket.md) (3 shared connections)
- [Planned Work: SSE-C and HA](Planned_Work-_SSE-C_and_HA.md) (2 shared connections)

## Source Files

- `CLAUDE.md`
- `CONTRIBUTING.md`
- `DEVELOPER.md`
- `README.md`
- `deploy/helm/s3-encryption-proxy/README.md`
- `docs/adr/0002-one-data-key-per-object.md`
- `docs/adr/0003-objects-are-an-authenticated-segment-chain.md`
- `docs/adr/0004-one-local-key-provider.md`
- `docs/adr/0005-a-kms-key-is-a-provider.md`
- `docs/adr/0021-key-material-is-generated-never-committed.md`
- `docs/adr/0027-conformance-is-asserted-against-a-backend-that-is-not-minio.md`
- `docs/tickets/025-tink-kms-hcvault.md`
- `docs/tickets/033-out-of-band-recovery-path.md`
- `docs/tickets/036-high-availability.md`

## Audit Trail

- EXTRACTED: 170 (93%)
- INFERRED: 13 (7%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*