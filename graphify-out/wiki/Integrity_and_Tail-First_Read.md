# Integrity and Tail-First Read

> 84 nodes · cohesion 0.03

## Key Concepts

- **ADR 0003: Objects are an authenticated segment chain** (88 connections) — `README.md`
- **ADR 0001: The backend is hostile** (60 connections) — `CONTRIBUTING.md`
- **ADR 0025: Leaving is a supported mode** (42 connections) — `README.md`
- **ADR 0023: Filename encryption encrypts every segment with a searchable leaf head** (33 connections) — `docs/tickets/017-filename-encryption.md`
- **exit provider (leaving the product)** (9 connections) — `docs/security/key-management.md`
- **Tail-first whole-object GET (bytes=-65604, then If-Match prefix)** (6 connections) — `docs/developer/request-paths.md`
- **CRC32C over whole plaintext sealed in trailer (D13)** (5 connections) — `docs/adr/0003-objects-are-an-authenticated-segment-chain.md`
- **Hostile S3 backend (adversary capability set)** (4 connections) — `docs/adr/0001-the-backend-is-hostile.md`
- **Sealed trailer with plaintext length and CRC32C** (4 connections) — `docs/adr/0003-objects-are-an-authenticated-segment-chain.md`
- **s3ep-gcm-seg-v2 AES-256-GCM segment chain** (4 connections) — `docs/adr/0003-objects-are-an-authenticated-segment-chain.md`
- **Foreign-format objects are refused, never guessed at (D4)** (4 connections) — `docs/adr/0017-stored-data-compatibility-is-not-owed.md`
- **Deviation never overrides honesty** (4 connections) — `docs/adr/0036-a-response-follows-s3-deviates-for-the-client-and-is-never-a-break.md`
- **Storage format s3ep-gcm-seg-v2** (4 connections) — `docs/operations/integrity.md`
- **Fail closed on foreign objects (403 InvalidObjectState)** (3 connections) — `docs/adr/0001-the-backend-is-hostile.md`
- **Integrity is not separable from decryption** (3 connections) — `docs/adr/0001-the-backend-is-hostile.md`
- **Every plaintext byte verified by the proxy** (3 connections) — `docs/adr/0001-the-backend-is-hostile.md`
- **s3ep-dek-algorithm metadata key** (3 connections) — `docs/adr/0003-objects-are-an-authenticated-segment-chain.md`
- **Size function well-formedness guard (D12a)** (3 connections) — `docs/adr/0003-objects-are-an-authenticated-segment-chain.md`
- **64-byte name key, wrapped by the KEK, not derived from it (D6)** (3 connections) — `docs/adr/0023-filename-encryption-encrypts-every-segment-with-a-searchable-leaf-head.md`
- **Per-object name-form lookup in mixed and drain modes (D19)** (3 connections) — `docs/adr/0023-filename-encryption-encrypts-every-segment-with-a-searchable-leaf-head.md`
- **No fingerprint special-cased on the read path (D7)** (3 connections) — `docs/adr/0025-leaving-is-a-supported-mode.md`
- **Per-object read decision under exit (D5)** (3 connections) — `docs/adr/0025-leaving-is-a-supported-mode.md`
- **Unreachable or unverifiable backend answers 500 InternalError** (3 connections) — `docs/adr/0037-the-backend-leg-is-trusted-explicitly-and-its-failures-are-named.md`
- **The Second Backend Request of a Whole-Object Read Costs About 300 Microseconds** (3 connections) — `docs/developer/performance.md`
- **What a read costs (tail-first whole-object GET)** (3 connections) — `docs/operations/s3-api.md`
- *... and 59 more nodes in this community*

## Relationships

- [S3 API Behaviour](S3_API_Behaviour.md) (22 shared connections)
- [ADR Corpus and Release History](ADR_Corpus_and_Release_History.md) (19 shared connections)
- [Key Hierarchy and Threat Rules](Key_Hierarchy_and_Threat_Rules.md) (18 shared connections)
- [Exit Provider and Session Lifecycle](Exit_Provider_and_Session_Lifecycle.md) (16 shared connections)
- [Monitoring and Licence Removal](Monitoring_and_Licence_Removal.md) (12 shared connections)
- [Client Library and Storage Format](Client_Library_and_Storage_Format.md) (12 shared connections)
- [SigV4 Authentication Rules](SigV4_Authentication_Rules.md) (9 shared connections)
- [Release Process and Doc Homes](Release_Process_and_Doc_Homes.md) (9 shared connections)
- [Planned Work: SSE-C and HA](Planned_Work-_SSE-C_and_HA.md) (9 shared connections)
- [Whole-Object Read Window](Whole-Object_Read_Window.md) (7 shared connections)
- [Filename Encryption Ticket](Filename_Encryption_Ticket.md) (7 shared connections)
- [Middleware: S3Auth Robust](Middleware-_S3Auth_Robust.md) (5 shared connections)

## Source Files

- `CONTRIBUTING.md`
- `README.md`
- `docs/adr/0001-the-backend-is-hostile.md`
- `docs/adr/0002-one-data-key-per-object.md`
- `docs/adr/0003-objects-are-an-authenticated-segment-chain.md`
- `docs/adr/0008-every-response-describes-the-proxy.md`
- `docs/adr/0009-the-metadata-prefix-is-the-proxys-namespace.md`
- `docs/adr/0011-the-proxy-owns-the-part-layout.md`
- `docs/adr/0017-stored-data-compatibility-is-not-owed.md`
- `docs/adr/0023-filename-encryption-encrypts-every-segment-with-a-searchable-leaf-head.md`
- `docs/adr/0025-leaving-is-a-supported-mode.md`
- `docs/adr/0036-a-response-follows-s3-deviates-for-the-client-and-is-never-a-break.md`
- `docs/adr/0037-the-backend-leg-is-trusted-explicitly-and-its-failures-are-named.md`
- `docs/developer/performance.md`
- `docs/developer/request-paths.md`
- `docs/operations/integrity.md`
- `docs/operations/s3-api.md`
- `docs/operations/upgrading.md`
- `docs/security/key-management.md`
- `docs/tickets/017-filename-encryption.md`

## Audit Trail

- EXTRACTED: 259 (93%)
- INFERRED: 20 (7%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*