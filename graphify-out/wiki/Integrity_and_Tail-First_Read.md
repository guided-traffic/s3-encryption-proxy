# Integrity and Tail-First Read

> 63 nodes · cohesion 0.04

## Key Concepts

- **ADR 0003: Objects are an authenticated segment chain** (70 connections) — `docs/adr/0003-objects-are-an-authenticated-segment-chain.md`
- **ADR 0001: The S3 backend is hostile** (46 connections) — `docs/adr/0001-the-backend-is-hostile.md`
- **ADR 0023: Filename encryption of key segments** (27 connections) — `docs/adr/0023-filename-encryption-encrypts-directory-segments.md`
- **exit provider (leaving the product)** (10 connections) — `docs/security/key-management.md`
- **s3ep-gcm-seg-v2 AES-256-GCM segment chain** (6 connections) — `docs/adr/0003-objects-are-an-authenticated-segment-chain.md`
- **Tail-first whole-object GET (bytes=-65604, then If-Match prefix)** (6 connections) — `docs/developer/request-paths.md`
- **What the backend learns anyway (names, sizes, timing, fingerprint, tags)** (6 connections) — `docs/security/stored-objects.md`
- **Mixed-bucket name leak via clear-form fallback requests** (5 connections) — `docs/tickets/017-filename-encryption.md`
- **Integrity is not configurable** (4 connections) — `CLAUDE.md`
- **Tail-first whole-object GET, trailer-authenticated length** (4 connections) — `DEVELOPER.md`
- **Benchmark before and after on the same machine** (4 connections) — `docs/adr/0020-performance-is-measured-before-and-after.md`
- **Deviation never overrides honesty** (4 connections) — `docs/adr/0036-a-response-follows-s3-deviates-for-the-client-and-is-never-a-break.md`
- **Out-of-band recovery tool for damaged objects** (4 connections) — `docs/tickets/033-out-of-band-recovery-path.md`
- **Tail-first read (bytes=-65604, HEAD bytes=-40)** (3 connections) — `CLAUDE.md`
- **Every plaintext byte verified by the proxy** (3 connections) — `docs/adr/0001-the-backend-is-hostile.md`
- **Sealed trailer with plaintext length and CRC32C** (3 connections) — `docs/adr/0003-objects-are-an-authenticated-segment-chain.md`
- **Tail-first whole-object read and x-amz-checksum-crc32c** (3 connections) — `docs/adr/0003-objects-are-an-authenticated-segment-chain.md`
- **x-amz-checksum-crc32c answered on writes** (3 connections) — `docs/adr/0003-objects-are-an-authenticated-segment-chain.md`
- **An object not in the current format is refused, never guessed at** (3 connections) — `docs/adr/0017-stored-data-compatibility-is-not-owed.md`
- **Unreachable or unverifiable backend answers 500 InternalError** (3 connections) — `docs/adr/0037-the-backend-leg-is-trusted-explicitly-and-its-failures-are-named.md`
- **The Second Backend Request of a Whole-Object Read Costs About 300 Microseconds** (3 connections) — `docs/developer/performance.md`
- **What a read costs (tail-first whole-object GET)** (3 connections) — `docs/operations/s3-api.md`
- **The exit fingerprint is not a key** (3 connections) — `docs/security/key-management.md`
- **Ticket 033: out-of-band recovery path for a damaged object** (3 connections) — `docs/tickets/033-out-of-band-recovery-path.md`
- **Minimal set of cryptographically load-bearing inputs** (3 connections) — `docs/tickets/033-out-of-band-recovery-path.md`
- *... and 38 more nodes in this community*

## Relationships

- [ADR Corpus and Release History](ADR_Corpus_and_Release_History.md) (47 shared connections)
- [Key Hierarchy and Threat Rules](Key_Hierarchy_and_Threat_Rules.md) (32 shared connections)
- [Client Library and Storage Format](Client_Library_and_Storage_Format.md) (11 shared connections)
- [Release Process and Doc Homes](Release_Process_and_Doc_Homes.md) (10 shared connections)
- [S3 API Behaviour](S3_API_Behaviour.md) (8 shared connections)
- [Key Material and Deployment Secrets](Key_Material_and_Deployment_Secrets.md) (6 shared connections)
- [Planned Work: SSE-C and HA](Planned_Work-_SSE-C_and_HA.md) (6 shared connections)
- [Monitoring and Licence Removal](Monitoring_and_Licence_Removal.md) (4 shared connections)
- [Filename Encryption Ticket](Filename_Encryption_Ticket.md) (4 shared connections)
- [Whole-Object Read Window](Whole-Object_Read_Window.md) (3 shared connections)
- [SigV4 Authentication Rules](SigV4_Authentication_Rules.md) (2 shared connections)
- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (2 shared connections)

## Source Files

- `CLAUDE.md`
- `DEVELOPER.md`
- `README.md`
- `docs/adr/0001-the-backend-is-hostile.md`
- `docs/adr/0002-one-data-key-per-object.md`
- `docs/adr/0003-objects-are-an-authenticated-segment-chain.md`
- `docs/adr/0005-a-kms-key-is-a-provider.md`
- `docs/adr/0006-the-proxy-serves-any-s3-client.md`
- `docs/adr/0009-the-metadata-prefix-is-the-proxys-namespace.md`
- `docs/adr/0010-sizes-and-listings-describe-the-plaintext.md`
- `docs/adr/0017-stored-data-compatibility-is-not-owed.md`
- `docs/adr/0020-performance-is-measured-before-and-after.md`
- `docs/adr/0023-filename-encryption-encrypts-directory-segments.md`
- `docs/adr/0036-a-response-follows-s3-deviates-for-the-client-and-is-never-a-break.md`
- `docs/adr/0037-the-backend-leg-is-trusted-explicitly-and-its-failures-are-named.md`
- `docs/developer/performance.md`
- `docs/developer/request-paths.md`
- `docs/operations/integrity.md`
- `docs/operations/s3-api.md`
- `docs/operations/upgrading.md`

## Audit Trail

- EXTRACTED: 195 (89%)
- INFERRED: 24 (11%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*