# Filename Encryption Design

> 43 nodes · cohesion 0.06

## Key Concepts

- **Ticket 017: Filename encryption** (37 connections) — `docs/tickets/017-filename-encryption.md`
- **ADR 0023: Filename encryption** (29 connections) — `docs/tickets/017-filename-encryption.md`
- **ADR 0025** (28 connections) — `docs/tickets/038-s3-encryption-operator.md`
- **Multi-source paged listing with proxy-minted continuation token (F3)** (5 connections) — `docs/tickets/017-filename-encryption.md`
- **Finding label index (N-, S-, P-, F- series)** (5 connections) — `docs/tickets/README.md`
- **/status document on the monitoring listener** (4 connections) — `docs/adr/0034-a-probe-reports-the-process-never-its-dependencies.md`
- **Filename encryption mode set off/drain/mixed/strict (F1, O1)** (4 connections) — `docs/tickets/017-filename-encryption.md`
- **Gate: s3cmd sync must converge on a partial-directory prefix** (4 connections) — `docs/tickets/017-filename-encryption.md`
- **Wrapped key auth failure answers 403 InvalidObjectState** (3 connections) — `docs/adr/0003-objects-are-an-authenticated-segment-chain.md`
- **encryption.filename_encryption modes: off, drain, mixed, strict** (3 connections) — `docs/adr/0023-filename-encryption-encrypts-directory-segments.md`
- **Per-object name form lookup in mixed and drain** (3 connections) — `docs/adr/0023-filename-encryption-encrypts-directory-segments.md`
- **Unauthenticated monitoring listener** (3 connections) — `docs/adr/0030-the-network-boundary-belongs-to-the-administrator.md`
- **Hand-rolled RFC 5297 AES-SIV with 512-bit key (F5)** (3 connections) — `docs/tickets/017-filename-encryption.md`
- **Leaf encrypted with keyed 4-char head tag of first character (F17, L2)** (3 connections) — `docs/tickets/017-filename-encryption.md`
- **Mixed-bucket name leak via clear-form fallback requests** (3 connections) — `docs/tickets/017-filename-encryption.md`
- **Other-form directory cache learned from backend listings (F2, M2, ADR 0023 D20)** (3 connections) — `docs/tickets/017-filename-encryption.md`
- **Partial-directory prefix fan-out (F9)** (3 connections) — `docs/tickets/017-filename-encryption.md`
- **Per-bucket slope: control plane additive, data plane is a format decision** (3 connections) — `docs/tickets/040-managed-buckets.md`
- **Tampered wrapped key fails before any byte is decrypted** (2 connections) — `docs/adr/0004-one-local-key-provider.md`
- **AES-SIV-CMAC (RFC 5297) segment encryption** (2 connections) — `docs/adr/0023-filename-encryption-encrypts-directory-segments.md`
- **Listings drop entries that do not decrypt, in backend order** (2 connections) — `docs/adr/0023-filename-encryption-encrypts-directory-segments.md`
- **Exit provider accepts only off/drain; ADR 0025 carve-out (F10)** (2 connections) — `docs/tickets/017-filename-encryption.md`
- **Enabling filename encryption is a rename, never a re-encryption** (2 connections) — `docs/tickets/017-filename-encryption.md`
- **S2V associated-data vector framing, bucket kept out of AAD (F6)** (2 connections) — `docs/tickets/017-filename-encryption.md`
- **N-1: fail-open pass-through read under encrypting provider (closed)** (2 connections) — `docs/tickets/README.md`
- *... and 18 more nodes in this community*

## Relationships

- [Multipart Part Layout Decisions](Multipart_Part_Layout_Decisions.md) (15 shared connections)
- [Storage Format Integrity Guarantees](Storage_Format_Integrity_Guarantees.md) (14 shared connections)
- [ADR Web: Auth, Checksums, Config](ADR_Web-_Auth,_Checksums,_Config.md) (14 shared connections)
- [Hostile Backend and Key Material ADRs](Hostile_Backend_and_Key_Material_ADRs.md) (7 shared connections)
- [Filename Encryption Pass Engine](Filename_Encryption_Pass_Engine.md) (7 shared connections)
- [Release and Test Discipline ADRs](Release_and_Test_Discipline_ADRs.md) (6 shared connections)
- [Forward-or-Refuse Response Rules](Forward-or-Refuse_Response_Rules.md) (4 shared connections)
- [Changelog and Project Front Page](Changelog_and_Project_Front_Page.md) (3 shared connections)
- [Upload Length Guards and Exit Provider](Upload_Length_Guards_and_Exit_Provider.md) (1 shared connections)
- [Service TLS and Operator Certificates](Service_TLS_and_Operator_Certificates.md) (1 shared connections)

## Source Files

- `README.md`
- `docs/adr/0003-objects-are-an-authenticated-segment-chain.md`
- `docs/adr/0004-one-local-key-provider.md`
- `docs/adr/0023-filename-encryption-encrypts-directory-segments.md`
- `docs/adr/0030-the-network-boundary-belongs-to-the-administrator.md`
- `docs/adr/0034-a-probe-reports-the-process-never-its-dependencies.md`
- `docs/tickets/017-filename-encryption.md`
- `docs/tickets/038-s3-encryption-operator.md`
- `docs/tickets/040-managed-buckets.md`
- `docs/tickets/README.md`

## Audit Trail

- EXTRACTED: 124 (98%)
- INFERRED: 2 (2%)
- AMBIGUOUS: 1 (1%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*