# Filename Encryption Pass Engine

> 41 nodes · cohesion 0.07

## Key Concepts

- **Ticket 040: managed buckets** (44 connections) — `docs/tickets/038-s3-encryption-operator.md`
- **Ticket 025: Vault as a key provider (parked)** (18 connections) — `docs/tickets/025-tink-kms-hcvault.md`
- **Extensible pass engine: enumerate/plan/transfer/verify/delete/report/config (F11)** (9 connections) — `docs/tickets/017-filename-encryption.md`
- **Pass moving a bucket onto the current KEK (item 4)** (8 connections) — `docs/tickets/040-managed-buckets.md`
- **Explicit S3BackendInterface forwarder with named inner field (F8)** (5 connections) — `docs/tickets/017-filename-encryption.md`
- **Rewrap campaign is a full server-side rewrite, not a metadata edit** (5 connections) — `docs/tickets/025-tink-kms-hcvault.md`
- **S3BackendInterface** (5 connections) — `docs/tickets/017-filename-encryption.md`
- **DEK cache: 1024-entry LRU with no expiry** (4 connections) — `docs/tickets/025-tink-kms-hcvault.md`
- **HashiCorp Vault Transit KEK provider (parked)** (4 connections) — `docs/tickets/025-tink-kms-hcvault.md`
- **CopyObject must not go on S3BackendInterface** (4 connections) — `docs/tickets/040-managed-buckets.md`
- **Failure policy: fail-on-bucket-missing / missing-permissions / file-not-readable** (4 connections) — `docs/tickets/040-managed-buckets.md`
- **Renamed metadata_key_prefix makes every object look plaintext** (4 connections) — `docs/tickets/040-managed-buckets.md`
- **Stored segment form: ! marker + 12-bit key fingerprint + key list (F4)** (3 connections) — `docs/tickets/017-filename-encryption.md`
- **Fan-out client implementing the 52-method interface** (3 connections) — `docs/tickets/037-multiple-backends.md`
- **Conditional self-copy (x-amz-copy-source-if-match) as compare-and-swap** (3 connections) — `docs/tickets/040-managed-buckets.md`
- **Fingerprint-seen counter on the read path as alternative** (3 connections) — `docs/tickets/040-managed-buckets.md`
- **Startup readability verdict per managed bucket** (3 connections) — `docs/tickets/040-managed-buckets.md`
- **names CLI surface: wrap, map, unmap, audit, migrate** (2 connections) — `docs/tickets/017-filename-encryption.md`
- **Off-state accident: feature off on a mapped bucket serves ciphertext names (D-J)** (2 connections) — `docs/tickets/017-filename-encryption.md`
- **Per-request name memoisation, no process-wide LRU (F14, D-K)** (2 connections) — `docs/tickets/017-filename-encryption.md`
- **Rename operation (names migrate)** (2 connections) — `docs/tickets/017-filename-encryption.md`
- **Provider registry shutdown path (manager -> registry -> provider)** (2 connections) — `docs/tickets/025-tink-kms-hcvault.md`
- **Thread request context to the key provider** (2 connections) — `docs/tickets/025-tink-kms-hcvault.md`
- **Three rotation mechanisms: rotate, retire version, move key** (2 connections) — `docs/tickets/025-tink-kms-hcvault.md`
- **Token-only Vault authentication in first release** (2 connections) — `docs/tickets/025-tink-kms-hcvault.md`
- *... and 16 more nodes in this community*

## Relationships

- [Multipart Part Layout Decisions](Multipart_Part_Layout_Decisions.md) (14 shared connections)
- [Hostile Backend and Key Material ADRs](Hostile_Backend_and_Key_Material_ADRs.md) (10 shared connections)
- [Filename Encryption Design](Filename_Encryption_Design.md) (7 shared connections)
- [Release and Test Discipline ADRs](Release_and_Test_Discipline_ADRs.md) (5 shared connections)
- [ADR Web: Auth, Checksums, Config](ADR_Web-_Auth,_Checksums,_Config.md) (4 shared connections)
- [Storage Format Integrity Guarantees](Storage_Format_Integrity_Guarantees.md) (3 shared connections)
- [Service TLS and Operator Certificates](Service_TLS_and_Operator_Certificates.md) (3 shared connections)
- [Forward-or-Refuse Response Rules](Forward-or-Refuse_Response_Rules.md) (2 shared connections)
- [Documentation Homes and Ticket Lifecycle](Documentation_Homes_and_Ticket_Lifecycle.md) (1 shared connections)

## Source Files

- `docs/tickets/017-filename-encryption.md`
- `docs/tickets/025-tink-kms-hcvault.md`
- `docs/tickets/037-multiple-backends.md`
- `docs/tickets/038-s3-encryption-operator.md`
- `docs/tickets/040-managed-buckets.md`

## Audit Trail

- EXTRACTED: 103 (94%)
- INFERRED: 6 (6%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*