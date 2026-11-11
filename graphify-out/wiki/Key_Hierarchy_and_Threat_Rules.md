# Key Hierarchy and Threat Rules

> 83 nodes · cohesion 0.04

## Key Concepts

- **ADR 0013: A configuration key exists only if code reads it** (60 connections) — `docs/tickets/037-multiple-backends.md`
- **ADR 0017: Stored data compatibility is not owed** (43 connections) — `docs/adr/0017-stored-data-compatibility-is-not-owed.md`
- **ADR 0002: One data key per object** (30 connections) — `docs/adr/0002-one-data-key-per-object.md`
- **ADR 0004: One local key provider** (30 connections) — `docs/adr/0004-one-local-key-provider.md`
- **ADR 0005: A KMS key is a provider** (30 connections) — `docs/tickets/025-tink-kms-hcvault.md`
- **ADR 0009: The metadata prefix is the proxy namespace** (27 connections) — `docs/adr/0009-the-metadata-prefix-is-the-proxys-namespace.md`
- **Key management: hierarchy, providers, custody, rotation** (16 connections) — `docs/security/key-management.md`
- **Upgrading from 3.x or 4.x to 5.x** (13 connections) — `docs/operations/upgrading.md`
- **Threat model and trust boundaries** (9 connections) — `docs/security/threat-model.md`
- **Extensible pass engine: enumerate/plan/transfer/verify/delete/report/config (F11)** (9 connections) — `docs/tickets/017-filename-encryption.md`
- **Rule 2: a control that exists only in configuration or documentation is worse than none** (7 connections) — `docs/security/threat-model.md`
- **Derived KEK fingerprint (HKDF label s3ep-kek-fingerprint)** (6 connections) — `docs/security/key-management.md`
- **Pass Moving a Bucket onto the Current KEK (rewrap)** (6 connections) — `docs/tickets/040-managed-buckets.md`
- **HKDF-SHA256 derived s3ep-kek-fingerprint** (5 connections) — `docs/adr/0004-one-local-key-provider.md`
- **encryption.metadata_key_prefix is the proxy exclusive namespace** (5 connections) — `docs/adr/0009-the-metadata-prefix-is-the-proxys-namespace.md`
- **An ADR states the current decision only (D9)** (5 connections) — `docs/adr/0022-tickets-are-work-lists-that-get-archived.md`
- **A control existing only in config or docs is worse than none** (4 connections) — `docs/adr/0001-the-backend-is-hostile.md`
- **Provider selection by KEK fingerprint** (4 connections) — `docs/adr/0002-one-data-key-per-object.md`
- **s3ep-kek-algorithm metadata key** (4 connections) — `docs/adr/0002-one-data-key-per-object.md`
- **AES-256-GCM key wrap with per-wrap salt (76 bytes)** (4 connections) — `docs/adr/0004-one-local-key-provider.md`
- **Forward it or refuse it, never silently drop** (4 connections) — `docs/adr/0007-forward-it-or-refuse-it.md`
- **Removed configuration keys now refuse the start** (4 connections) — `docs/operations/upgrading.md`
- **KEK rotation by fingerprint** (4 connections) — `docs/security/key-management.md`
- **Clock-skew replay window (max_clock_skew_seconds)** (4 connections) — `docs/security/request-authentication.md`
- **Tenancy and privilege: the blast radius** (4 connections) — `docs/security/tenancy-and-privilege.md`
- *... and 58 more nodes in this community*

## Relationships

- [ADR Corpus and Release History](ADR_Corpus_and_Release_History.md) (45 shared connections)
- [Integrity and Tail-First Read](Integrity_and_Tail-First_Read.md) (32 shared connections)
- [Release Process and Doc Homes](Release_Process_and_Doc_Homes.md) (22 shared connections)
- [Key Material and Deployment Secrets](Key_Material_and_Deployment_Secrets.md) (16 shared connections)
- [SigV4 Authentication Rules](SigV4_Authentication_Rules.md) (16 shared connections)
- [Monitoring and Licence Removal](Monitoring_and_Licence_Removal.md) (15 shared connections)
- [Client Library and Storage Format](Client_Library_and_Storage_Format.md) (12 shared connections)
- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (8 shared connections)
- [Planned Work: SSE-C and HA](Planned_Work-_SSE-C_and_HA.md) (7 shared connections)
- [Exit Provider and Session Lifecycle](Exit_Provider_and_Session_Lifecycle.md) (4 shared connections)
- [S3 API Behaviour](S3_API_Behaviour.md) (4 shared connections)
- [Filename Encryption Ticket](Filename_Encryption_Ticket.md) (4 shared connections)

## Source Files

- `DEVELOPER.md`
- `README.md`
- `docs/adr/0001-the-backend-is-hostile.md`
- `docs/adr/0002-one-data-key-per-object.md`
- `docs/adr/0003-objects-are-an-authenticated-segment-chain.md`
- `docs/adr/0004-one-local-key-provider.md`
- `docs/adr/0005-a-kms-key-is-a-provider.md`
- `docs/adr/0006-the-proxy-serves-any-s3-client.md`
- `docs/adr/0007-forward-it-or-refuse-it.md`
- `docs/adr/0008-every-response-describes-the-proxy.md`
- `docs/adr/0009-the-metadata-prefix-is-the-proxys-namespace.md`
- `docs/adr/0013-a-configuration-key-exists-only-if-code-reads-it.md`
- `docs/adr/0017-stored-data-compatibility-is-not-owed.md`
- `docs/adr/0022-tickets-are-work-lists-that-get-archived.md`
- `docs/adr/0023-filename-encryption-encrypts-directory-segments.md`
- `docs/operations/configuration.md`
- `docs/operations/upgrading.md`
- `docs/security/key-management.md`
- `docs/security/refusals.md`
- `docs/security/request-authentication.md`

## Audit Trail

- EXTRACTED: 291 (90%)
- INFERRED: 31 (10%)
- AMBIGUOUS: 3 (1%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*