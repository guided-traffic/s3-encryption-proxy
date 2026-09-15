# Release 5.0.0 Breaking Changes

> 61 nodes · cohesion 0.04

## Key Concepts

- **ADR 0003 Objects are an authenticated segment chain** (49 connections) — `SECURITY_ARCHITECTURE.md`
- **ADR 0017 Stored data compatibility is not owed** (33 connections) — `DEVELOPER.md`
- **Release 5.0.0 - the storage format break** (10 connections) — `CHANGELOG.md`
- **s3ep-gcm-seg-v2 stored format** (7 connections) — `README.md`
- **A control that exists only in configuration is worse than no control** (7 connections) — `SECURITY_ARCHITECTURE.md`
- **The Tail-First Whole-Object GET** (5 connections) — `docs/developer/request-paths.md`
- **KEK/DEK key hierarchy, two layers and no third** (5 connections) — `SECURITY_ARCHITECTURE.md`
- **Client upload checksums are the one control on the client leg** (5 connections) — `SECURITY_ARCHITECTURE.md`
- **Integrity is not configurable and never was a layer** (4 connections) — `CLAUDE.md`
- **Envelope encryption: DEK per object, KEK wraps DEKs only (D1, D2)** (4 connections) — `docs/adr/0002-one-data-key-per-object.md`
- **An object the release did not write is refused, never guessed at (D4)** (4 connections) — `docs/adr/0017-stored-data-compatibility-is-not-owed.md`
- **Envelope encryption, one data key per object** (4 connections) — `README.md`
- **The sealed trailer authenticates length and CRC32C** (4 connections) — `SECURITY_ARCHITECTURE.md`
- **Segment seal bound to format id, object key and index** (4 connections) — `SECURITY_ARCHITECTURE.md`
- **CHANGELOG.md release history** (3 connections) — `CHANGELOG.md`
- **5.0.0: a chart upgrade that changes the configuration restarts the pods** (3 connections) — `CHANGELOG.md`
- **No backward compatibility; remove unnecessary code** (3 connections) — `CLAUDE.md`
- **A whole-object GET is tail-first** (3 connections) — `DEVELOPER.md`
- **ADR 0004 D9: A tampered wrapped key fails with its own error before any stored byte is decrypted** (3 connections) — `docs/adr/0004-one-local-key-provider.md`
- **A Key With No Reader** (3 connections) — `docs/adr/0013-a-configuration-key-exists-only-if-code-reads-it.md`
- **ADR 0013 D1: A configuration key exists only if code reads it and that read changes behaviour** (3 connections) — `docs/adr/0013-a-configuration-key-exists-only-if-code-reads-it.md`
- **The transform is applied at exactly one boundary (D8)** (3 connections) — `docs/adr/0023-filename-encryption-encrypts-directory-segments.md`
- **On read the exit provider still decrypts, per object (D4, D5)** (3 connections) — `docs/adr/0025-leaving-is-a-supported-mode.md`
- **The Second Backend Request of a Whole-Object Read Costs About 300 Microseconds** (3 connections) — `docs/developer/performance.md`
- **Foreign objects are refused, not served** (3 connections) — `README.md`
- *... and 36 more nodes in this community*

## Relationships

- [Contributor Guide and KMS Provider ADR](Contributor_Guide_and_KMS_Provider_ADR.md) (14 shared connections)
- [KEK Providers and Key Rotation](KEK_Providers_and_Key_Rotation.md) (13 shared connections)
- [Any-S3-Client Scope and E2E Rules](Any-S3-Client_Scope_and_E2E_Rules.md) (8 shared connections)
- [Response Composition Rules](Response_Composition_Rules.md) (7 shared connections)
- [KEK Fingerprint and Client Checksums](KEK_Fingerprint_and_Client_Checksums.md) (6 shared connections)
- [Proxy-Owned Part Layout](Proxy-Owned_Part_Layout.md) (6 shared connections)
- [Network Boundary and HA Store](Network_Boundary_and_HA_Store.md) (6 shared connections)
- [Hostile Backend Threat Model](Hostile_Backend_Threat_Model.md) (5 shared connections)
- [PUT Routing and Short-Part Budget](PUT_Routing_and_Short-Part_Budget.md) (5 shared connections)
- [Configuration Loading and Upload Sweeper](Configuration_Loading_and_Upload_Sweeper.md) (5 shared connections)
- [SigV4 Authentication Rules](SigV4_Authentication_Rules.md) (4 shared connections)
- [Forward-or-Refuse and CI Gates](Forward-or-Refuse_and_CI_Gates.md) (4 shared connections)

## Source Files

- `CHANGELOG.md`
- `CLAUDE.md`
- `CONTRIBUTING.md`
- `DEVELOPER.md`
- `README.md`
- `SECURITY_ARCHITECTURE.md`
- `docs/adr/0002-one-data-key-per-object.md`
- `docs/adr/0003-objects-are-an-authenticated-segment-chain.md`
- `docs/adr/0004-one-local-key-provider.md`
- `docs/adr/0013-a-configuration-key-exists-only-if-code-reads-it.md`
- `docs/adr/0017-stored-data-compatibility-is-not-owed.md`
- `docs/adr/0018-a-major-release-is-declared-by-a-label.md`
- `docs/adr/0023-filename-encryption-encrypts-directory-segments.md`
- `docs/adr/0025-leaving-is-a-supported-mode.md`
- `docs/developer/performance.md`
- `docs/developer/request-paths.md`

## Audit Trail

- EXTRACTED: 152 (92%)
- INFERRED: 14 (8%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*