# Hostile Backend and Key Material ADRs

> 59 nodes · cohesion 0.05

## Key Concepts

- **ADR 0002** (33 connections) — `docs/tickets/033-out-of-band-recovery-path.md`
- **ADR 0004: One local key provider** (29 connections) — `docs/tickets/040-managed-buckets.md`
- **ADR 0005: A KMS key is a provider** (29 connections) — `docs/tickets/025-tink-kms-hcvault.md`
- **ADR 0009** (26 connections) — `docs/tickets/038-s3-encryption-operator.md`
- **Developer: Package map** (14 connections) — `DEVELOPER.md`
- **Architecture Decision Records index** (13 connections) — `docs/adr/README.md`
- **s3ep-kek-algorithm metadata key** (6 connections) — `docs/adr/0002-one-data-key-per-object.md`
- **s3ep-gcm-seg-v2 AES-256-GCM segment chain** (6 connections) — `docs/adr/0003-objects-are-an-authenticated-segment-chain.md`
- **s3ep- metadata namespace, filtered out and refused in** (6 connections) — `docs/security/stored-objects.md`
- **Provider selection by KEK fingerprint** (5 connections) — `docs/adr/0002-one-data-key-per-object.md`
- **Developer: Request paths** (5 connections) — `DEVELOPER.md`
- **aes.go** (5 connections) — `pkg/encryption/keyencryption/aes.go`
- **A control existing only in config or docs is worse than none** (4 connections) — `docs/adr/0001-the-backend-is-hostile.md`
- **Hostile S3 backend (adversary capability set)** (4 connections) — `docs/adr/0001-the-backend-is-hostile.md`
- **s3ep-encrypted-dek metadata key** (4 connections) — `docs/adr/0002-one-data-key-per-object.md`
- **s3ep-kek-fingerprint metadata key** (4 connections) — `docs/adr/0002-one-data-key-per-object.md`
- **Forward it or refuse it, never silently drop** (4 connections) — `docs/adr/0007-forward-it-or-refuse-it.md`
- **encryption.metadata_key_prefix is the proxy exclusive namespace** (4 connections) — `docs/adr/0009-the-metadata-prefix-is-the-proxys-namespace.md`
- **Developer docs index** (4 connections) — `DEVELOPER.md`
- **metadata.go** (4 connections) — `internal/orchestration/metadata.go`
- **Every plaintext byte verified by the proxy** (3 connections) — `docs/adr/0001-the-backend-is-hostile.md`
- **Envelope encryption: DEK wrapped by configured KEK** (3 connections) — `docs/adr/0002-one-data-key-per-object.md`
- **Key rotation is a configuration procedure** (3 connections) — `docs/adr/0002-one-data-key-per-object.md`
- **AES-256-GCM wrap with per-wrap 16-byte salt** (3 connections) — `docs/adr/0004-one-local-key-provider.md`
- **HKDF-SHA256 derived fingerprint and wrapping key** (3 connections) — `docs/adr/0004-one-local-key-provider.md`
- *... and 34 more nodes in this community*

## Relationships

- [Multipart Part Layout Decisions](Multipart_Part_Layout_Decisions.md) (17 shared connections)
- [Storage Format Integrity Guarantees](Storage_Format_Integrity_Guarantees.md) (14 shared connections)
- [ADR Web: Auth, Checksums, Config](ADR_Web-_Auth,_Checksums,_Config.md) (11 shared connections)
- [Filename Encryption Pass Engine](Filename_Encryption_Pass_Engine.md) (10 shared connections)
- [Changelog and Project Front Page](Changelog_and_Project_Front_Page.md) (9 shared connections)
- [Release and Test Discipline ADRs](Release_and_Test_Discipline_ADRs.md) (9 shared connections)
- [Filename Encryption Design](Filename_Encryption_Design.md) (7 shared connections)
- [Forward-or-Refuse Response Rules](Forward-or-Refuse_Response_Rules.md) (7 shared connections)
- [Transfer Bounds and Shutdown](Transfer_Bounds_and_Shutdown.md) (4 shared connections)
- [Documentation Homes and Ticket Lifecycle](Documentation_Homes_and_Ticket_Lifecycle.md) (3 shared connections)
- [Keygen and KEK Factory](Keygen_and_KEK_Factory.md) (3 shared connections)
- [Upload Length Guards and Exit Provider](Upload_Length_Guards_and_Exit_Provider.md) (2 shared connections)

## Source Files

- `DEVELOPER.md`
- `README.md`
- `deploy/helm/s3-encryption-proxy/templates/deployment.yaml`
- `docs/adr/0001-the-backend-is-hostile.md`
- `docs/adr/0002-one-data-key-per-object.md`
- `docs/adr/0003-objects-are-an-authenticated-segment-chain.md`
- `docs/adr/0004-one-local-key-provider.md`
- `docs/adr/0005-a-kms-key-is-a-provider.md`
- `docs/adr/0006-the-proxy-serves-any-s3-client.md`
- `docs/adr/0007-forward-it-or-refuse-it.md`
- `docs/adr/0008-every-response-describes-the-proxy.md`
- `docs/adr/0009-the-metadata-prefix-is-the-proxys-namespace.md`
- `docs/adr/README.md`
- `docs/operations/integrity.md`
- `docs/security/key-management.md`
- `docs/security/stored-objects.md`
- `docs/tickets/025-tink-kms-hcvault.md`
- `docs/tickets/033-out-of-band-recovery-path.md`
- `docs/tickets/038-s3-encryption-operator.md`
- `docs/tickets/040-managed-buckets.md`

## Audit Trail

- EXTRACTED: 182 (92%)
- INFERRED: 16 (8%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*