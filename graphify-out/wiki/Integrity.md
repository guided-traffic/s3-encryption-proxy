# Integrity

> 19 nodes · cohesion 0.12

## Key Concepts

- **Filename encryption (directory segments only)** (9 connections) — `docs/tickets/017-filename-encryption.md`
- **Storage format s3ep-gcm-seg-v2** (8 connections) — `docs/operations/integrity.md`
- **Out-of-band recovery tool for a damaged object** (5 connections) — `docs/tickets/033-out-of-band-recovery-path.md`
- **Associated data binds segment index and object key** (4 connections) — `docs/operations/integrity.md`
- **s3ep-kek-fingerprint** (4 connections) — `docs/operations/integrity.md`
- **s3ep-dek-algorithm** (3 connections) — `docs/operations/integrity.md`
- **The load-bearing decryption inputs stay minimal** (3 connections) — `docs/tickets/033-out-of-band-recovery-path.md`
- **optimizations.multipart_session_idle_timeout** (2 connections) — `docs/operations/configuration.md`
- **s3ep-encrypted-dek** (2 connections) — `docs/operations/integrity.md`
- **metadata_key_prefix is the proxy's exclusive namespace** (2 connections) — `docs/operations/integrity.md`
- **CopyObject and UploadPartCopy answer 422 NotSupportedWithEncryption** (2 connections) — `docs/operations/s3-api.md`
- **Enabling the feature is a rename, never a re-encryption** (2 connections) — `docs/tickets/017-filename-encryption.md`
- **The multipart sweeper calls the SDK client outside the interface** (2 connections) — `docs/tickets/017-filename-encryption.md`
- **s3ep-kek-algorithm** (1 connections) — `docs/operations/integrity.md`
- **D-A The cryptographic primitive (AES-SIV)** (1 connections) — `docs/tickets/017-filename-encryption.md`
- **D-B A name domain bound into the associated data** (1 connections) — `docs/tickets/017-filename-encryption.md`
- **D-C The AAD must be injective** (1 connections) — `docs/tickets/017-filename-encryption.md`
- **D-E The explicit backend forwarder** (1 connections) — `docs/tickets/017-filename-encryption.md`
- **Damage inside the wrapped DEK is unrecoverable** (1 connections) — `docs/tickets/033-out-of-band-recovery-path.md`

## Relationships

- [Hardening History](Hardening_History.md) (3 shared connections)
- [Client E2E Verdicts](Client_E2E_Verdicts.md) (3 shared connections)
- [Monitoring](Monitoring.md) (2 shared connections)
- [Configuration](Configuration.md) (2 shared connections)
- [027 Whole Object Read](027_Whole_Object_Read.md) (1 shared connections)
- [Testing](Testing.md) (1 shared connections)

## Source Files

- `docs/operations/configuration.md`
- `docs/operations/integrity.md`
- `docs/operations/s3-api.md`
- `docs/tickets/017-filename-encryption.md`
- `docs/tickets/033-out-of-band-recovery-path.md`

## Audit Trail

- EXTRACTED: 27 (82%)
- INFERRED: 6 (18%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*