# Key Management ADRs

> 51 nodes · cohesion 0.05

## Key Concepts

- **ADR 0002: One Data Key per Object** (21 connections) — `docs/adr/0002-one-data-key-per-object.md`
- **ADR 0004: One Local Key Provider** (20 connections) — `docs/adr/0004-one-local-key-provider.md`
- **ADR 0009: The Metadata Prefix Is the Proxy's Namespace** (20 connections) — `docs/adr/0009-the-metadata-prefix-is-the-proxys-namespace.md`
- **ADR 0016: The License Is a Startup Gate** (20 connections) — `docs/adr/0016-the-license-is-a-startup-gate.md`
- **ADR 0021: Key Material Is Generated, Never Committed** (16 connections) — `docs/adr/README.md`
- **An Unworkable Configuration Refuses to Start, Never Normalised (D7)** (5 connections) — `docs/adr/0013-a-configuration-key-exists-only-if-code-reads-it.md`
- **InvalidObjectState / HTTP 403 for a Foreign or Unauthenticated Object (D10, D10a)** (4 connections) — `docs/adr/0003-objects-are-an-authenticated-segment-chain.md`
- **The Proxy Refuses to Start Without a Valid License (D1)** (4 connections) — `docs/adr/0016-the-license-is-a-startup-gate.md`
- **Key Rotation Is a Configuration Procedure, Not an Operation (D7)** (3 connections) — `docs/adr/0002-one-data-key-per-object.md`
- **Provider Selection by s3ep-kek-fingerprint (D4, D5)** (3 connections) — `docs/adr/0002-one-data-key-per-object.md`
- **aes_key Is Base64 of Exactly 32 Bytes, Admitted at Startup (D3, D4, D5)** (3 connections) — `docs/adr/0004-one-local-key-provider.md`
- **The none Pass-Through Provider (D10, superseded by ADR 0025)** (3 connections) — `docs/adr/0004-one-local-key-provider.md`
- **Custody by Injection Is Not a KMS (D2)** (3 connections) — `docs/adr/0005-a-kms-key-is-a-provider.md`
- **The Prefix Is Validated at Startup and Never Normalised (D2, D3, D4)** (3 connections) — `docs/adr/0009-the-metadata-prefix-is-the-proxys-namespace.md`
- **A Running Proxy Stops When Its License Expires (D4)** (3 connections) — `docs/adr/0016-the-license-is-a-startup-gate.md`
- **A published key is rotated, never un-published (D7)** (3 connections) — `docs/adr/0021-key-material-is-generated-never-committed.md`
- **Subsystems with no developer page (SigV4, config, license, monitoring)** (3 connections) — `docs/developer/README.md`
- **The response is composed from an allowlist, never proxied** (3 connections) — `docs/developer/request-paths.md`
- **Fail Closed on Foreign Objects (D5)** (2 connections) — `docs/adr/0001-the-backend-is-hostile.md`
- **The Key Layer Fails Closed (D11)** (2 connections) — `docs/adr/0002-one-data-key-per-object.md`
- **The Key Encryption Key Is the Single Point of Total Loss** (2 connections) — `docs/adr/0002-one-data-key-per-object.md`
- **s3ep-encrypted-dek Travels with the Object (D3)** (2 connections) — `docs/adr/0002-one-data-key-per-object.md`
- **The aes Provider Is the One Local Key Provider (D1, D2)** (2 connections) — `docs/adr/0004-one-local-key-provider.md`
- **AES-256-GCM Wrap with a Per-Wrap Salt: salt|nonce|ciphertext|tag (D7, D8)** (2 connections) — `docs/adr/0004-one-local-key-provider.md`
- **HKDF-SHA256 Derives the Fingerprint and the Wrapping Key (D6)** (2 connections) — `docs/adr/0004-one-local-key-provider.md`
- *... and 26 more nodes in this community*

## Relationships

- [Authentication and Response ADRs](Authentication_and_Response_ADRs.md) (36 shared connections)
- [Developer Docs: Errors and Format](Developer_Docs-_Errors_and_Format.md) (8 shared connections)
- [Exit Provider ADRs](Exit_Provider_ADRs.md) (8 shared connections)
- [Hostile Backend Decisions](Hostile_Backend_Decisions.md) (2 shared connections)
- [Forward-or-Refuse ADRs](Forward-or-Refuse_ADRs.md) (2 shared connections)
- [Filename Encryption ADR](Filename_Encryption_ADR.md) (2 shared connections)
- [Storage Format Decisions](Storage_Format_Decisions.md) (1 shared connections)
- [Performance Measurement Docs](Performance_Measurement_Docs.md) (1 shared connections)
- [Test Strategy Docs](Test_Strategy_Docs.md) (1 shared connections)

## Source Files

- `docs/adr/0001-the-backend-is-hostile.md`
- `docs/adr/0002-one-data-key-per-object.md`
- `docs/adr/0003-objects-are-an-authenticated-segment-chain.md`
- `docs/adr/0004-one-local-key-provider.md`
- `docs/adr/0005-a-kms-key-is-a-provider.md`
- `docs/adr/0009-the-metadata-prefix-is-the-proxys-namespace.md`
- `docs/adr/0011-the-proxy-owns-the-part-layout.md`
- `docs/adr/0013-a-configuration-key-exists-only-if-code-reads-it.md`
- `docs/adr/0016-the-license-is-a-startup-gate.md`
- `docs/adr/0021-key-material-is-generated-never-committed.md`
- `docs/adr/README.md`
- `docs/developer/README.md`
- `docs/developer/errors.md`
- `docs/developer/request-paths.md`

## Audit Trail

- EXTRACTED: 125 (95%)
- INFERRED: 6 (5%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*