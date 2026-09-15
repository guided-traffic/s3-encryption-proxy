# Hostile Backend Threat Model

> 39 nodes · cohesion 0.06

## Key Concepts

- **ADR 0001 The backend is hostile** (41 connections) — `SECURITY_ARCHITECTURE.md`
- **ADR 0026 The proxy terminates TLS at its own Service** (16 connections) — `SECURITY_ARCHITECTURE.md`
- **s3ep-gcm-seg-v2 storage format (64 KiB AES-256-GCM segments)** (5 connections) — `docs/adr/0003-objects-are-an-authenticated-segment-chain.md`
- **ADR 0007 D11: A backend error behind a non-error status is answered as a failure** (4 connections) — `docs/adr/0007-forward-it-or-refuse-it.md`
- **A control that exists only in configuration is worse than none (D6)** (3 connections) — `docs/adr/0001-the-backend-is-hostile.md`
- **Fail closed on foreign objects (D5)** (3 connections) — `docs/adr/0001-the-backend-is-hostile.md`
- **Provider selection by s3ep-kek-fingerprint (D4, D14)** (3 connections) — `docs/adr/0002-one-data-key-per-object.md`
- **The 40-byte sealed trailer (plaintext length + CRC32C)** (3 connections) — `docs/adr/0003-objects-are-an-authenticated-segment-chain.md`
- **ADR 0008 D8: An error behind a non-error status is answered 500, with 304 the single carve-out** (3 connections) — `docs/adr/0008-every-response-describes-the-proxy.md`
- **The transform is deterministic, keyed and stateless (D3)** (3 connections) — `docs/adr/0023-filename-encryption-encrypts-directory-segments.md`
- **No fingerprint is special-cased on the read path (D6, D7)** (3 connections) — `docs/adr/0025-leaving-is-a-supported-mode.md`
- **config/exit-example.yaml (the way out of the product)** (2 connections) — `config/exit-example.yaml`
- **The aes provider stays listed beside exit or old objects stop being readable** (2 connections) — `config/exit-example.yaml`
- **The exit provider (the way out, deciding per object)** (2 connections) — `docs/adr/0001-the-backend-is-hostile.md`
- **Rollback and deletion are not defended, by construction** (2 connections) — `docs/adr/0001-the-backend-is-hostile.md`
- **Verification at the granularity of the read that asked for it (D3)** (2 connections) — `docs/adr/0001-the-backend-is-hostile.md`
- **The key layer fails closed (D11)** (2 connections) — `docs/adr/0002-one-data-key-per-object.md`
- **Exactly one stored value is an input to decryption (D13)** (2 connections) — `docs/adr/0002-one-data-key-per-object.md`
- **x-amz-checksum-crc32c answered on write as well as on read (D16)** (2 connections) — `docs/adr/0003-objects-are-an-authenticated-segment-chain.md`
- **403 InvalidObjectState on a foreign object or unauthenticated key material (D10, D10a)** (2 connections) — `docs/adr/0003-objects-are-an-authenticated-segment-chain.md`
- **Ranged read fetches only the segments the range covers (D9)** (2 connections) — `docs/adr/0003-objects-are-an-authenticated-segment-chain.md`
- **Associated data: format id, object key, segment index; no bucket (D4, D5)** (2 connections) — `docs/adr/0003-objects-are-an-authenticated-segment-chain.md`
- **Tail-first read (D14): bytes=-65604 then If-Match, HEAD bytes=-40** (2 connections) — `docs/adr/0003-objects-are-an-authenticated-segment-chain.md`
- **A Backend Error Behind a Non-Error Status** (2 connections) — `docs/adr/0007-forward-it-or-refuse-it.md`
- **Encryption at rest is asserted by reading the backend directly (D6)** (2 connections) — `docs/adr/0019-integration-and-e2e-tests-are-the-product.md`
- *... and 14 more nodes in this community*

## Relationships

- [KEK Providers and Key Rotation](KEK_Providers_and_Key_Rotation.md) (8 shared connections)
- [Contributor Guide and KMS Provider ADR](Contributor_Guide_and_KMS_Provider_ADR.md) (5 shared connections)
- [Release 5.0.0 Breaking Changes](Release_5.0.0_Breaking_Changes.md) (5 shared connections)
- [Response Composition Rules](Response_Composition_Rules.md) (5 shared connections)
- [Proxy-Owned Part Layout](Proxy-Owned_Part_Layout.md) (5 shared connections)
- [Forward-or-Refuse and CI Gates](Forward-or-Refuse_and_CI_Gates.md) (4 shared connections)
- [Any-S3-Client Scope and E2E Rules](Any-S3-Client_Scope_and_E2E_Rules.md) (3 shared connections)
- [Network Boundary and HA Store](Network_Boundary_and_HA_Store.md) (3 shared connections)
- [SigV4 Authentication Rules](SigV4_Authentication_Rules.md) (2 shared connections)
- [Documentation and Release Process Rules](Documentation_and_Release_Process_Rules.md) (2 shared connections)
- [KEK Fingerprint and Client Checksums](KEK_Fingerprint_and_Client_Checksums.md) (1 shared connections)
- [PUT Routing and Short-Part Budget](PUT_Routing_and_Short-Part_Budget.md) (1 shared connections)

## Source Files

- `SECURITY_ARCHITECTURE.md`
- `config/exit-example.yaml`
- `docs/adr/0001-the-backend-is-hostile.md`
- `docs/adr/0002-one-data-key-per-object.md`
- `docs/adr/0003-objects-are-an-authenticated-segment-chain.md`
- `docs/adr/0007-forward-it-or-refuse-it.md`
- `docs/adr/0008-every-response-describes-the-proxy.md`
- `docs/adr/0019-integration-and-e2e-tests-are-the-product.md`
- `docs/adr/0023-filename-encryption-encrypts-directory-segments.md`
- `docs/adr/0025-leaving-is-a-supported-mode.md`
- `docs/adr/0026-the-proxy-terminates-tls-at-its-own-service.md`

## Audit Trail

- EXTRACTED: 81 (92%)
- INFERRED: 7 (8%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*