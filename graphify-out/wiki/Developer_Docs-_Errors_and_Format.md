# Developer Docs: Errors and Format

> 59 nodes · cohesion 0.06

## Key Concepts

- **ADR 0003: Objects Are an Authenticated Segment Chain** (35 connections) — `docs/adr/0003-objects-are-an-authenticated-segment-chain.md`
- **ADR 0011: The Proxy Owns the Part Layout** (26 connections) — `docs/adr/0011-the-proxy-owns-the-part-layout.md`
- **The storage format page** (17 connections) — `docs/developer/storage-format.md`
- **Errors page** (15 connections) — `docs/developer/errors.md`
- **Package map** (12 connections) — `docs/developer/package-map.md`
- **Request paths page** (12 connections) — `docs/developer/request-paths.md`
- **The client-driven multipart upload** (9 connections) — `docs/developer/multipart.md`
- **Developer documentation index** (9 connections) — `docs/developer/README.md`
- **Multipart uploads page** (8 connections) — `docs/developer/multipart.md`
- **The Trailer Authenticates the Plaintext Length and Checksum (D6)** (4 connections) — `docs/adr/0003-objects-are-an-authenticated-segment-chain.md`
- **A foreign object is refused, never guessed at (D4)** (4 connections) — `docs/adr/0017-stored-data-compatibility-is-not-owed.md`
- **ListParts answers a fabricated empty document with 200** (4 connections) — `docs/developer/errors.md`
- **A permanent object state is 4xx, a transient failure 5xx** (4 connections) — `docs/developer/errors.md`
- **internal/orchestration: the encryption facade the handlers call** (4 connections) — `docs/developer/package-map.md`
- **The ranged GET path** (4 connections) — `docs/developer/request-paths.md`
- **What is refused rather than pretended: 501, 405, 400** (4 connections) — `docs/developer/request-paths.md`
- **A range is planned into a window without the key** (4 connections) — `docs/developer/storage-format.md`
- **DEK Cache Keyed by a Digest of the Wrapped Key (D9)** (3 connections) — `docs/adr/0002-one-data-key-per-object.md`
- **Each Segment Carries Its Own Random 96-Bit Nonce (D3)** (3 connections) — `docs/adr/0003-objects-are-an-authenticated-segment-chain.md`
- **Server-Side Copy Refused with 422 NotSupportedWithEncryption (D9, D10)** (3 connections) — `docs/adr/0011-the-proxy-owns-the-part-layout.md`
- **The Short-Part Buffer, EntityTooSmall and SlowDown (D5)** (3 connections) — `docs/adr/0011-the-proxy-owns-the-part-layout.md`
- **A mid-stream fault is reported by aborting the body** (3 connections) — `docs/developer/errors.md`
- **Six refusals answer a bare text body with no S3 code** (3 connections) — `docs/developer/errors.md`
- **The five error codes the proxy defines itself** (3 connections) — `docs/developer/errors.md`
- **Every client failure is an S3 <Error> document** (3 connections) — `docs/developer/errors.md`
- *... and 34 more nodes in this community*

## Relationships

- [Authentication and Response ADRs](Authentication_and_Response_ADRs.md) (25 shared connections)
- [Performance Measurement Docs](Performance_Measurement_Docs.md) (10 shared connections)
- [Key Management ADRs](Key_Management_ADRs.md) (8 shared connections)
- [Exit Provider ADRs](Exit_Provider_ADRs.md) (7 shared connections)
- [Forward-or-Refuse ADRs](Forward-or-Refuse_ADRs.md) (7 shared connections)
- [Test Strategy Docs](Test_Strategy_Docs.md) (7 shared connections)
- [Storage Format Decisions](Storage_Format_Decisions.md) (2 shared connections)
- [Hostile Backend Decisions](Hostile_Backend_Decisions.md) (2 shared connections)
- [Checksum and Trailer Decisions](Checksum_and_Trailer_Decisions.md) (2 shared connections)
- [Ticket Lifecycle ADR](Ticket_Lifecycle_ADR.md) (2 shared connections)
- [Filename Encryption ADR](Filename_Encryption_ADR.md) (2 shared connections)

## Source Files

- `docs/adr/0002-one-data-key-per-object.md`
- `docs/adr/0003-objects-are-an-authenticated-segment-chain.md`
- `docs/adr/0005-a-kms-key-is-a-provider.md`
- `docs/adr/0007-forward-it-or-refuse-it.md`
- `docs/adr/0011-the-proxy-owns-the-part-layout.md`
- `docs/adr/0012-client-checksums-are-verified-never-forwarded.md`
- `docs/adr/0017-stored-data-compatibility-is-not-owed.md`
- `docs/adr/0025-leaving-is-a-supported-mode.md`
- `docs/developer/README.md`
- `docs/developer/errors.md`
- `docs/developer/multipart.md`
- `docs/developer/package-map.md`
- `docs/developer/request-paths.md`
- `docs/developer/storage-format.md`

## Audit Trail

- EXTRACTED: 162 (95%)
- INFERRED: 8 (5%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*