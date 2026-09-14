# Authentication and Response ADRs

> 65 nodes · cohesion 0.07

## Key Concepts

- **ADR 0020: Performance Is Measured Before and After** (34 connections) — `docs/adr/README.md`
- **ADR 0013: A Configuration Key Exists Only If Code Reads It** (33 connections) — `docs/adr/0013-a-configuration-key-exists-only-if-code-reads-it.md`
- **ADR 0019: Integration and E2E Tests Are the Product** (31 connections) — `docs/adr/README.md`
- **Architecture Decision Records Index** (31 connections) — `docs/adr/README.md`
- **ADR 0001: The S3 Backend Is Hostile** (30 connections) — `docs/adr/0001-the-backend-is-hostile.md`
- **ADR 0012: Client Checksums Are Verified, Never Forwarded** (25 connections) — `docs/adr/0012-client-checksums-are-verified-never-forwarded.md`
- **ADR 0010: Sizes and Listings Describe the Plaintext** (24 connections) — `docs/adr/0010-sizes-and-listings-describe-the-plaintext.md`
- **ADR 0005: A KMS-Backed KEK Is a Provider, Not a Mode** (23 connections) — `docs/adr/0005-a-kms-key-is-a-provider.md`
- **ADR 0006: The Proxy Serves Any S3 Client** (20 connections) — `docs/adr/0006-the-proxy-serves-any-s3-client.md`
- **ADR 0014: Authentication Is SigV4, No Rate Limiting** (19 connections) — `docs/adr/0014-authentication-is-sigv4-no-rate-limiting.md`
- **ADR 0008: Every Response Describes the Proxy** (18 connections) — `docs/adr/0008-every-response-describes-the-proxy.md`
- **ADR 0015: A Transfer Is Bounded by the Client and by Shutdown** (16 connections) — `docs/adr/0015-a-transfer-is-bounded-by-the-client-and-by-shutdown.md`
- **ADR 0023: Filename Encryption Encrypts Directory Segments** (14 connections) — `docs/adr/README.md`
- **ADR 0018: A Major Release Is Declared by a Label** (12 connections) — `docs/adr/README.md`
- **The Proxy Serves Any S3 Client (D1)** (5 connections) — `docs/adr/0006-the-proxy-serves-any-s3-client.md`
- **Rollback and Deletion Are Undefended by Construction** (3 connections) — `docs/adr/0001-the-backend-is-hostile.md`
- **No Rate Limiting and No Per-Address Blocking (D7, D12)** (3 connections) — `docs/adr/0014-authentication-is-sigv4-no-rate-limiting.md`
- **No Wall-Clock Budget on a Request or Response Body (D1)** (3 connections) — `docs/adr/0015-a-transfer-is-bounded-by-the-client-and-by-shutdown.md`
- **Encryption at rest is asserted by reading the backend (D6)** (3 connections) — `docs/adr/0019-integration-and-e2e-tests-are-the-product.md`
- **ADR Section Format** (3 connections) — `docs/adr/README.md`
- **An ADR Carries No References into the Code** (3 connections) — `docs/adr/README.md`
- **The Bucket Is Not in the Associated Data (D5)** (2 connections) — `docs/adr/0003-objects-are-an-authenticated-segment-chain.md`
- **Every KMS Call Carries an Explicit Timeout (D7)** (2 connections) — `docs/adr/0005-a-kms-key-is-a-provider.md`
- **The End-to-End Suite Proves One Client, Never the Scope (D5)** (2 connections) — `docs/adr/0006-the-proxy-serves-any-s3-client.md`
- **The Backend Account Never Appears in a Response Document (D10)** (2 connections) — `docs/adr/0008-every-response-describes-the-proxy.md`
- *... and 40 more nodes in this community*

## Relationships

- [Key Management ADRs](Key_Management_ADRs.md) (36 shared connections)
- [Forward-or-Refuse ADRs](Forward-or-Refuse_ADRs.md) (26 shared connections)
- [Developer Docs: Errors and Format](Developer_Docs-_Errors_and_Format.md) (25 shared connections)
- [Performance Measurement Docs](Performance_Measurement_Docs.md) (18 shared connections)
- [Exit Provider ADRs](Exit_Provider_ADRs.md) (12 shared connections)
- [Test Strategy Docs](Test_Strategy_Docs.md) (10 shared connections)
- [Ticket Lifecycle ADR](Ticket_Lifecycle_ADR.md) (7 shared connections)
- [Hostile Backend Decisions](Hostile_Backend_Decisions.md) (5 shared connections)
- [Checksum and Trailer Decisions](Checksum_and_Trailer_Decisions.md) (3 shared connections)
- [Storage Format Decisions](Storage_Format_Decisions.md) (2 shared connections)
- [Filename Encryption ADR](Filename_Encryption_ADR.md) (2 shared connections)

## Source Files

- `docs/adr/0001-the-backend-is-hostile.md`
- `docs/adr/0003-objects-are-an-authenticated-segment-chain.md`
- `docs/adr/0005-a-kms-key-is-a-provider.md`
- `docs/adr/0006-the-proxy-serves-any-s3-client.md`
- `docs/adr/0008-every-response-describes-the-proxy.md`
- `docs/adr/0010-sizes-and-listings-describe-the-plaintext.md`
- `docs/adr/0012-client-checksums-are-verified-never-forwarded.md`
- `docs/adr/0013-a-configuration-key-exists-only-if-code-reads-it.md`
- `docs/adr/0014-authentication-is-sigv4-no-rate-limiting.md`
- `docs/adr/0015-a-transfer-is-bounded-by-the-client-and-by-shutdown.md`
- `docs/adr/0019-integration-and-e2e-tests-are-the-product.md`
- `docs/adr/0020-performance-is-measured-before-and-after.md`
- `docs/adr/README.md`

## Audit Trail

- EXTRACTED: 277 (98%)
- INFERRED: 6 (2%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*