# Test Strategy Docs

> 31 nodes · cohesion 0.08

## Key Concepts

- **Testing page** (17 connections) — `docs/developer/testing.md`
- **The HEAD path** (5 connections) — `docs/developer/request-paths.md`
- **S3EP_LICENSE_TOKEN is the one route for the license (D5)** (4 connections) — `docs/adr/0021-key-material-is-generated-never-committed.md`
- **The mutation-round convention for crypto changes** (4 connections) — `docs/developer/storage-format.md`
- **Invariant 2: the stored length is a pure function of the plaintext length** (4 connections) — `docs/developer/storage-format.md`
- **Assert what is stored, not only what round-trips** (4 connections) — `docs/developer/testing.md`
- **A Major Release Is Declared by the release:major Label** (3 connections) — `docs/adr/0018-a-major-release-is-declared-by-a-label.md`
- **Both the plain-HTTP and the TLS run must be green (D5)** (3 connections) — `docs/adr/0019-integration-and-e2e-tests-are-the-product.md`
- **Unit coverage is a floor, not a goal (D13)** (3 connections) — `docs/adr/0019-integration-and-e2e-tests-are-the-product.md`
- **The suites are part of the product, not convenience (D1)** (3 connections) — `docs/adr/0019-integration-and-e2e-tests-are-the-product.md`
- **A listing reports the stored size verbatim under exit (D8)** (3 connections) — `docs/adr/0025-leaving-is-a-supported-mode.md`
- **Listings still carry the stored size** (3 connections) — `docs/developer/request-paths.md`
- **The build tag separates the layers, not -short** (3 connections) — `docs/developer/testing.md`
- **Coverage has two sources in two processes** (3 connections) — `docs/developer/testing.md`
- **Two suites start the proxy in process** (3 connections) — `docs/developer/testing.md`
- **The integration suites and their subjects** (3 connections) — `docs/developer/testing.md`
- **Why the TLS run exists** (3 connections) — `docs/developer/testing.md`
- **The upgrade is rehearsed on a running stack (D6)** (2 connections) — `docs/adr/0017-stored-data-compatibility-is-not-owed.md`
- **Denominator correction in coverage reporting** (2 connections) — `docs/adr/0019-integration-and-e2e-tests-are-the-product.md`
- **Every test is shown to fail without its change (D11)** (2 connections) — `docs/adr/0019-integration-and-e2e-tests-are-the-product.md`
- **STREAMING-UNSIGNED-PAYLOAD-TRAILER framing is TLS-only** (2 connections) — `docs/adr/0019-integration-and-e2e-tests-are-the-product.md`
- **Conditional headers are dropped, so a race loses a write** (2 connections) — `docs/developer/request-paths.md`
- **A test that pins a defect says so** (2 connections) — `docs/developer/testing.md`
- **Four test layers: unit, integration, integration over TLS, e2e** (2 connections) — `docs/developer/testing.md`
- **make lint compiles none of the tagged trees** (2 connections) — `docs/developer/testing.md`
- *... and 6 more nodes in this community*

## Relationships

- [Authentication and Response ADRs](Authentication_and_Response_ADRs.md) (10 shared connections)
- [Developer Docs: Errors and Format](Developer_Docs-_Errors_and_Format.md) (7 shared connections)
- [Exit Provider ADRs](Exit_Provider_ADRs.md) (3 shared connections)
- [Performance Measurement Docs](Performance_Measurement_Docs.md) (3 shared connections)
- [Key Management ADRs](Key_Management_ADRs.md) (1 shared connections)

## Source Files

- `docs/adr/0017-stored-data-compatibility-is-not-owed.md`
- `docs/adr/0018-a-major-release-is-declared-by-a-label.md`
- `docs/adr/0019-integration-and-e2e-tests-are-the-product.md`
- `docs/adr/0021-key-material-is-generated-never-committed.md`
- `docs/adr/0025-leaving-is-a-supported-mode.md`
- `docs/developer/request-paths.md`
- `docs/developer/storage-format.md`
- `docs/developer/testing.md`

## Audit Trail

- EXTRACTED: 53 (88%)
- INFERRED: 7 (12%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*