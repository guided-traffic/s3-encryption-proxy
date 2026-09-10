# Performance Measurement Docs

> 38 nodes · cohesion 0.07

## Key Concepts

- **Performance page** (14 connections) — `docs/developer/performance.md`
- **ADR 0024: An Upload Forwards While It Receives** (11 connections) — `docs/adr/README.md`
- **The PUT path** (8 connections) — `docs/developer/request-paths.md`
- **The local baseline suite with its own build tag (D18)** (6 connections) — `docs/adr/0020-performance-is-measured-before-and-after.md`
- **The internal multipart producer** (6 connections) — `docs/developer/multipart.md`
- **The resident-memory bound is a test that may fail a build (D14)** (5 connections) — `docs/adr/0020-performance-is-measured-before-and-after.md`
- **No performance measurement fails a build (D11)** (5 connections) — `docs/adr/0020-performance-is-measured-before-and-after.md`
- **One machine-readable record and one human summary (D20)** (4 connections) — `docs/adr/0020-performance-is-measured-before-and-after.md`
- **A part is retained until acknowledged and replayed on retry (D5)** (4 connections) — `docs/adr/0024-an-upload-forwards-while-it-receives.md`
- **The three-leg upload comparison** (4 connections) — `docs/adr/0024-an-upload-forwards-while-it-receives.md`
- **The three-leg upload comparison instrument** (4 connections) — `docs/developer/performance.md`
- **Parts are segment-aligned** (4 connections) — `docs/developer/storage-format.md`
- **The perf-tagged baseline asserts nothing** (4 connections) — `docs/developer/testing.md`
- **GOMEMLIMIT is set explicitly, about 80% of the container limit (D15)** (3 connections) — `docs/adr/0020-performance-is-measured-before-and-after.md`
- **A run records the machine it ran on (D19)** (3 connections) — `docs/adr/0020-performance-is-measured-before-and-after.md`
- **In-flight memory is bounded and configured (D4)** (3 connections) — `docs/adr/0024-an-upload-forwards-while-it-receives.md`
- **An upload forwards bytes while still receiving them (D1)** (3 connections) — `docs/adr/0024-an-upload-forwards-while-it-receives.md`
- **S3EP_PERF_ALT_PROXY: the second proxy the instrument needs** (3 connections) — `docs/developer/performance.md`
- **A recorded run in perf-baseline/<timestamp>-<commit>/** (3 connections) — `docs/developer/performance.md`
- **The after column this release owes** (3 connections) — `docs/developer/performance.md`
- **Route on the plaintext length, never on the wire length** (3 connections) — `docs/developer/request-paths.md`
- **Invariant 3: a nonce is never reused under one key** (3 connections) — `docs/developer/storage-format.md`
- **No environment switch disarms an assertion (D4)** (2 connections) — `docs/adr/0019-integration-and-e2e-tests-are-the-product.md`
- **Absolute thresholds measure the runner, not the code** (2 connections) — `docs/adr/0020-performance-is-measured-before-and-after.md`
- **A performance change carries a before and an after (D1)** (2 connections) — `docs/adr/0020-performance-is-measured-before-and-after.md`
- *... and 13 more nodes in this community*

## Relationships

- [Authentication and Response ADRs](Authentication_and_Response_ADRs.md) (18 shared connections)
- [Developer Docs: Errors and Format](Developer_Docs-_Errors_and_Format.md) (10 shared connections)
- [Test Strategy Docs](Test_Strategy_Docs.md) (3 shared connections)
- [Key Management ADRs](Key_Management_ADRs.md) (1 shared connections)
- [Exit Provider ADRs](Exit_Provider_ADRs.md) (1 shared connections)

## Source Files

- `docs/adr/0019-integration-and-e2e-tests-are-the-product.md`
- `docs/adr/0020-performance-is-measured-before-and-after.md`
- `docs/adr/0024-an-upload-forwards-while-it-receives.md`
- `docs/adr/README.md`
- `docs/developer/multipart.md`
- `docs/developer/performance.md`
- `docs/developer/request-paths.md`
- `docs/developer/storage-format.md`
- `docs/developer/testing.md`

## Audit Trail

- EXTRACTED: 80 (94%)
- INFERRED: 5 (6%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*