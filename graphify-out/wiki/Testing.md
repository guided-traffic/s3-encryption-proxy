# Testing

> 18 nodes · cohesion 0.12

## Key Concepts

- **SSE-C on every verb, or not at all** (6 connections) — `docs/tickets/026-sse-c-passthrough.md`
- **Conformance suite (any backend)** (4 connections) — `docs/developer/testing.md`
- **BACKEND DEVIATION log instead of a skip** (3 connections) — `docs/developer/testing.md`
- **Conformance cost rule and Budget.Authorize** (3 connections) — `docs/developer/testing.md`
- **Five test layers** (3 connections) — `docs/developer/testing.md`
- **Storage headers on upload: forward it or refuse it** (3 connections) — `docs/operations/s3-api.md`
- **Build tags separate the layers, not -short** (2 connections) — `docs/developer/testing.md`
- **x-amz-expected-bucket-owner forwarded on every verb** (2 connections) — `docs/operations/s3-api.md`
- **Client part sizes must cover whole 64 KiB segments** (2 connections) — `docs/operations/s3-api.md`
- **multipart_short_part_buffer_size bounds held last parts** (2 connections) — `docs/operations/s3-api.md`
- **SSE-C headers answer 501 NotImplemented** (2 connections) — `docs/operations/s3-api.md`
- **Two-process coverage merge, one toolchain** (1 connections) — `docs/developer/testing.md`
- **LINT_TAGS covers the tagged trees** (1 connections) — `docs/developer/testing.md`
- **MinIO is the oracle, AWS docs are the specification** (1 connections) — `docs/developer/testing.md`
- **Paid-run bucket policy (scoped sub-user)** (1 connections) — `docs/developer/testing.md`
- **Part numbers run 1 to 9999** (1 connections) — `docs/operations/s3-api.md`
- **SSE-C buys compatibility, not security** (1 connections) — `docs/tickets/026-sse-c-passthrough.md`
- **The customer key is never logged, stored or cached** (1 connections) — `docs/tickets/026-sse-c-passthrough.md`

## Relationships

- [Conformance Run](Conformance_Run.md) (1 shared connections)
- [Monitoring](Monitoring.md) (1 shared connections)
- [Integrity](Integrity.md) (1 shared connections)

## Source Files

- `docs/developer/testing.md`
- `docs/operations/s3-api.md`
- `docs/tickets/026-sse-c-passthrough.md`

## Audit Trail

- EXTRACTED: 17 (81%)
- INFERRED: 4 (19%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*