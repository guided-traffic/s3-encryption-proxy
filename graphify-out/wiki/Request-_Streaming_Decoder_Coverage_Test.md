# Request: Streaming Decoder Coverage Test

> 25 nodes · cohesion 0.11

## Key Concepts

- **Release 5.0.0: incompatible stored format, strict configuration** (39 connections) — `CHANGELOG.md`
- **Entity tag as change token with -0 suffix (ADR 0032)** (4 connections) — `CHANGELOG.md`
- **Every declared upload checksum verified against plaintext (ADR 0012)** (4 connections) — `CHANGELOG.md`
- **optimizations.max_request_document_size** (4 connections) — `docs/operations/s3-api.md`
- **E2E suites: Velero (13), rclone (28), s3cmd (19)** (3 connections) — `CHANGELOG.md`
- **Tail-first whole-object read with sealed CRC32C** (3 connections) — `CHANGELOG.md`
- **Suites assert target behaviour, none skipped (ADR 0031, ADR 0019)** (3 connections) — `CHANGELOG.md`
- **s3_security.verify_payload_hash** (3 connections) — `docs/operations/integrity.md`
- **aes_key must be base64 of 32 random bytes** (2 connections) — `CHANGELOG.md`
- **S3 client authentication (2.1.0)** (2 connections) — `CHANGELOG.md`
- **Conformance tests against MinIO, LocalStack, Wasabi (ADR 0027)** (2 connections) — `CHANGELOG.md`
- **${VAR} reference is the only environment mechanism; no S3EP_ overrides** (2 connections) — `CHANGELOG.md`
- **Image ships config/default.yaml and an ENTRYPOINT** (2 connections) — `CHANGELOG.md`
- **optimizations.multipart_short_part_buffer_size (process-wide budget)** (2 connections) — `CHANGELOG.md`
- **max_presign_expiry_seconds and max_clock_skew_seconds (no 0)** (2 connections) — `CHANGELOG.md`
- **x-amz-request-id on every response and RequestId in error documents** (2 connections) — `CHANGELOG.md`
- **SigV4 canonical query sorted by name, whitespace collapsed** (2 connections) — `CHANGELOG.md`
- **Chart ships no NetworkPolicy (ADR 0030)** (1 connections) — `CHANGELOG.md`
- **Conditional requests honoured on every verb** (1 connections) — `CHANGELOG.md`
- **Bucket listing as S3 ListBucketResult with plaintext size** (1 connections) — `CHANGELOG.md`
- **Metrics: 13 dead series removed, Go runtime/process collectors restored** (1 connections) — `CHANGELOG.md`
- **response-* query overrides honoured on HEAD** (1 connections) — `CHANGELOG.md`
- **s3_backend mapping becomes s3_backends list (one entry)** (1 connections) — `CHANGELOG.md`
- **Query string containing ';' refused with 400 InvalidArgument** (1 connections) — `CHANGELOG.md`
- **Storage headers, tagging, retention, legal hold forwarded; SSE-C refused 501** (1 connections) — `CHANGELOG.md`

## Relationships

- [Object: Range (2)](Object-_Range_2.md) (5 shared connections)
- [Misc (31)](Misc_31.md) (4 shared connections)
- [Changelog: Configuration Refusals](Changelog-_Configuration_Refusals.md) (3 shared connections)
- [Changelog: Shutdown And Listener Budgets](Changelog-_Shutdown_And_Listener_Budgets.md) (3 shared connections)
- [S3 API Behaviour](S3_API_Behaviour.md) (2 shared connections)
- [Changelog: Release 4.0.0 Hardening](Changelog-_Release_4.0.0_Hardening.md) (1 shared connections)
- [Changelog: Providers And Licence](Changelog-_Providers_And_Licence.md) (1 shared connections)
- [Middleware: S3Auth Robust](Middleware-_S3Auth_Robust.md) (1 shared connections)
- [Exit Provider and Session Lifecycle](Exit_Provider_and_Session_Lifecycle.md) (1 shared connections)

## Source Files

- `CHANGELOG.md`
- `docs/operations/integrity.md`
- `docs/operations/s3-api.md`

## Audit Trail

- EXTRACTED: 49 (89%)
- INFERRED: 6 (11%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*