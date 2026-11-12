# Middleware: S3Auth Robust

> 37 nodes · cohesion 0.07

## Key Concepts

- **ADR 0012: Client-supplied checksums are verified against the plaintext and never forwarded** (45 connections) — `docs/adr/0012-client-checksums-are-verified-never-forwarded.md`
- **Developer: Request paths** (31 connections) — `docs/developer/request-paths.md`
- **Upload checksum verifier reader** (11 connections) — `docs/developer/request-paths.md`
- **Client-leg checksum verification** (7 connections) — `docs/security/upload-integrity.md`
- **What is verified on every S3 request** (6 connections) — `docs/security/request-authentication.md`
- **Client Checksum Verified Against Plaintext (D1-D3)** (5 connections) — `docs/adr/0012-client-checksums-are-verified-never-forwarded.md`
- **fillPart()** (5 connections) — `internal/proxy/handlers/object/operations.go`
- **CRC-64/NVME slicing-by-8 table** (4 connections) — `docs/developer/request-paths.md`
- **response-* query parameter overrides** (4 connections) — `docs/developer/request-paths.md`
- **Short-body guard (declared length check, only io.EOF ends a part)** (4 connections) — `docs/developer/request-paths.md`
- **Client-declared checksums verified, never forwarded** (4 connections) — `docs/operations/integrity.md`
- **No Plaintext Checksum in Object Metadata (D9)** (3 connections) — `docs/adr/0012-client-checksums-are-verified-never-forwarded.md`
- **SigV4 Payload Hash Verified When Enabled (D15)** (3 connections) — `docs/adr/0012-client-checksums-are-verified-never-forwarded.md`
- **CompleteMultipartUpload reads body unverified** (3 connections) — `docs/developer/request-paths.md`
- **Upload integrity: the client leg** (3 connections) — `docs/security/upload-integrity.md`
- **400 BadDigest / 400 InvalidDigest Verdicts (D6)** (2 connections) — `docs/adr/0012-client-checksums-are-verified-never-forwarded.md`
- **Client Checksum Never Forwarded to Backend (D8)** (2 connections) — `docs/adr/0012-client-checksums-are-verified-never-forwarded.md`
- **DeleteObjects Requires a Body Digest (D14)** (2 connections) — `docs/adr/0012-client-checksums-are-verified-never-forwarded.md`
- **Verdict Lands Before Anything Is Committed (D7)** (2 connections) — `docs/adr/0012-client-checksums-are-verified-never-forwarded.md`
- **D9a aws-chunked decoding unconditional** (2 connections) — `docs/adr/0013-a-configuration-key-exists-only-if-code-reads-it.md`
- **Per-chunk aws-chunked signatures not verified** (2 connections) — `docs/adr/0014-authentication-is-sigv4-no-rate-limiting.md`
- **s3_security carries exactly three enforced keys** (2 connections) — `docs/adr/0014-authentication-is-sigv4-no-rate-limiting.md`
- **DELETE and DeleteObjects** (2 connections) — `docs/developer/request-paths.md`
- **The multipart verbs routing** (2 connections) — `docs/developer/request-paths.md`
- **Router SkipClean: a//b, a/./b and a/../b are distinct keys** (2 connections) — `docs/developer/request-paths.md`
- *... and 12 more nodes in this community*

## Relationships

- [SigV4 Authentication Rules](SigV4_Authentication_Rules.md) (11 shared connections)
- [S3 API Behaviour](S3_API_Behaviour.md) (10 shared connections)
- [Exit Provider and Session Lifecycle](Exit_Provider_and_Session_Lifecycle.md) (9 shared connections)
- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (9 shared connections)
- [ADR Corpus and Release History](ADR_Corpus_and_Release_History.md) (7 shared connections)
- [Integrity and Tail-First Read](Integrity_and_Tail-First_Read.md) (5 shared connections)
- [Client Library and Storage Format](Client_Library_and_Storage_Format.md) (3 shared connections)
- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (3 shared connections)
- [Whole-Object Read Window](Whole-Object_Read_Window.md) (2 shared connections)
- [Monitoring and Licence Removal](Monitoring_and_Licence_Removal.md) (2 shared connections)
- [Object: Storage Headers](Object-_Storage_Headers.md) (2 shared connections)
- [Orchestration: Providers Coverage Test (2)](Orchestration-_Providers_Coverage_Test_2.md) (2 shared connections)

## Source Files

- `docs/adr/0012-client-checksums-are-verified-never-forwarded.md`
- `docs/adr/0013-a-configuration-key-exists-only-if-code-reads-it.md`
- `docs/adr/0014-authentication-is-sigv4-no-rate-limiting.md`
- `docs/developer/request-paths.md`
- `docs/operations/integrity.md`
- `docs/security/request-authentication.md`
- `docs/security/upload-integrity.md`
- `internal/proxy/handlers/object/operations.go`

## Audit Trail

- EXTRACTED: 114 (93%)
- INFERRED: 9 (7%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*