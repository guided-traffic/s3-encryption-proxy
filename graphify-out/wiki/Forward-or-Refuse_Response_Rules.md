# Forward-or-Refuse Response Rules

> 45 nodes · cohesion 0.06

## Key Concepts

- **ADR 0007: Forward it or refuse it** (38 connections) — `docs/tickets/037-multiple-backends.md`
- **ADR 0008: every response describes the proxy** (25 connections) — `DEVELOPER.md`
- **Explicit refusals instead of misleading success** (8 connections) — `docs/security/refusals.md`
- **Rule 2: a control that exists only in configuration or documentation is worse than none** (8 connections) — `docs/security/threat-model.md`
- **Backend operations the proxy calls (privilege footprint)** (6 connections) — `docs/security/tenancy-and-privilege.md`
- **Backend header restated by what it describes** (4 connections) — `docs/adr/0008-every-response-describes-the-proxy.md`
- **Deviation never overrides honesty** (4 connections) — `docs/adr/0036-a-response-follows-s3-deviates-for-the-client-and-is-never-a-break.md`
- **x-amz-expected-bucket-owner set in every s3 Input literal** (4 connections) — `docs/developer/request-paths.md`
- **s3_backends list shape shipped in 5.0.0, one entry read** (4 connections) — `docs/tickets/037-multiple-backends.md`
- **bucket/handler.go** (4 connections) — `internal/proxy/handlers/bucket/handler.go`
- **TestEveryBackendCallCarriesTheOwnerGuard()** (4 connections) — `internal/proxy/request/bucketowner_guard_test.go`
- **Error behind non-error status answered 500 (304 carve-out)** (3 connections) — `docs/adr/0008-every-response-describes-the-proxy.md`
- **Unreachable or unverifiable backend answers 500 InternalError** (3 connections) — `docs/adr/0037-the-backend-leg-is-trusted-explicitly-and-its-failures-are-named.md`
- **S3 backend interface (52 SDK methods)** (3 connections) — `docs/developer/package-map.md`
- **x-amz-expected-bucket-owner carried on every backend call** (3 connections) — `docs/security/refusals.md`
- **bucketowner.go** (3 connections) — `internal/proxy/request/bucketowner.go`
- **bucketowner_guard_test.go** (3 connections) — `internal/proxy/request/bucketowner_guard_test.go`
- **isOwnerHeaderCall()** (3 connections) — `internal/proxy/request/bucketowner_guard_test.go`
- **Response timestamps via response.S3Timestamp, omitempty for absent values** (2 connections) — `DEVELOPER.md`
- **Conditional request headers honoured** (2 connections) — `docs/adr/0007-forward-it-or-refuse-it.md`
- **Backend error under non-error status answered as failure** (2 connections) — `docs/adr/0007-forward-it-or-refuse-it.md`
- **?tagging, ?retention, ?legal-hold passthrough** (2 connections) — `docs/adr/0007-forward-it-or-refuse-it.md`
- **Ten storage headers forwarded on every upload path** (2 connections) — `docs/adr/0007-forward-it-or-refuse-it.md`
- **A refusal says what is true** (2 connections) — `docs/adr/0007-forward-it-or-refuse-it.md`
- **Metadata namespace stripped from GET/HEAD/ranged responses** (2 connections) — `docs/adr/0008-every-response-describes-the-proxy.md`
- *... and 20 more nodes in this community*

## Relationships

- [Multipart Part Layout Decisions](Multipart_Part_Layout_Decisions.md) (11 shared connections)
- [ADR Web: Auth, Checksums, Config](ADR_Web-_Auth,_Checksums,_Config.md) (9 shared connections)
- [Storage Format Integrity Guarantees](Storage_Format_Integrity_Guarantees.md) (8 shared connections)
- [Hostile Backend and Key Material ADRs](Hostile_Backend_and_Key_Material_ADRs.md) (7 shared connections)
- [Release and Test Discipline ADRs](Release_and_Test_Discipline_ADRs.md) (6 shared connections)
- [Filename Encryption Design](Filename_Encryption_Design.md) (4 shared connections)
- [Changelog and Project Front Page](Changelog_and_Project_Front_Page.md) (2 shared connections)
- [Filename Encryption Pass Engine](Filename_Encryption_Pass_Engine.md) (2 shared connections)
- [Multipart Handler Wiring](Multipart_Handler_Wiring.md) (2 shared connections)
- [Service TLS and Operator Certificates](Service_TLS_and_Operator_Certificates.md) (1 shared connections)
- [Object Sub-Resource Dispatch](Object_Sub-Resource_Dispatch.md) (1 shared connections)
- [Bucket ACL and Accelerate Handlers](Bucket_ACL_and_Accelerate_Handlers.md) (1 shared connections)

## Source Files

- `DEVELOPER.md`
- `docs/adr/0007-forward-it-or-refuse-it.md`
- `docs/adr/0008-every-response-describes-the-proxy.md`
- `docs/adr/0009-the-metadata-prefix-is-the-proxys-namespace.md`
- `docs/adr/0036-a-response-follows-s3-deviates-for-the-client-and-is-never-a-break.md`
- `docs/adr/0037-the-backend-leg-is-trusted-explicitly-and-its-failures-are-named.md`
- `docs/developer/package-map.md`
- `docs/developer/request-paths.md`
- `docs/developer/testing.md`
- `docs/security/operational-security.md`
- `docs/security/refusals.md`
- `docs/security/tenancy-and-privilege.md`
- `docs/security/threat-model.md`
- `docs/tickets/037-multiple-backends.md`
- `docs/tickets/040-managed-buckets.md`
- `internal/proxy/handlers/bucket/handler.go`
- `internal/proxy/handlers/bucket/operations.go`
- `internal/proxy/interfaces/s3_backend.go`
- `internal/proxy/request/bucketowner.go`
- `internal/proxy/request/bucketowner_guard_test.go`

## Audit Trail

- EXTRACTED: 107 (92%)
- INFERRED: 9 (8%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*