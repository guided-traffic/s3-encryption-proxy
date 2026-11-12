# S3 API Behaviour

> 84 nodes · cohesion 0.03

## Key Concepts

- **ADR 0007: Forward it or refuse it** (63 connections) — `docs/tickets/017-filename-encryption.md`
- **ADR 0008: Every response describes the proxy** (42 connections) — `docs/adr/0008-every-response-describes-the-proxy.md`
- **ADR 0009: The metadata prefix is the proxy namespace** (33 connections) — `docs/adr/0009-the-metadata-prefix-is-the-proxys-namespace.md`
- **ADR 0032: The entity tag is a change token** (23 connections) — `docs/tickets/037-multiple-backends.md`
- **Operations: S3 API behaviour** (22 connections) — `docs/operations/s3-api.md`
- **Operating the proxy (operations index)** (11 connections) — `docs/operations/README.md`
- **What the proxy guarantees about your bytes** (10 connections) — `docs/operations/integrity.md`
- **Forward it or refuse it, never silently drop** (7 connections) — `docs/adr/0007-forward-it-or-refuse-it.md`
- **x-amz-expected-bucket-owner set in every s3 Input literal** (7 connections) — `docs/developer/request-paths.md`
- **rclone** (7 connections) — `docs/operations/clients/rclone.md`
- **A control existing only in config or docs is worse than none** (5 connections) — `docs/adr/0001-the-backend-is-hostile.md`
- **405 MethodNotAllowed vs 501 NotImplemented dispatch** (5 connections) — `docs/developer/request-paths.md`
- **x-amz-expected-bucket-owner forwarded on every verb** (5 connections) — `docs/operations/s3-api.md`
- **Client part sizes must cover whole 64 KiB segments** (5 connections) — `docs/operations/s3-api.md`
- **Sub-resources: 501 NotImplemented or 405 MethodNotAllowed** (5 connections) — `docs/operations/s3-api.md`
- **TestEveryBackendCallCarriesTheOwnerGuard()** (5 connections) — `internal/proxy/request/bucketowner_guard_test.go`
- **Prefix validated at startup (^[a-z0-9][a-z0-9-]{2,}-$)** (4 connections) — `docs/adr/0009-the-metadata-prefix-is-the-proxys-namespace.md`
- **Backend Checksum Never Relayed; Proxy Serves Its Own Sealed CRC32C (D10/D10a)** (4 connections) — `docs/adr/0012-client-checksums-are-verified-never-forwarded.md`
- **Storage headers on upload: forward it or refuse it** (4 connections) — `docs/operations/s3-api.md`
- **x-amz-expected-bucket-owner carried on every backend call** (3 connections) — `docs/adr/0007-forward-it-or-refuse-it.md`
- **Backend header restated by what it describes** (3 connections) — `docs/adr/0008-every-response-describes-the-proxy.md`
- **Client metadata key inside the namespace refused 400 InvalidArgument** (3 connections) — `docs/adr/0009-the-metadata-prefix-is-the-proxys-namespace.md`
- **When the defect is an omission, test the source** (3 connections) — `docs/developer/testing.md`
- **use_multipart_etag = false** (3 connections) — `docs/operations/clients/rclone.md`
- **Three write paths produce identical bytes** (3 connections) — `docs/operations/s3-api.md`
- *... and 59 more nodes in this community*

## Relationships

- [Integrity and Tail-First Read](Integrity_and_Tail-First_Read.md) (22 shared connections)
- [ADR Corpus and Release History](ADR_Corpus_and_Release_History.md) (20 shared connections)
- [Exit Provider and Session Lifecycle](Exit_Provider_and_Session_Lifecycle.md) (14 shared connections)
- [Client Library and Storage Format](Client_Library_and_Storage_Format.md) (12 shared connections)
- [SigV4 Authentication Rules](SigV4_Authentication_Rules.md) (10 shared connections)
- [Middleware: S3Auth Robust](Middleware-_S3Auth_Robust.md) (10 shared connections)
- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (7 shared connections)
- [Filename Encryption Ticket](Filename_Encryption_Ticket.md) (6 shared connections)
- [Whole-Object Read Window](Whole-Object_Read_Window.md) (5 shared connections)
- [Planned Work: SSE-C and HA](Planned_Work-_SSE-C_and_HA.md) (5 shared connections)
- [Monitoring and Licence Removal](Monitoring_and_Licence_Removal.md) (5 shared connections)
- [Key Hierarchy and Threat Rules](Key_Hierarchy_and_Threat_Rules.md) (4 shared connections)

## Source Files

- `DEVELOPER.md`
- `docs/adr/0001-the-backend-is-hostile.md`
- `docs/adr/0006-the-proxy-serves-any-s3-client.md`
- `docs/adr/0007-forward-it-or-refuse-it.md`
- `docs/adr/0008-every-response-describes-the-proxy.md`
- `docs/adr/0009-the-metadata-prefix-is-the-proxys-namespace.md`
- `docs/adr/0012-client-checksums-are-verified-never-forwarded.md`
- `docs/developer/request-paths.md`
- `docs/developer/testing.md`
- `docs/operations/README.md`
- `docs/operations/clients/rclone.md`
- `docs/operations/integrity.md`
- `docs/operations/s3-api.md`
- `docs/security/refusals.md`
- `docs/tickets/017-filename-encryption.md`
- `docs/tickets/036-high-availability.md`
- `docs/tickets/037-multiple-backends.md`
- `internal/proxy/request/bucketowner_guard_test.go`

## Audit Trail

- EXTRACTED: 243 (94%)
- INFERRED: 15 (6%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*