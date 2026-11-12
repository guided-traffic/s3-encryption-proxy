# Exit Provider and Session Lifecycle

> 71 nodes · cohesion 0.04

## Key Concepts

- **ADR 0011: The proxy owns the part layout it writes, and refuses copies it cannot re-encrypt** (57 connections) — `docs/adr/0011-the-proxy-owns-the-part-layout.md`
- **Developer guide (DEVELOPER.md)** (49 connections) — `DEVELOPER.md`
- **ADR 0024: An upload forwards while it receives** (22 connections) — `docs/adr/0024-an-upload-forwards-while-it-receives.md`
- **Errors (developer page)** (19 connections) — `docs/developer/errors.md`
- **Configuration: where a value comes from** (18 connections) — `docs/developer/configuration.md`
- **Multipart uploads (developer page)** (14 connections) — `docs/developer/multipart.md`
- **Developer documentation index** (14 connections) — `docs/developer/README.md`
- **Package map** (12 connections) — `docs/developer/package-map.md`
- **pkg/s3enc client library** (9 connections) — `docs/adr/0041-the-project-ships-a-client-library-for-its-stored-format.md`
- **ADR 0039: The analysis tools move with the Go toolchain** (6 connections) — `docs/adr/0039-the-analysis-tools-move-with-the-go-toolchain.md`
- **PUT routes on plaintext length, never wire length** (5 connections) — `docs/developer/request-paths.md`
- **Makefile build/test/lint/perf/coverage matrix** (4 connections) — `DEVELOPER.md`
- **Internal multipart producer (concurrency+1 buffers)** (4 connections) — `DEVELOPER.md`
- **optimizations.multipart_part_size (multiple of 64 KiB)** (4 connections) — `docs/adr/0011-the-proxy-owns-the-part-layout.md`
- **Strict ErrorUnused decode and keys refused by name** (4 connections) — `docs/developer/configuration.md`
- **Internal multipart producer** (4 connections) — `docs/developer/multipart.md`
- **Three-Leg Upload Comparison** (4 connections) — `docs/developer/performance.md`
- **test-pipeline.yml CI jobs** (3 connections) — `DEVELOPER.md`
- **Tail-first whole-object GET, trailer-authenticated length** (3 connections) — `DEVELOPER.md`
- **tools/go.mod pins golangci-lint, gosec, govulncheck** (3 connections) — `DEVELOPER.md`
- **Associated data binds format id, object key and segment index** (3 connections) — `docs/adr/0003-objects-are-an-authenticated-segment-chain.md`
- **64 KiB segment size, a format constant** (3 connections) — `docs/adr/0003-objects-are-an-authenticated-segment-chain.md`
- **422 NotSupportedWithEncryption (proxy-own code)** (3 connections) — `docs/adr/0011-the-proxy-owns-the-part-layout.md`
- **Server-Side Copy Refused Under Encryption (D9/D10)** (3 connections) — `docs/adr/0011-the-proxy-owns-the-part-layout.md`
- **Bounded memory: multipart_upload_concurrency + 1 part buffers** (3 connections) — `docs/adr/0024-an-upload-forwards-while-it-receives.md`
- *... and 46 more nodes in this community*

## Relationships

- [Monitoring and Licence Removal](Monitoring_and_Licence_Removal.md) (17 shared connections)
- [Integrity and Tail-First Read](Integrity_and_Tail-First_Read.md) (16 shared connections)
- [S3 API Behaviour](S3_API_Behaviour.md) (14 shared connections)
- [Whole-Object Read Window](Whole-Object_Read_Window.md) (13 shared connections)
- [Client Library and Storage Format](Client_Library_and_Storage_Format.md) (13 shared connections)
- [ADR Corpus and Release History](ADR_Corpus_and_Release_History.md) (12 shared connections)
- [Release Process and Doc Homes](Release_Process_and_Doc_Homes.md) (12 shared connections)
- [SigV4 Authentication Rules](SigV4_Authentication_Rules.md) (10 shared connections)
- [Middleware: S3Auth Robust](Middleware-_S3Auth_Robust.md) (9 shared connections)
- [Key Hierarchy and Threat Rules](Key_Hierarchy_and_Threat_Rules.md) (7 shared connections)
- [Planned Work: SSE-C and HA](Planned_Work-_SSE-C_and_HA.md) (3 shared connections)
- [Key Material and Deployment Secrets](Key_Material_and_Deployment_Secrets.md) (3 shared connections)

## Source Files

- `DEVELOPER.md`
- `docs/adr/0003-objects-are-an-authenticated-segment-chain.md`
- `docs/adr/0007-forward-it-or-refuse-it.md`
- `docs/adr/0011-the-proxy-owns-the-part-layout.md`
- `docs/adr/0024-an-upload-forwards-while-it-receives.md`
- `docs/adr/0028-an-abandoned-upload-is-ended-not-forgotten.md`
- `docs/adr/0039-the-analysis-tools-move-with-the-go-toolchain.md`
- `docs/adr/0040-the-go-module-path-carries-the-major-version.md`
- `docs/adr/0041-the-project-ships-a-client-library-for-its-stored-format.md`
- `docs/developer/README.md`
- `docs/developer/configuration.md`
- `docs/developer/errors.md`
- `docs/developer/multipart.md`
- `docs/developer/package-map.md`
- `docs/developer/performance.md`
- `docs/developer/request-paths.md`
- `docs/tickets/036-high-availability.md`

## Audit Trail

- EXTRACTED: 245 (98%)
- INFERRED: 6 (2%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*