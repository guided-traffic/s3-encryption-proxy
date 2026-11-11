# Release Process and Doc Homes

> 65 nodes · cohesion 0.05

## Key Concepts

- **Developer guide (DEVELOPER.md)** (52 connections) — `DEVELOPER.md`
- **ADR 0018: A major release is declared by a label** (34 connections) — `docs/tickets/037-multiple-backends.md`
- **Contributing guide** (21 connections) — `CONTRIBUTING.md`
- **ADR 0022: Tickets are work lists that get archived** (21 connections) — `docs/adr/0022-tickets-are-work-lists-that-get-archived.md`
- **Developer documentation index** (18 connections) — `docs/developer/README.md`
- **ADR 0035: The README advertises the product; the reference lives under docs/** (13 connections) — `docs/adr/0035-the-readme-advertises-the-reference-lives-under-docs.md`
- **ADR 0040: The Go module path carries the major version** (9 connections) — `docs/adr/0040-the-go-module-path-carries-the-major-version.md`
- **Security policy (SECURITY.md)** (9 connections) — `SECURITY.md`
- **ADR 0038: The security architecture is one page per perspective** (8 connections) — `docs/adr/0038-the-security-architecture-is-one-page-per-perspective.md`
- **ADR 0039: The analysis tools move with the Go toolchain** (8 connections) — `docs/adr/0039-the-analysis-tools-move-with-the-go-toolchain.md`
- **Makefile build/test/lint/perf/coverage matrix** (5 connections) — `DEVELOPER.md`
- **test-pipeline.yml CI jobs** (5 connections) — `DEVELOPER.md`
- **Bounded memory: multipart_upload_concurrency + 1 part buffers** (5 connections) — `docs/adr/0024-an-upload-forwards-while-it-receives.md`
- **Decisions live in ADRs; tickets are archived work lists** (4 connections) — `CLAUDE.md`
- **Contributor security considerations** (4 connections) — `CONTRIBUTING.md`
- **Go toolchain version in Containerfile and go.mod** (4 connections) — `DEVELOPER.md`
- **Internal multipart producer (concurrency+1 buffers)** (4 connections) — `DEVELOPER.md`
- **No compatibility owed for data at rest** (4 connections) — `docs/adr/0017-stored-data-compatibility-is-not-owed.md`
- **release:major label declares a major** (4 connections) — `docs/adr/0018-a-major-release-is-declared-by-a-label.md`
- **End-to-end suite gates the release** (4 connections) — `docs/adr/0019-integration-and-e2e-tests-are-the-product.md`
- **No working key material tracked in the repository** (4 connections) — `docs/adr/0021-key-material-is-generated-never-committed.md`
- **An upload forwards bytes while it receives them** (4 connections) — `docs/adr/0024-an-upload-forwards-while-it-receives.md`
- **Library and proxy are one module and one release line** (4 connections) — `docs/operations/client-library.md`
- **Release 5.0.0: stored format break** (3 connections) — `CHANGELOG.md`
- **Go version spelled in exactly two files (Containerfile, go.mod)** (3 connections) — `CLAUDE.md`
- *... and 40 more nodes in this community*

## Relationships

- [ADR Corpus and Release History](ADR_Corpus_and_Release_History.md) (58 shared connections)
- [Key Hierarchy and Threat Rules](Key_Hierarchy_and_Threat_Rules.md) (22 shared connections)
- [Key Material and Deployment Secrets](Key_Material_and_Deployment_Secrets.md) (12 shared connections)
- [Integrity and Tail-First Read](Integrity_and_Tail-First_Read.md) (10 shared connections)
- [Client Library and Storage Format](Client_Library_and_Storage_Format.md) (9 shared connections)
- [Monitoring and Licence Removal](Monitoring_and_Licence_Removal.md) (8 shared connections)
- [Performance and Test Docs](Performance_and_Test_Docs.md) (5 shared connections)
- [Exit Provider and Session Lifecycle](Exit_Provider_and_Session_Lifecycle.md) (5 shared connections)
- [S3 API Behaviour](S3_API_Behaviour.md) (4 shared connections)
- [SigV4 Authentication Rules](SigV4_Authentication_Rules.md) (4 shared connections)
- [Planned Work: SSE-C and HA](Planned_Work-_SSE-C_and_HA.md) (3 shared connections)
- [Adr: 0039 The Analysis Tools Move With The Go Toolchain](Adr-_0039_The_Analysis_Tools_Move_With_The_Go_Toolchain.md) (2 shared connections)

## Source Files

- `CHANGELOG.md`
- `CLAUDE.md`
- `CONTRIBUTING.md`
- `DEVELOPER.md`
- `README.md`
- `SECURITY.md`
- `docs/adr/0017-stored-data-compatibility-is-not-owed.md`
- `docs/adr/0018-a-major-release-is-declared-by-a-label.md`
- `docs/adr/0019-integration-and-e2e-tests-are-the-product.md`
- `docs/adr/0020-performance-is-measured-before-and-after.md`
- `docs/adr/0021-key-material-is-generated-never-committed.md`
- `docs/adr/0022-tickets-are-work-lists-that-get-archived.md`
- `docs/adr/0024-an-upload-forwards-while-it-receives.md`
- `docs/adr/0035-the-readme-advertises-the-reference-lives-under-docs.md`
- `docs/adr/0038-the-security-architecture-is-one-page-per-perspective.md`
- `docs/adr/0039-the-analysis-tools-move-with-the-go-toolchain.md`
- `docs/adr/0040-the-go-module-path-carries-the-major-version.md`
- `docs/adr/README.md`
- `docs/developer/README.md`
- `docs/operations/client-library.md`

## Audit Trail

- EXTRACTED: 226 (93%)
- INFERRED: 13 (5%)
- AMBIGUOUS: 3 (1%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*