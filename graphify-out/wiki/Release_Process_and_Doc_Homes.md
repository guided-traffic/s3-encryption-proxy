# Release Process and Doc Homes

> 43 nodes · cohesion 0.07

## Key Concepts

- **ADR 0017: Stored data compatibility is not owed** (46 connections) — `docs/tickets/017-filename-encryption.md`
- **ADR 0018: A major release is declared by a label** (38 connections) — `docs/tickets/037-multiple-backends.md`
- **Ticket 040: Managed Buckets** (10 connections) — `docs/tickets/040-managed-buckets.md`
- **ADR 0040: The Go module path carries the major version** (9 connections) — `docs/adr/0040-the-go-module-path-carries-the-major-version.md`
- **Pass Moving a Bucket onto the Current KEK (rewrap)** (6 connections) — `docs/tickets/040-managed-buckets.md`
- **release:major pull-request label (D4)** (5 connections) — `docs/adr/0018-a-major-release-is-declared-by-a-label.md`
- **Pass operation: rewrap (ticket 040)** (5 connections) — `docs/tickets/017-filename-encryption.md`
- **Startup Readability Verdict per Managed Bucket** (5 connections) — `docs/tickets/040-managed-buckets.md`
- **Security policy (SECURITY.md)** (5 connections) — `SECURITY.md`
- **Backward-compatibility code is deleted, not carried (D9)** (4 connections) — `docs/adr/0017-stored-data-compatibility-is-not-owed.md`
- **Breaking-marker inspection on commits, PR title and body (D3)** (4 connections) — `docs/adr/0018-a-major-release-is-declared-by-a-label.md`
- **One client, one suite, one job; every e2e suite gates the release (D9)** (4 connections) — `docs/adr/0019-integration-and-e2e-tests-are-the-product.md`
- **Library and proxy are one module and one release line** (4 connections) — `docs/operations/client-library.md`
- **A major release moves the Go module path (/v5 to /v6)** (3 connections) — `DEVELOPER.md`
- **Break, or ship two readers** (3 connections) — `docs/adr/0017-stored-data-compatibility-is-not-owed.md`
- **Everything that forces operator action ships in one major (D10)** (3 connections) — `docs/adr/0017-stored-data-compatibility-is-not-owed.md`
- **Removed configuration keys refused by name, no deprecation window (D7)** (3 connections) — `docs/adr/0017-stored-data-compatibility-is-not-owed.md`
- **type none refused by name (D9)** (3 connections) — `docs/adr/0025-leaving-is-a-supported-mode.md`
- **semantic-release-dry-run.yml workflow** (2 connections) — `DEVELOPER.md`
- **An invalid configuration value refuses the start, naming the field (D8)** (2 connections) — `docs/adr/0017-stored-data-compatibility-is-not-owed.md`
- **No migration: data is uploaded again from its source (D3)** (2 connections) — `docs/adr/0017-stored-data-compatibility-is-not-owed.md`
- **Read-only fallback path for the previous format (D2, design only)** (2 connections) — `docs/adr/0017-stored-data-compatibility-is-not-owed.md`
- **Accidental 4.0.0 release of 2026-09-07** (2 connections) — `docs/adr/0018-a-major-release-is-declared-by-a-label.md`
- **Breaking changes collected on one long-lived branch (D7)** (2 connections) — `docs/adr/0018-a-major-release-is-declared-by-a-label.md`
- **Major release notes open with the compatibility banner (D10)** (2 connections) — `docs/adr/0018-a-major-release-is-declared-by-a-label.md`
- *... and 18 more nodes in this community*

## Relationships

- [Monitoring and Licence Removal](Monitoring_and_Licence_Removal.md) (15 shared connections)
- [Exit Provider and Session Lifecycle](Exit_Provider_and_Session_Lifecycle.md) (12 shared connections)
- [Integrity and Tail-First Read](Integrity_and_Tail-First_Read.md) (9 shared connections)
- [SigV4 Authentication Rules](SigV4_Authentication_Rules.md) (9 shared connections)
- [Key Hierarchy and Threat Rules](Key_Hierarchy_and_Threat_Rules.md) (7 shared connections)
- [ADR Corpus and Release History](ADR_Corpus_and_Release_History.md) (7 shared connections)
- [Client Library and Storage Format](Client_Library_and_Storage_Format.md) (5 shared connections)
- [Planned Work: SSE-C and HA](Planned_Work-_SSE-C_and_HA.md) (5 shared connections)
- [Whole-Object Read Window](Whole-Object_Read_Window.md) (4 shared connections)
- [Performance and Test Docs](Performance_and_Test_Docs.md) (4 shared connections)
- [S3 API Behaviour](S3_API_Behaviour.md) (3 shared connections)
- [Middleware: S3Auth Robust](Middleware-_S3Auth_Robust.md) (1 shared connections)

## Source Files

- `DEVELOPER.md`
- `SECURITY.md`
- `docs/adr/0017-stored-data-compatibility-is-not-owed.md`
- `docs/adr/0018-a-major-release-is-declared-by-a-label.md`
- `docs/adr/0019-integration-and-e2e-tests-are-the-product.md`
- `docs/adr/0020-performance-is-measured-before-and-after.md`
- `docs/adr/0025-leaving-is-a-supported-mode.md`
- `docs/adr/0030-the-network-boundary-belongs-to-the-administrator.md`
- `docs/adr/0034-a-probe-reports-the-process-never-its-dependencies.md`
- `docs/adr/0035-the-readme-advertises-the-reference-lives-under-docs.md`
- `docs/adr/0040-the-go-module-path-carries-the-major-version.md`
- `docs/operations/client-library.md`
- `docs/tickets/017-filename-encryption.md`
- `docs/tickets/037-multiple-backends.md`
- `docs/tickets/040-managed-buckets.md`

## Audit Trail

- EXTRACTED: 134 (94%)
- INFERRED: 8 (6%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*