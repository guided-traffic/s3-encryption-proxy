# Filename Encryption Ticket

> 50 nodes · cohesion 0.05

## Key Concepts

- **README: S3 Encryption Proxy front page** (14 connections) — `README.md`
- **s3cmd client operations page** (8 connections) — `docs/operations/clients/s3cmd.md`
- **F3 multi-source paged listing primitive** (8 connections) — `docs/tickets/017-filename-encryption.md`
- **Client e2e suites rclone R1-R7 and s3cmd S1-S7** (6 connections) — `CLAUDE.md`
- **F1 mode set: off / drain / mixed / strict** (6 connections) — `docs/tickets/017-filename-encryption.md`
- **Exactly four s3ep- metadata keys** (5 connections) — `CLAUDE.md`
- **Supported clients (Velero, rclone, s3cmd)** (5 connections) — `docs/operations/README.md`
- **F8 explicit forwarder over all 52 S3BackendInterface methods** (5 connections) — `docs/tickets/017-filename-encryption.md`
- **F17 encrypted leaf with keyed first-character head tag** (5 connections) — `docs/tickets/017-filename-encryption.md`
- **F2 M2: other-form directory tree learned from backend listings** (5 connections) — `docs/tickets/017-filename-encryption.md`
- **What the proxy deliberately does not do** (5 connections) — `README.md`
- **s3cmd compares every PUT/part entity tag with MD5** (4 connections) — `docs/operations/clients/s3cmd.md`
- **F9 partial-directory prefix fan-out** (4 connections) — `docs/tickets/017-filename-encryption.md`
- **F4 stored segment form: '!' marker + 12-bit key fingerprint** (4 connections) — `docs/tickets/017-filename-encryption.md`
- **Naming conventions (format id, metadata keys, env vars, metrics, binaries)** (4 connections) — `README.md`
- **e2e harness two halves (stored/atrest shared vs backend demo-stack)** (3 connections) — `CLAUDE.md`
- **Tail-first whole-object read (bytes=-65604, HEAD bytes=-40)** (3 connections) — `CLAUDE.md`
- **x-amz-meta-s3cmd-attrs plaintext MD5 bookkeeping** (3 connections) — `docs/operations/clients/s3cmd.md`
- **Mixed-bucket name leak via fallback requests** (3 connections) — `docs/tickets/017-filename-encryption.md`
- **Pass operation: rename (names migrate)** (3 connections) — `docs/tickets/017-filename-encryption.md`
- **Request-scoped resolution memo** (3 connections) — `docs/tickets/017-filename-encryption.md`
- **s3cmd sync partial-prefix listing never converges** (3 connections) — `docs/tickets/017-filename-encryption.md`
- **Entity tag marker "<32 hex>-0" (change token)** (3 connections) — `README.md`
- **Metadata prefix is the proxy's exclusive namespace both directions** (2 connections) — `CLAUDE.md`
- **One tool, one suite, one CI job (E2E <tool> (<backend>))** (2 connections) — `CLAUDE.md`
- *... and 25 more nodes in this community*

## Relationships

- [Integrity and Tail-First Read](Integrity_and_Tail-First_Read.md) (7 shared connections)
- [S3 API Behaviour](S3_API_Behaviour.md) (6 shared connections)
- [ADR Corpus and Release History](ADR_Corpus_and_Release_History.md) (4 shared connections)
- [Performance and Test Docs](Performance_and_Test_Docs.md) (3 shared connections)
- [SigV4 Authentication Rules](SigV4_Authentication_Rules.md) (3 shared connections)
- [Key Hierarchy and Threat Rules](Key_Hierarchy_and_Threat_Rules.md) (3 shared connections)
- [Planned Work: SSE-C and HA](Planned_Work-_SSE-C_and_HA.md) (2 shared connections)
- [Monitoring and Licence Removal](Monitoring_and_Licence_Removal.md) (2 shared connections)
- [Misc (7)](Misc_7.md) (1 shared connections)
- [Whole-Object Read Window](Whole-Object_Read_Window.md) (1 shared connections)

## Source Files

- `CLAUDE.md`
- `README.md`
- `docs/operations/README.md`
- `docs/operations/clients/s3cmd.md`
- `docs/tickets/017-filename-encryption.md`

## Audit Trail

- EXTRACTED: 81 (87%)
- INFERRED: 12 (13%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*