# Whole-Object Read Window

> 72 nodes · cohesion 0.04

## Key Concepts

- **ADR 0020: Performance is measured before and after** (40 connections) — `docs/tickets/017-filename-encryption.md`
- **Developer: Testing** (24 connections) — `docs/developer/testing.md`
- **Developer: Performance** (17 connections) — `docs/developer/performance.md`
- **Local Performance Baseline Suite (test/perf)** (11 connections) — `test/perf/README.md`
- **Perf Findings: pre-v2 Baseline** (10 connections) — `perf-baseline/20260909T175340Z-9f3fbd1/FINDINGS.md`
- **Perf Findings: post-v2 After Column (2026-09-11)** (10 connections) — `perf-baseline/20260911T103132Z-cc62c05/FINDINGS.md`
- **Perf Findings: pre-v2-uploadpath Before Column** (6 connections) — `perf-baseline/20260910T090543Z-530472c/FINDINGS.md`
- **A client suite asserts the target behaviour** (5 connections) — `docs/developer/testing.md`
- **Ticket 027: Whole-Object Read First Window** (5 connections) — `docs/tickets/027-whole-object-read-first-window.md`
- **Perf Findings: Upload Path Decomposition** (5 connections) — `perf-baseline/20260910T062529Z-9f3fbd1/FINDINGS.md`
- **Local baseline suite: make perf-baseline / perf-compare (D18)** (4 connections) — `docs/adr/0020-performance-is-measured-before-and-after.md`
- **Option C: Second Request Issued on First Answer's Headers** (4 connections) — `docs/tickets/027-whole-object-read-first-window.md`
- **Tail-First Read First Window (65604 bytes)** (4 connections) — `docs/tickets/027-whole-object-read-first-window.md`
- **Segment Chain Model 3.4x Faster (cipher only)** (4 connections) — `perf-baseline/20260909T175340Z-9f3fbd1/FINDINGS.md`
- **Perf Findings: Segment Codec Measured** (4 connections) — `perf-baseline/20260909T212247Z-9f3fbd1/FINDINGS.md`
- **Upload Deficit Is Per Byte, Serialised Inside One Part** (4 connections) — `perf-baseline/20260910T090543Z-530472c/FINDINGS.md`
- **Upload Deficit Gone After Segment Chain + Producer Restructuring** (4 connections) — `perf-baseline/20260911T103132Z-cc62c05/FINDINGS.md`
- **Complete instrument set recorded before a rewrite (D17)** (3 connections) — `docs/adr/0020-performance-is-measured-before-and-after.md`
- **The Memory Instrument Is the One Asserted Figure** (3 connections) — `docs/developer/performance.md`
- **test/perf baseline records, never asserts throughput** (3 connections) — `docs/developer/testing.md`
- **Equal-Allocation Rule for Crypto Comparisons** (3 connections) — `perf-baseline/20260909T175340Z-9f3fbd1/FINDINGS.md`
- **Upload Cliff at streaming_threshold (5 MiB)** (3 connections) — `perf-baseline/20260909T175340Z-9f3fbd1/FINDINGS.md`
- **Shipped Segment Codec 1.75x (CRC32C included)** (3 connections) — `perf-baseline/20260909T212247Z-9f3fbd1/FINDINGS.md`
- **Auto-Multipart Write Path Carries 87% of Upload Gap** (3 connections) — `perf-baseline/20260910T062529Z-9f3fbd1/FINDINGS.md`
- **Self-Copy Is Not the Upload Deficit (~5%)** (3 connections) — `perf-baseline/20260910T062529Z-9f3fbd1/FINDINGS.md`
- *... and 47 more nodes in this community*

## Relationships

- [Exit Provider and Session Lifecycle](Exit_Provider_and_Session_Lifecycle.md) (13 shared connections)
- [ADR Corpus and Release History](ADR_Corpus_and_Release_History.md) (8 shared connections)
- [Integrity and Tail-First Read](Integrity_and_Tail-First_Read.md) (7 shared connections)
- [S3 API Behaviour](S3_API_Behaviour.md) (5 shared connections)
- [Key Hierarchy and Threat Rules](Key_Hierarchy_and_Threat_Rules.md) (4 shared connections)
- [Release Process and Doc Homes](Release_Process_and_Doc_Homes.md) (4 shared connections)
- [Monitoring and Licence Removal](Monitoring_and_Licence_Removal.md) (3 shared connections)
- [Planned Work: SSE-C and HA](Planned_Work-_SSE-C_and_HA.md) (3 shared connections)
- [Middleware: S3Auth Robust](Middleware-_S3Auth_Robust.md) (2 shared connections)
- [Streaming Integration Helpers](Streaming_Integration_Helpers.md) (2 shared connections)
- [Client Library and Storage Format](Client_Library_and_Storage_Format.md) (2 shared connections)
- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (2 shared connections)

## Source Files

- `docs/adr/0020-performance-is-measured-before-and-after.md`
- `docs/developer/performance.md`
- `docs/developer/testing.md`
- `docs/operations/clients/rclone.md`
- `docs/tickets/017-filename-encryption.md`
- `docs/tickets/027-whole-object-read-first-window.md`
- `docs/tickets/040-managed-buckets.md`
- `perf-baseline/20260909T175340Z-9f3fbd1/FINDINGS.md`
- `perf-baseline/20260909T175340Z-9f3fbd1/REPORT.md`
- `perf-baseline/20260909T212247Z-9f3fbd1/FINDINGS.md`
- `perf-baseline/20260909T212247Z-9f3fbd1/REPORT.md`
- `perf-baseline/20260910T062529Z-9f3fbd1/FINDINGS.md`
- `perf-baseline/20260910T062529Z-9f3fbd1/REPORT.md`
- `perf-baseline/20260910T090543Z-530472c/FINDINGS.md`
- `perf-baseline/20260910T090543Z-530472c/REPORT.md`
- `perf-baseline/20260911T064137Z-233d559/REPORT.md`
- `perf-baseline/20260911T101344Z-cc62c05/REPORT.md`
- `perf-baseline/20260911T102319Z-cc62c05/REPORT.md`
- `perf-baseline/20260911T103132Z-cc62c05/FINDINGS.md`
- `perf-baseline/20260911T103132Z-cc62c05/REPORT.md`

## Audit Trail

- EXTRACTED: 141 (90%)
- INFERRED: 16 (10%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*