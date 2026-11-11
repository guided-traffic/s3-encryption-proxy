# Whole-Object Read Window

> 39 nodes · cohesion 0.07

## Key Concepts

- **Local Performance Baseline Suite (test/perf)** (11 connections) — `test/perf/README.md`
- **Perf Findings: pre-v2 Baseline** (10 connections) — `perf-baseline/20260909T175340Z-9f3fbd1/FINDINGS.md`
- **Perf Findings: post-v2 After Column (2026-09-11)** (10 connections) — `perf-baseline/20260911T103132Z-cc62c05/FINDINGS.md`
- **Ticket 027: Whole-Object Read First Window** (6 connections) — `docs/tickets/027-whole-object-read-first-window.md`
- **Perf Findings: pre-v2-uploadpath Before Column** (6 connections) — `perf-baseline/20260910T090543Z-530472c/FINDINGS.md`
- **Perf Findings: Upload Path Decomposition** (5 connections) — `perf-baseline/20260910T062529Z-9f3fbd1/FINDINGS.md`
- **Tail-First Read First Window (65604 bytes)** (4 connections) — `docs/tickets/027-whole-object-read-first-window.md`
- **Segment Chain Model 3.4x Faster (cipher only)** (4 connections) — `perf-baseline/20260909T175340Z-9f3fbd1/FINDINGS.md`
- **Perf Findings: Segment Codec Measured** (4 connections) — `perf-baseline/20260909T212247Z-9f3fbd1/FINDINGS.md`
- **Upload Deficit Is Per Byte, Serialised Inside One Part** (4 connections) — `perf-baseline/20260910T090543Z-530472c/FINDINGS.md`
- **Upload Deficit Gone After Segment Chain + Producer Restructuring** (4 connections) — `perf-baseline/20260911T103132Z-cc62c05/FINDINGS.md`
- **Equal-Allocation Rule for Crypto Comparisons** (3 connections) — `perf-baseline/20260909T175340Z-9f3fbd1/FINDINGS.md`
- **Upload Cliff at streaming_threshold (5 MiB)** (3 connections) — `perf-baseline/20260909T175340Z-9f3fbd1/FINDINGS.md`
- **Shipped Segment Codec 1.75x (CRC32C included)** (3 connections) — `perf-baseline/20260909T212247Z-9f3fbd1/FINDINGS.md`
- **Auto-Multipart Write Path Carries 87% of Upload Gap** (3 connections) — `perf-baseline/20260910T062529Z-9f3fbd1/FINDINGS.md`
- **Self-Copy Is Not the Upload Deficit (~5%)** (3 connections) — `perf-baseline/20260910T062529Z-9f3fbd1/FINDINGS.md`
- **Self-CopyObject is a Full Server-Side Rewrite (measured)** (2 connections) — `docs/tickets/040-managed-buckets.md`
- **HMAC-SHA256 Dominates the CTR+HMAC Path** (2 connections) — `perf-baseline/20260909T175340Z-9f3fbd1/FINDINGS.md`
- **Memory Far Below 512 MiB Container Limit** (2 connections) — `perf-baseline/20260909T175340Z-9f3fbd1/FINDINGS.md`
- **RSA Unwrap Four Orders of Magnitude Above AES** (2 connections) — `perf-baseline/20260909T175340Z-9f3fbd1/FINDINGS.md`
- **Per-Segment CRC Combine and Pending-Buffer Copy Bugs** (2 connections) — `perf-baseline/20260909T212247Z-9f3fbd1/FINDINGS.md`
- **Between-Run Spread up to 15% End to End** (2 connections) — `perf-baseline/20260911T103132Z-cc62c05/FINDINGS.md`
- **Ranged Read Left Backend Connection Unpooled (closeDrained fix)** (2 connections) — `perf-baseline/20260911T103132Z-cc62c05/FINDINGS.md`
- **Second Proxy for uploadpath Instrument (S3EP_PERF_ALT_PROXY)** (2 connections) — `test/perf/README.md`
- **Backend Refuses aws-chunked Chunk Above 16 MiB** (2 connections) — `test/perf/README.md`
- *... and 14 more nodes in this community*

## Relationships

- [ADR Corpus and Release History](ADR_Corpus_and_Release_History.md) (5 shared connections)
- [Integrity and Tail-First Read](Integrity_and_Tail-First_Read.md) (3 shared connections)
- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (2 shared connections)
- [Key Hierarchy and Threat Rules](Key_Hierarchy_and_Threat_Rules.md) (2 shared connections)
- [Performance and Test Docs](Performance_and_Test_Docs.md) (2 shared connections)
- [Planned Work: SSE-C and HA](Planned_Work-_SSE-C_and_HA.md) (1 shared connections)

## Source Files

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
- `test/perf/README.md`

## Audit Trail

- EXTRACTED: 52 (79%)
- INFERRED: 14 (21%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*