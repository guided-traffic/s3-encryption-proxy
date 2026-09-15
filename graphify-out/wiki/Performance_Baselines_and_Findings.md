# Performance Baselines and Findings

> 23 nodes · cohesion 0.11

## Key Concepts

- **uploadpath Instrument** (7 connections) — `test/perf/README.md`
- **FINDINGS — The After Column, 2026-09-11** (6 connections) — `perf-baseline/20260911T103132Z-cc62c05/FINDINGS.md`
- **Measurement Record — schema_version 1** (6 connections) — `test/perf/README.md`
- **closeDrained()** (5 connections) — `internal/proxy/handlers/object/range.go`
- **Baseline Run wave3-checksums (20260911T064137Z-233d559)** (4 connections) — `perf-baseline/20260911T064137Z-233d559/REPORT.md`
- **Baseline Run post-v2-wave5 (20260911T101344Z-cc62c05)** (4 connections) — `perf-baseline/20260911T101344Z-cc62c05/REPORT.md`
- **Baseline Run post-v2-wave5-drained (20260911T102319Z-cc62c05)** (4 connections) — `perf-baseline/20260911T102319Z-cc62c05/REPORT.md`
- **A Ranged Read Left the Backend Connection Unusable** (4 connections) — `perf-baseline/20260911T103132Z-cc62c05/FINDINGS.md`
- **S3EP_PERF_ALT_PROXY — the Second Proxy uploadpath Needs** (3 connections) — `test/perf/README.md`
- **rangeread Instrument** (3 connections) — `test/perf/README.md`
- **wave3 — 1 MiB Ranged Read at 153.8 MiB/s (68 % of Direct)** (2 connections) — `perf-baseline/20260911T064137Z-233d559/REPORT.md`
- **wave3 Run — uploadpath and memory Skipped** (2 connections) — `perf-baseline/20260911T064137Z-233d559/REPORT.md`
- **Between-Run Spread — Anything Under 15 % End to End Is the Machine** (2 connections) — `perf-baseline/20260911T103132Z-cc62c05/FINDINGS.md`
- **The Multipart Leg Moved (+33 % to +47 %)** (2 connections) — `perf-baseline/20260911T103132Z-cc62c05/FINDINGS.md`
- **The Single-Request Leg Is 0-8 % Slower** (2 connections) — `perf-baseline/20260911T103132Z-cc62c05/FINDINGS.md`
- **Baseline Run post-v2-wave5 of Record (20260911T103132Z-cc62c05)** (2 connections) — `perf-baseline/20260911T103132Z-cc62c05/REPORT.md`
- **perf-compare Ratio Verdict** (2 connections) — `test/perf/README.md`
- **Ratios Are Never Stored (D20)** (2 connections) — `test/perf/README.md`
- **Spread Threshold — Combined RSD with a 3 % Floor** (2 connections) — `test/perf/README.md`
- **uploadpath_test.go** (2 connections) — `test/perf/uploadpath_test.go`
- **Provisional Range Window** (1 connections) — `perf-baseline/20260911T103132Z-cc62c05/FINDINGS.md`
- **FINDINGS.md — Hand-Written, Written the Day the Numbers Were Taken** (1 connections) — `test/perf/README.md`
- **Machine Record (ADR 0020 D19)** (1 connections) — `test/perf/README.md`

## Relationships

- [Readme](Readme.md) (3 shared connections)
- [Throughput](Throughput.md) (3 shared connections)
- [Ranged GET Path and Window](Ranged_GET_Path_and_Window.md) (2 shared connections)
- [Segmented Manager Streaming IO](Segmented_Manager_Streaming_IO.md) (1 shared connections)
- [Rangeread](Rangeread.md) (1 shared connections)
- [Performance Test Client](Performance_Test_Client.md) (1 shared connections)

## Source Files

- `internal/proxy/handlers/object/range.go`
- `perf-baseline/20260911T064137Z-233d559/REPORT.md`
- `perf-baseline/20260911T101344Z-cc62c05/REPORT.md`
- `perf-baseline/20260911T102319Z-cc62c05/REPORT.md`
- `perf-baseline/20260911T103132Z-cc62c05/FINDINGS.md`
- `perf-baseline/20260911T103132Z-cc62c05/REPORT.md`
- `test/perf/README.md`
- `test/perf/uploadpath_test.go`

## Audit Trail

- EXTRACTED: 38 (95%)
- INFERRED: 2 (5%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*