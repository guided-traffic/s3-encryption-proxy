# Performance Ticket Baseline

> 59 nodes · cohesion 0.05

## Key Concepts

- **Ticket 010: Performance Improvements - Streaming Throughput** (20 connections) — `docs/tickets/010-performance-improvements.md`
- **Ticket 010 Baseline Snapshot (BEFORE)** (13 connections) — `docs/tickets/010-baseline/README.md`
- **Baseline Proxy alloc_space Top-20 (17.97 GB per 1 GB round-trip)** (7 connections) — `docs/tickets/010-baseline/proxy-allocs-top20.txt`
- **Ticket 010 Tier 1.1 Snapshot (in-place CTR XOR)** (7 connections) — `docs/tickets/010-tier1/README.md`
- **Tier 1.3 Eliminate Per-Read logrus Allocations in streaming_io** (6 connections) — `docs/tickets/010-performance-improvements.md`
- **io.ReadAll Proxy Alloc Hotspot (7.12 GB, 39.6%)** (5 connections) — `docs/tickets/010-baseline/proxy-allocs-top20.txt`
- **Tier 1.1 In-Place XOR in AES-CTR Stateful Encryptor** (5 connections) — `docs/tickets/010-performance-improvements.md`
- **logrus Entry.WithFields Object-Alloc Hotspot (23.0%, rank 1)** (4 connections) — `docs/tickets/010-baseline/proxy-allocs-objects-top15.txt`
- **Baseline Proxy CPU Top-20** (4 connections) — `docs/tickets/010-baseline/proxy-cpu-top20.txt`
- **Client-Side Profile Cannot See Proxy Hot Paths** (4 connections) — `docs/tickets/010-baseline/README.md`
- **AES-NI plus SHA-256 Crypto Floor** (4 connections) — `docs/tickets/010-performance-improvements.md`
- **Tier 2.2 Single-Pass HMAC in DecryptGCMStream** (4 connections) — `docs/tickets/010-performance-improvements.md`
- **Tier 2.3 Stream Directly to ResponseWriter (no io.ReadAll)** (4 connections) — `docs/tickets/010-performance-improvements.md`
- **Tier 2.4 Parallel S3 UploadPart in putObjectAutoMultipart** (4 connections) — `docs/tickets/010-performance-improvements.md`
- **Tier 2.5 Eliminate Append-Build in processPartOrdered** (4 connections) — `docs/tickets/010-performance-improvements.md`
- **Tier 2.6 hmacGatedDecryptionReader Replaces Pipe plus Goroutine** (4 connections) — `docs/tickets/010-performance-improvements.md`
- **Client io.ReadAll of the 1 GB GET Body (2.56 GB, 71%)** (3 connections) — `docs/tickets/010-baseline/mem-alloc-space.txt`
- **Baseline Proxy alloc_objects Top-15** (3 connections) — `docs/tickets/010-baseline/proxy-allocs-objects-top15.txt`
- **decryptionReader.Read Object-Alloc Hotspot (16.2%, rank 2)** (3 connections) — `docs/tickets/010-baseline/proxy-allocs-objects-top15.txt`
- **monitoring.pprof_enabled Proxy-Side Profiling Flag** (3 connections) — `docs/tickets/010-performance-improvements.md`
- **Tier 3.1 AES-GCM Copy-Avoidance (in-place Seal/Open)** (3 connections) — `docs/tickets/010-performance-improvements.md`
- **Tier 3.2 DEK Cache Copy Avoidance** (3 connections) — `docs/tickets/010-performance-improvements.md`
- **Tier 1.3 Proxy alloc_space Top-20 (22.29 GB cumulative)** (3 connections) — `docs/tickets/010-tier1.3/proxy-allocs-top20.txt`
- **Tier 1.1 Proxy alloc_space Top-20 (13.38 GB)** (3 connections) — `docs/tickets/010-tier1/proxy-allocs-top20.txt`
- **Baseline Client CPU Top-20 Profile** (2 connections) — `docs/tickets/010-baseline/cpu-top20.txt`
- *... and 34 more nodes in this community*

## Relationships

- No strong cross-community connections detected

## Source Files

- `docs/tickets/010-baseline/README.md`
- `docs/tickets/010-baseline/cpu-top20.txt`
- `docs/tickets/010-baseline/mem-alloc-objects.txt`
- `docs/tickets/010-baseline/mem-alloc-space.txt`
- `docs/tickets/010-baseline/proxy-allocs-objects-top15.txt`
- `docs/tickets/010-baseline/proxy-allocs-top20.txt`
- `docs/tickets/010-baseline/proxy-cpu-top20.txt`
- `docs/tickets/010-performance-improvements.md`
- `docs/tickets/010-tier1.3/proxy-allocs-objects-top15.txt`
- `docs/tickets/010-tier1.3/proxy-allocs-top20.txt`
- `docs/tickets/010-tier1/README.md`
- `docs/tickets/010-tier1/proxy-allocs-objects-top15.txt`
- `docs/tickets/010-tier1/proxy-allocs-top20.txt`
- `docs/tickets/010-tier1/proxy-cpu-top20.txt`

## Audit Trail

- EXTRACTED: 79 (87%)
- INFERRED: 12 (13%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*