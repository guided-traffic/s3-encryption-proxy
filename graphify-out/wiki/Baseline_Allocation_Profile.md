# Baseline Allocation Profile

> 14 nodes · cohesion 0.15

## Key Concepts

- **Baseline Proxy alloc_space Top-20 (17.97 GB per 1 GB round-trip)** (7 connections) — `docs/tickets/010-baseline/proxy-allocs-top20.txt`
- **Ticket 010 Tier 1.1 Snapshot (in-place CTR XOR)** (7 connections) — `docs/tickets/010-tier1/README.md`
- **Tier 2.5 Eliminate Append-Build in processPartOrdered** (4 connections) — `docs/tickets/010-performance-improvements.md`
- **Tier 1.1 Proxy alloc_space Top-20 (13.38 GB)** (3 connections) — `docs/tickets/010-tier1/proxy-allocs-top20.txt`
- **Package Dependency Graph (CMD to PROXY to CORE to PKG Encryption)** (2 connections) — `docs/architecture/ARCHITECTURE_ANALYSIS.md`
- **AWSChunkedDecoder.RequiresChunkedDecoding Alloc Hotspot (1.12 GB)** (2 connections) — `docs/tickets/010-baseline/proxy-allocs-top20.txt`
- **Middleware-to-Handler Allocation Chain (cors, logging, tracking, s3auth, monitoring)** (2 connections) — `docs/tickets/010-baseline/proxy-allocs-top20.txt`
- **processPartOrdered Alloc Hotspot (5.44 GB, 30.3%)** (2 connections) — `docs/tickets/010-baseline/proxy-allocs-top20.txt`
- **Tier 4.1 Buffer Size Tuning (32 KB to 128 KB, 64 KB to 128 KB)** (2 connections) — `docs/tickets/010-performance-improvements.md`
- **Tier 4.2 Pooled 128 KiB io.CopyBuffer on the GET Path** (2 connections) — `docs/tickets/010-performance-improvements.md`
- **Tier 1.1 Proxy alloc_objects Top-15** (2 connections) — `docs/tickets/010-tier1/proxy-allocs-objects-top15.txt`
- **request.Parser.ReadBody Upload-Side Alloc Path (5.34 GB, 39.9%)** (2 connections) — `docs/tickets/010-tier1/proxy-allocs-top20.txt`
- **processBufferedPartsData Knock-On Saving (-58%)** (2 connections) — `docs/tickets/010-tier1/README.md`
- **Tier 1.1 Proxy CPU Top-20** (1 connections) — `docs/tickets/010-tier1/proxy-cpu-top20.txt`

## Relationships

- [Streaming Throughput Ticket](Streaming_Throughput_Ticket.md) (4 shared connections)
- [CPU Hotspot Baseline](CPU_Hotspot_Baseline.md) (2 shared connections)
- [io.ReadAll Allocation Hotspot](io.ReadAll_Allocation_Hotspot.md) (2 shared connections)
- [Baseline Client Profiles](Baseline_Client_Profiles.md) (2 shared connections)
- [Architecture Analysis Findings](Architecture_Analysis_Findings.md) (1 shared connections)
- [Baseline Object Allocation Profile](Baseline_Object_Allocation_Profile.md) (1 shared connections)

## Source Files

- `docs/architecture/ARCHITECTURE_ANALYSIS.md`
- `docs/tickets/010-baseline/proxy-allocs-top20.txt`
- `docs/tickets/010-performance-improvements.md`
- `docs/tickets/010-tier1/README.md`
- `docs/tickets/010-tier1/proxy-allocs-objects-top15.txt`
- `docs/tickets/010-tier1/proxy-allocs-top20.txt`
- `docs/tickets/010-tier1/proxy-cpu-top20.txt`

## Audit Trail

- EXTRACTED: 21 (81%)
- INFERRED: 5 (19%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*