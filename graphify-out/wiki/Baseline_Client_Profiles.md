# Baseline Client Profiles

> 10 nodes · cohesion 0.27

## Key Concepts

- **Ticket 010 Baseline Snapshot (BEFORE)** (13 connections) — `docs/tickets/010-baseline/README.md`
- **Client-Side Profile Cannot See Proxy Hot Paths** (4 connections) — `docs/tickets/010-baseline/README.md`
- **Client io.ReadAll of the 1 GB GET Body (2.56 GB, 71%)** (3 connections) — `docs/tickets/010-baseline/mem-alloc-space.txt`
- **monitoring.pprof_enabled Proxy-Side Profiling Flag** (3 connections) — `docs/tickets/010-performance-improvements.md`
- **Baseline Client CPU Top-20 Profile** (2 connections) — `docs/tickets/010-baseline/cpu-top20.txt`
- **Client v4 Chunked SHA-256 Signing Cost (28% CPU)** (2 connections) — `docs/tickets/010-baseline/cpu-top20.txt`
- **Baseline Client alloc_space Profile** (2 connections) — `docs/tickets/010-baseline/mem-alloc-space.txt`
- **Baseline Client alloc_objects Profile** (1 connections) — `docs/tickets/010-baseline/mem-alloc-objects.txt`
- **Per-Tier Profiling Re-Run Procedure** (1 connections) — `docs/tickets/010-baseline/README.md`
- **1 GB Throughput Baseline (78.42 MB/s up, 120.43 MB/s down)** (1 connections) — `docs/tickets/010-baseline/README.md`

## Relationships

- [io.ReadAll Allocation Hotspot](io.ReadAll_Allocation_Hotspot.md) (2 shared connections)
- [Baseline Allocation Profile](Baseline_Allocation_Profile.md) (2 shared connections)
- [Streaming Throughput Ticket](Streaming_Throughput_Ticket.md) (2 shared connections)
- [Baseline Object Allocation Profile](Baseline_Object_Allocation_Profile.md) (1 shared connections)
- [CPU Hotspot Baseline](CPU_Hotspot_Baseline.md) (1 shared connections)

## Source Files

- `docs/tickets/010-baseline/README.md`
- `docs/tickets/010-baseline/cpu-top20.txt`
- `docs/tickets/010-baseline/mem-alloc-objects.txt`
- `docs/tickets/010-baseline/mem-alloc-space.txt`
- `docs/tickets/010-performance-improvements.md`

## Audit Trail

- EXTRACTED: 19 (95%)
- INFERRED: 1 (5%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*