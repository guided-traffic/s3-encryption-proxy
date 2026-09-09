# Baseline Object Allocation Profile

> 6 nodes · cohesion 0.47

## Key Concepts

- **Tier 1.3 Eliminate Per-Read logrus Allocations in streaming_io** (7 connections) — `docs/tickets/010-performance-improvements.md`
- **logrus Entry.WithFields Object-Alloc Hotspot (23.0%, rank 1)** (4 connections) — `docs/tickets/010-baseline/proxy-allocs-objects-top15.txt`
- **Baseline Proxy alloc_objects Top-15** (3 connections) — `docs/tickets/010-baseline/proxy-allocs-objects-top15.txt`
- **decryptionReader.Read Object-Alloc Hotspot (16.2%, rank 2)** (3 connections) — `docs/tickets/010-baseline/proxy-allocs-objects-top15.txt`
- **Tier 4.3 Demote Per-Request Info Logs to Debug** (2 connections) — `docs/tickets/010-performance-improvements.md`
- **Tier 1.3 Proxy alloc_objects Top-15 (WithFields down to rank 14)** (2 connections) — `docs/tickets/010-tier1.3/proxy-allocs-objects-top15.txt`

## Relationships

- [Streaming Throughput Ticket](Streaming_Throughput_Ticket.md) (3 shared connections)
- [Baseline Client Profiles](Baseline_Client_Profiles.md) (1 shared connections)
- [Baseline Allocation Profile](Baseline_Allocation_Profile.md) (1 shared connections)
- [io.ReadAll Allocation Hotspot](io.ReadAll_Allocation_Hotspot.md) (1 shared connections)
- [Architecture Analysis Findings](Architecture_Analysis_Findings.md) (1 shared connections)

## Source Files

- `docs/tickets/010-baseline/proxy-allocs-objects-top15.txt`
- `docs/tickets/010-performance-improvements.md`
- `docs/tickets/010-tier1.3/proxy-allocs-objects-top15.txt`

## Audit Trail

- EXTRACTED: 11 (79%)
- INFERRED: 3 (21%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*