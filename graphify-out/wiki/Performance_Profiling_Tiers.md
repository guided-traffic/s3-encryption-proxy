# Performance Profiling Tiers

> 58 nodes · cohesion 0.07

## Key Concepts

- **.handleStreamingUploadPart()** (16 connections) — `internal/proxy/handlers/multipart/upload.go`
- **.processPartOrdered()** (15 connections) — `internal/orchestration/multipart.go`
- **Ticket 010 Tier 2 snapshot (2026-04-24)** (13 connections) — `docs/tickets/010-tier2/README.md`
- **.Handle()** (11 connections) — `internal/proxy/handlers/multipart/upload.go`
- **Ticket 010 baseline snapshot (2026-04-23)** (10 connections) — `docs/tickets/010-baseline/README.md`
- **.processPartDataInOrder()** (10 connections) — `internal/orchestration/multipart.go`
- **Baseline proxy CPU top-20** (9 connections) — `docs/tickets/010-baseline/proxy-cpu-top20.txt`
- **Tier 2 proxy CPU top-20 (crypto dominant)** (9 connections) — `docs/tickets/010-tier2/proxy-cpu-top20.txt`
- **io.ReadAll** (9 connections) — `docs/tickets/010-baseline/proxy-allocs-top20.txt`
- **Ticket 010 Tier 1.1 snapshot (in-place CTR XOR)** (8 connections) — `docs/tickets/010-tier1/README.md`
- **P-2: the pooled read buffer is bypassed because dst implements ReaderFrom** (8 connections) — `docs/tickets/024-coverage-round-findings.md`
- **.Read()** (8 connections) — `internal/orchestration/streaming_io.go`
- **.processBufferedPartsData()** (8 connections) — `internal/orchestration/multipart.go`
- **Baseline proxy alloc_space top-20 (17.97 GB)** (7 connections) — `docs/tickets/010-baseline/proxy-allocs-top20.txt`
- **Tier 1.3 proxy alloc_objects top-15** (7 connections) — `docs/tickets/010-tier1.3/proxy-allocs-objects-top15.txt`
- **Tier 1.1 proxy alloc_objects top-15** (7 connections) — `docs/tickets/010-tier1/proxy-allocs-objects-top15.txt`
- **Tier 1.1 proxy alloc_space top-20 (13.38 GB)** (7 connections) — `docs/tickets/010-tier1/proxy-allocs-top20.txt`
- **Tier 2 proxy alloc_objects top-15 (465 k objects)** (7 connections) — `docs/tickets/010-tier2/proxy-allocs-objects-top15.txt`
- **Baseline proxy alloc_objects top-15 (1.01 M objects)** (6 connections) — `docs/tickets/010-baseline/proxy-allocs-objects-top15.txt`
- **Tier 1.3 proxy alloc_space top (22.29 GB, multi-run)** (6 connections) — `docs/tickets/010-tier1.3/proxy-allocs-top20.txt`
- **Tier 1.1 proxy CPU top-20** (6 connections) — `docs/tickets/010-tier1/proxy-cpu-top20.txt`
- **Tier 2 proxy alloc_space top-20 (10.01 GB)** (6 connections) — `docs/tickets/010-tier2/proxy-allocs-top20.txt`
- **Ticket 010: Performance improvements** (5 connections) — `docs/tickets/010-performance-improvements.md`
- **Ticket 010 Tier 1.3 profile capture (logrus allocation tier)** (5 connections) — `docs/tickets/010-tier1.3/proxy-allocs-top20.txt`
- **Tier 2 client CPU top-20** (5 connections) — `docs/tickets/010-tier2/cpu-top20.txt`
- *... and 33 more nodes in this community*

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
- `docs/tickets/010-tier2/README.md`
- `docs/tickets/010-tier2/cpu-top20.txt`
- `docs/tickets/010-tier2/mem-alloc-objects.txt`
- `docs/tickets/010-tier2/mem-alloc-space.txt`
- `docs/tickets/010-tier2/proxy-allocs-objects-top15.txt`
- `docs/tickets/010-tier2/proxy-allocs-top20.txt`

## Audit Trail

- EXTRACTED: 255 (87%)
- INFERRED: 38 (13%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [[index]] to navigate.*