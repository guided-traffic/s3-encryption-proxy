# io.ReadAll Allocation Hotspot

> 9 nodes · cohesion 0.22

## Key Concepts

- **io.ReadAll Proxy Alloc Hotspot (7.12 GB, 39.6%)** (5 connections) — `docs/tickets/010-baseline/proxy-allocs-top20.txt`
- **Tier 2.3 Stream Directly to ResponseWriter (no io.ReadAll)** (4 connections) — `docs/tickets/010-performance-improvements.md`
- **Tier 3.2 DEK Cache Copy Avoidance** (3 connections) — `docs/tickets/010-performance-improvements.md`
- **Tier 1.3 Proxy alloc_space Top-20 (22.29 GB cumulative)** (3 connections) — `docs/tickets/010-tier1.3/proxy-allocs-top20.txt`
- **Cumulative allocs Profile Requires Proxy Restart** (2 connections) — `docs/tickets/010-baseline/README.md`
- **Known DEK-Cache-Stale-On-Reupload Test Flakiness** (2 connections) — `docs/tickets/010-performance-improvements.md`
- **UploadHandler.handleStreamingUploadPart Alloc Path (13.49 GB, 60.5%)** (2 connections) — `docs/tickets/010-tier1.3/proxy-allocs-top20.txt`
- **Cache-Owned DEK Read-Only Contract** (1 connections) — `docs/tickets/010-performance-improvements.md`
- **GCM Response Content-Length = encrypted_len minus 28 (12-byte nonce + 16-byte tag)** (1 connections) — `docs/tickets/010-performance-improvements.md`

## Relationships

- [Baseline Allocation Profile](Baseline_Allocation_Profile.md) (2 shared connections)
- [Baseline Client Profiles](Baseline_Client_Profiles.md) (2 shared connections)
- [Streaming Throughput Ticket](Streaming_Throughput_Ticket.md) (2 shared connections)
- [Baseline Object Allocation Profile](Baseline_Object_Allocation_Profile.md) (1 shared connections)

## Source Files

- `docs/tickets/010-baseline/README.md`
- `docs/tickets/010-baseline/proxy-allocs-top20.txt`
- `docs/tickets/010-performance-improvements.md`
- `docs/tickets/010-tier1.3/proxy-allocs-top20.txt`

## Audit Trail

- EXTRACTED: 10 (67%)
- INFERRED: 5 (33%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*