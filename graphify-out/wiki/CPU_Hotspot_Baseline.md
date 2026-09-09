# CPU Hotspot Baseline

> 9 nodes · cohesion 0.25

## Key Concepts

- **Tier 1.1 In-Place XOR in AES-CTR Stateful Encryptor** (5 connections) — `docs/tickets/010-performance-improvements.md`
- **Baseline Proxy CPU Top-20** (4 connections) — `docs/tickets/010-baseline/proxy-cpu-top20.txt`
- **AES-NI plus SHA-256 Crypto Floor** (4 connections) — `docs/tickets/010-performance-improvements.md`
- **Tier 3.1 AES-GCM Copy-Avoidance (in-place Seal/Open)** (3 connections) — `docs/tickets/010-performance-improvements.md`
- **AESCTRStatefulEncryptor En/DecryptPart Alloc Hotspot (2.25 GB)** (2 connections) — `docs/tickets/010-baseline/proxy-allocs-top20.txt`
- **runtime.memmove CPU Hotspot (10.3%)** (2 connections) — `docs/tickets/010-baseline/proxy-cpu-top20.txt`
- **Chunked GCM Framing (Rejected)** (2 connections) — `docs/tickets/010-performance-improvements.md`
- **MinIO Loopback Masks Network-Latency Wins** (2 connections) — `docs/tickets/010-performance-improvements.md`
- **hash/crc64 Checksum CPU Cost (6.5%)** (1 connections) — `docs/tickets/010-baseline/proxy-cpu-top20.txt`

## Relationships

- [Streaming Throughput Ticket](Streaming_Throughput_Ticket.md) (4 shared connections)
- [Baseline Allocation Profile](Baseline_Allocation_Profile.md) (2 shared connections)
- [Baseline Client Profiles](Baseline_Client_Profiles.md) (1 shared connections)

## Source Files

- `docs/tickets/010-baseline/proxy-allocs-top20.txt`
- `docs/tickets/010-baseline/proxy-cpu-top20.txt`
- `docs/tickets/010-performance-improvements.md`

## Audit Trail

- EXTRACTED: 15 (94%)
- INFERRED: 1 (6%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*