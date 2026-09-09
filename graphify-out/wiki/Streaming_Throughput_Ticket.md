# Streaming Throughput Ticket

> 12 nodes · cohesion 0.23

## Key Concepts

- **Ticket 010: Performance Improvements - Streaming Throughput** (21 connections) — `docs/tickets/010-performance-improvements.md`
- **Tier 2.2 Single-Pass HMAC in DecryptGCMStream** (4 connections) — `docs/tickets/010-performance-improvements.md`
- **Tier 2.4 Parallel S3 UploadPart in putObjectAutoMultipart** (4 connections) — `docs/tickets/010-performance-improvements.md`
- **Tier 2.6 hmacGatedDecryptionReader Replaces Pipe plus Goroutine** (4 connections) — `docs/tickets/010-performance-improvements.md`
- **Last-Chunk Gating Invariant (hold one chunk until HMAC verifies)** (2 connections) — `docs/tickets/010-performance-improvements.md`
- **optimizations.multipart_upload_concurrency Knob (default 4, validated 1-32)** (2 connections) — `docs/tickets/010-performance-improvements.md`
- **Streaming Peak-Memory Bound (segment_size x (1 + concurrency))** (2 connections) — `docs/tickets/010-performance-improvements.md`
- **Tier 1.2 Remove Per-Read Mutex from CTR Stateful Encryptor** (2 connections) — `docs/tickets/010-performance-improvements.md`
- **Tier 2.1 Single-Pass HMAC via io.TeeReader in EncryptCTR** (2 connections) — `docs/tickets/010-performance-improvements.md`
- **Ordered Encryption with Parallel Upload Dispatch** (1 connections) — `docs/tickets/010-performance-improvements.md`
- **Single-Owner Sequential-Reads Contract on the CTR Encryptor** (1 connections) — `docs/tickets/010-performance-improvements.md`
- **Tier 3.3 Avoid Redundant bufio.NewReader Wrapping** (1 connections) — `docs/tickets/010-performance-improvements.md`

## Relationships

- [CPU Hotspot Baseline](CPU_Hotspot_Baseline.md) (4 shared connections)
- [Baseline Allocation Profile](Baseline_Allocation_Profile.md) (4 shared connections)
- [Baseline Object Allocation Profile](Baseline_Object_Allocation_Profile.md) (3 shared connections)
- [io.ReadAll Allocation Hotspot](io.ReadAll_Allocation_Hotspot.md) (2 shared connections)
- [Baseline Client Profiles](Baseline_Client_Profiles.md) (2 shared connections)
- [Architecture Analysis Findings](Architecture_Analysis_Findings.md) (1 shared connections)

## Source Files

- `docs/tickets/010-performance-improvements.md`

## Audit Trail

- EXTRACTED: 28 (90%)
- INFERRED: 3 (10%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*