# Performance Tier Baselines

> 40 nodes · cohesion 0.06

## Key Concepts

- **Ticket 010 Tier 2 Snapshot (AFTER)** (8 connections) — `docs/tickets/010-tier2/README.md`
- **Tier 2 proxy CPU profile (15 s, 5.48 s samples, crypto + syscalls dominant)** (5 connections) — `docs/tickets/010-tier2/proxy-cpu-top20.txt`
- **Tier 2 proxy alloc_space profile (10 007.86 MB total)** (4 connections) — `docs/tickets/010-tier2/proxy-allocs-top20.txt`
- **Multipart upload alloc chain: UploadHandler.Handle → handleStreamingUploadPart → Parser.ReadBody → Manager.UploadPartStreaming → ProcessPart → processPartOrdered** (4 connections) — `docs/tickets/010-tier2/proxy-allocs-top20.txt`
- **memmove collapse: 10.3 % → 3.47 % of proxy CPU after Tier 2** (4 connections) — `docs/tickets/010-tier2/README.md`
- **Tier 2 client CPU profile (performance-test.test, 23.97 s / 4.53 s samples)** (3 connections) — `docs/tickets/010-tier2/cpu-top20.txt`
- **Client-side SHA-256 verification cost (crypto/sha256.Sum256, 17.88 % cum)** (3 connections) — `docs/tickets/010-tier2/cpu-top20.txt`
- **Tier 2 client alloc_space profile (3.59 GB, io.ReadAll 71.29 % inside runPerformanceTest)** (3 connections) — `docs/tickets/010-tier2/mem-alloc-space.txt`
- **performance-test runPerformanceTest (test harness allocating the 1 GB payload)** (3 connections) — `docs/tickets/010-tier2/mem-alloc-space.txt`
- **Tier 2 proxy alloc_objects profile (465 597 objects, HTTP/TLS plumbing on top)** (3 connections) — `docs/tickets/010-tier2/proxy-allocs-objects-top15.txt`
- **Crypto hardware floor (AES-NI + SHA-256 ~42 % of proxy CPU)** (3 connections) — `docs/tickets/010-tier2/README.md`
- **TestStreamingPerformance/Performance_1GB benchmark (MinIO loopback, fresh proxy)** (3 connections) — `docs/tickets/010-tier2/README.md`
- **Tier 2.5: eliminate geometric-growth append in processPartOrdered** (3 connections) — `docs/tickets/010-tier2/README.md`
- **Tier 3.1 / Tier 4 target: upload-side v4-chunked body collection via io.ReadAll** (3 connections) — `docs/tickets/010-tier2/README.md`
- **Tier 4.1 proxy alloc_objects profile (410 187 objects)** (3 connections) — `docs/tickets/010-tier4.1/proxy-allocs-objects-top15.txt`
- **Tier 2 client alloc_objects profile (204 319 objects, AWS SDK middleware dominated)** (2 connections) — `docs/tickets/010-tier2/mem-alloc-objects.txt`
- **hash/crc64 S3 SDK checksum cost (15.15 % cum in the proxy CPU profile)** (2 connections) — `docs/tickets/010-tier2/proxy-cpu-top20.txt`
- **orchestration.decryptionReader.Read download hot path (51.82 % cum, feeding io.copyBuffer)** (2 connections) — `docs/tickets/010-tier2/proxy-cpu-top20.txt`
- **AWSChunkedDecoder.RequiresChunkedDecoding (flat ~1.03 GB, Tier 4 candidate)** (2 connections) — `docs/tickets/010-tier2/README.md`
- **io.ReadAll as the dominant proxy alloc_space source (64.56 %)** (2 connections) — `docs/tickets/010-tier2/README.md`
- **logrus Entry.WithFields gone from the alloc_objects top-15 (Tier 1.3)** (2 connections) — `docs/tickets/010-tier2/README.md`
- **MinIO loopback is not alloc-bound (throughput stays flat while memory wins land)** (2 connections) — `docs/tickets/010-tier2/README.md`
- **MultipartOperations.processPartOrdered (alloc hotspot, 4.99 GB → 2.40 GB)** (2 connections) — `docs/tickets/010-tier2/README.md`
- **Proxy /debug/pprof endpoint on :9090 (profile capture surface)** (2 connections) — `docs/tickets/010-tier2/README.md`
- **Tier 2.3: remove io.ReadAll on the GCM-GET path** (2 connections) — `docs/tickets/010-tier2/README.md`
- *... and 15 more nodes in this community*

## Relationships

- No strong cross-community connections detected

## Source Files

- `docs/tickets/010-tier2/README.md`
- `docs/tickets/010-tier2/cpu-top20.txt`
- `docs/tickets/010-tier2/mem-alloc-objects.txt`
- `docs/tickets/010-tier2/mem-alloc-space.txt`
- `docs/tickets/010-tier2/proxy-allocs-objects-top15.txt`
- `docs/tickets/010-tier2/proxy-allocs-top20.txt`
- `docs/tickets/010-tier2/proxy-cpu-top20.txt`
- `docs/tickets/010-tier4.1/cpu-top20.txt`
- `docs/tickets/010-tier4.1/mem-alloc-objects.txt`
- `docs/tickets/010-tier4.1/mem-alloc-space.txt`
- `docs/tickets/010-tier4.1/proxy-allocs-objects-top15.txt`
- `docs/tickets/010-tier4.1/proxy-allocs-top20.txt`
- `docs/tickets/010-tier4.1/proxy-cpu-top20.txt`

## Audit Trail

- EXTRACTED: 33 (67%)
- INFERRED: 15 (31%)
- AMBIGUOUS: 1 (2%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*