# Orchestration README Staleness

> 14 nodes · cohesion 0.24

## Key Concepts

- **internal/orchestration package overview (German, stale)** (8 connections) — `internal/orchestration/README.md`
- **multipart.go — session lifecycle Initiate/Process/Finalize/Abort** (7 connections) — `internal/orchestration/README.md`
- **manager.go — central orchestration facade** (5 connections) — `internal/orchestration/README.md`
- **metadata.go — build, filter and parse encryption metadata** (5 connections) — `internal/orchestration/README.md`
- **TestStreamingMultipartUploadEndToEnd round-trip scenario** (5 connections) — `test/integration/README.md`
- **singlepart.go — EncryptGCM / EncryptCTR data paths** (4 connections) — `internal/orchestration/README.md`
- **Multipart versus streaming: session state against reader wrapping** (3 connections) — `internal/orchestration/README.md`
- **providers.go — provider management and key caching** (3 connections) — `internal/orchestration/README.md`
- **ManagerV2 — a name this document uses that the tree does not have** (2 connections) — `internal/orchestration/README.md`
- **streaming.go — described but not present in the tree** (2 connections) — `internal/orchestration/README.md`
- **Direct MinIO inspection is expected to fail, proving encryption at rest** (2 connections) — `test/integration/README.md`
- **The proxy filters encryption metadata out of client responses** (2 connections) — `test/integration/README.md`
- **text.txt readable test fixture** (1 connections) — `test/example-files/text.txt`
- **SHA-256 round-trip verification** (1 connections) — `test/integration/README.md`

## Relationships

- [Segmented Storage Format V2](Segmented_Storage_Format_V2.md) (4 shared connections)
- [Performance Audit Round Two](Performance_Audit_Round_Two.md) (1 shared connections)
- [Stale DEK Cache Ticket](Stale_DEK_Cache_Ticket.md) (1 shared connections)

## Source Files

- `internal/orchestration/README.md`
- `test/example-files/text.txt`
- `test/integration/README.md`

## Audit Trail

- EXTRACTED: 17 (61%)
- INFERRED: 9 (32%)
- AMBIGUOUS: 2 (7%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*