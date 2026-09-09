# Stale DEK Cache Ticket

> 6 nodes · cohesion 0.47

## Key Concepts

- **DEK cache key (fingerprint:objectKey)** (6 connections) — `docs/tickets/011-dek-cache-stale-on-reupload.md`
- **Ticket 011: DEK cache returns stale DEK after re-upload** (5 connections) — `docs/tickets/011-dek-cache-stale-on-reupload.md`
- **Option A: include encryptedDEK digest in the cache key** (2 connections) — `docs/tickets/011-dek-cache-stale-on-reupload.md`
- **Option C: key the cache by encryptedDEK only** (2 connections) — `docs/tickets/011-dek-cache-stale-on-reupload.md`
- **TestLargeMultipart500MB reproduction** (2 connections) — `docs/tickets/011-dek-cache-stale-on-reupload.md`
- **Option B: invalidate the DEK cache on write** (1 connections) — `docs/tickets/011-dek-cache-stale-on-reupload.md`

## Relationships

- [Orchestration README Staleness](Orchestration_README_Staleness.md) (1 shared connections)
- [Segmented Storage Format V2](Segmented_Storage_Format_V2.md) (1 shared connections)
- [Coverage Round Findings](Coverage_Round_Findings.md) (1 shared connections)
- [Performance Audit Round Two](Performance_Audit_Round_Two.md) (1 shared connections)

## Source Files

- `docs/tickets/011-dek-cache-stale-on-reupload.md`

## Audit Trail

- EXTRACTED: 8 (73%)
- INFERRED: 3 (27%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*