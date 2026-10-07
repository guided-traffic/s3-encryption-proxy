# Client-Driven Multipart Paths

> 10 nodes · cohesion 0.20

## Key Concepts

- **.PlaintextContentLength()** (5 connections) — `internal/proxy/request/parser.go`
- **The Internal Multipart Producer** (4 connections) — `docs/developer/multipart.md`
- **The Client-Driven Multipart Upload** (3 connections) — `docs/developer/multipart.md`
- **UploadHandler.Handle** (3 connections) — `docs/developer/multipart.md`
- **A Part Is Streamed or Held, and the Declared Length Decides** (2 connections) — `docs/developer/multipart.md`
- **A Client That Hangs Up Mid-Body Must Not Commit** (2 connections) — `docs/developer/multipart.md`
- **putObjectAutoMultipart** (2 connections) — `docs/developer/multipart.md`
- **orchestration.CanStreamPart** (1 connections) — `docs/developer/multipart.md`
- **SegmentedSession** (1 connections) — `docs/developer/multipart.md`
- **utils.CleanupContext** (1 connections) — `docs/developer/multipart.md`

## Relationships

- [Bucket ACL and Accelerate Handlers](Bucket_ACL_and_Accelerate_Handlers.md) (3 shared connections)
- [Entity Tag Marker](Entity_Tag_Marker.md) (2 shared connections)
- [Short-Part Budget and Memory](Short-Part_Budget_and_Memory.md) (1 shared connections)

## Source Files

- `docs/developer/multipart.md`
- `internal/proxy/request/parser.go`

## Audit Trail

- EXTRACTED: 14 (93%)
- INFERRED: 1 (7%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*