# Multipart Session Table

> 18 nodes · cohesion 0.14

## Key Concepts

- **SegmentedSession** (19 connections) — `internal/orchestration/segmented_session.go`
- **Manager** (6 connections) — `internal/orchestration/segmented_session.go`
- **sync.Mutex** (4 connections)
- **.SealPart()** (4 connections) — `internal/orchestration/segmented_session.go`
- **segmented_session.go** (3 connections) — `internal/orchestration/segmented_session.go`
- **.Complete()** (3 connections) — `internal/orchestration/segmented_session.go`
- **sessionPart** (3 connections) — `internal/orchestration/segmented_session.go`
- **FinalPart** (2 connections) — `internal/orchestration/segmented_session.go`
- **.CleanupExpiredSegmentedSessions()** (2 connections) — `internal/orchestration/segmented_session.go`
- **.NewSegmentedSession()** (2 connections) — `internal/orchestration/segmented_session.go`
- **.RegisterSegmentedSession()** (2 connections) — `internal/orchestration/segmented_session.go`
- **.SegmentedSession()** (2 connections) — `internal/orchestration/segmented_session.go`
- **.CloseSegmentedSession()** (1 connections) — `internal/orchestration/segmented_session.go`
- **.ShortPartBufferSize()** (1 connections) — `internal/orchestration/segmented_session.go`
- **.PartETag()** (1 connections) — `internal/orchestration/segmented_session.go`
- **.PartNumbers()** (1 connections) — `internal/orchestration/segmented_session.go`
- **.RecordETag()** (1 connections) — `internal/orchestration/segmented_session.go`
- **.VerifyClientParts()** (1 connections) — `internal/orchestration/segmented_session.go`

## Relationships

- [Segmented Orchestration Tests](Segmented_Orchestration_Tests.md) (3 shared connections)
- [Multipart Handler](Multipart_Handler.md) (2 shared connections)
- [Sealed Part Arithmetic](Sealed_Part_Arithmetic.md) (2 shared connections)
- [Object PUT Handler Tests](Object_PUT_Handler_Tests.md) (1 shared connections)
- [Provider Manager](Provider_Manager.md) (1 shared connections)
- [SigV4 Signing Helper](SigV4_Signing_Helper.md) (1 shared connections)
- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (1 shared connections)
- [Velero E2E Suite](Velero_E2E_Suite.md) (1 shared connections)
- [Segment Codec Tests](Segment_Codec_Tests.md) (1 shared connections)
- [Segment Codec Core](Segment_Codec_Core.md) (1 shared connections)

## Source Files

- `internal/orchestration/segmented_session.go`

## Audit Trail

- EXTRACTED: 36 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*