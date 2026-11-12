# Orchestration: Segmented Session

> 27 nodes · cohesion 0.14

## Key Concepts

- **SegmentedSession** (34 connections) — `internal/orchestration/segmented_session.go`
- **TestSegmentedSessionEveryPartMovesTheIdleClock()** (11 connections) — `internal/orchestration/segmented_session_test.go`
- **assembleSession()** (10 connections) — `internal/orchestration/segmented_session_test.go`
- **.SealPart()** (9 connections) — `internal/orchestration/segmented_session.go`
- **.RecordETag()** (8 connections) — `internal/orchestration/segmented_session.go`
- **.SealStreamingPart()** (8 connections) — `internal/orchestration/segmented_session.go`
- **sinceStart()** (7 connections) — `internal/orchestration/segmented_session.go`
- **segStreamPart()** (7 connections) — `internal/orchestration/segmented_session_test.go`
- **.RecordStreamedPart()** (7 connections) — `internal/orchestration/segmented_session.go`
- **.touch()** (7 connections) — `internal/orchestration/segmented_session.go`
- **segCompleted()** (6 connections) — `internal/orchestration/segmented_session_test.go`
- **.Complete()** (5 connections) — `internal/orchestration/segmented_session.go`
- **touchingReader** (5 connections) — `internal/orchestration/segmented_session.go`
- **sessionPart** (4 connections) — `internal/orchestration/segmented_session.go`
- **CanStreamPart()** (3 connections) — `internal/orchestration/segmented_session.go`
- **FinalPart** (3 connections) — `internal/orchestration/segmented_session.go`
- **.dropPendingLocked()** (3 connections) — `internal/orchestration/segmented_session.go`
- **.idleFor()** (3 connections) — `internal/orchestration/segmented_session.go`
- **.PartChecksum()** (3 connections) — `internal/orchestration/segmented_session.go`
- **.PartETag()** (3 connections) — `internal/orchestration/segmented_session.go`
- **.NewSegmentedSession()** (2 connections) — `internal/orchestration/segmented_session.go`
- **.PartNumbers()** (2 connections) — `internal/orchestration/segmented_session.go`
- **.reserveLocked()** (2 connections) — `internal/orchestration/segmented_session.go`
- **.Read()** (2 connections) — `internal/orchestration/segmented_session.go`
- **.RegisterSegmentedSession()** (1 connections) — `internal/orchestration/segmented_session.go`
- *... and 2 more nodes in this community*

## Relationships

- [Request Documents and Owner Guard](Request_Documents_and_Owner_Guard.md) (12 shared connections)
- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (10 shared connections)
- [Segmented Session Tests](Segmented_Session_Tests.md) (8 shared connections)
- [Segment Seal and Trailer](Segment_Seal_and_Trailer.md) (7 shared connections)
- [Shutdown and Test Contexts](Shutdown_and_Test_Contexts.md) (4 shared connections)
- [Server and Listings](Server_and_Listings.md) (3 shared connections)
- [Multipart Handlers and Manager](Multipart_Handlers_and_Manager.md) (2 shared connections)
- [Etag: Etag](Etag-_Etag.md) (2 shared connections)
- [Shutdown: Shutdown Test](Shutdown-_Shutdown_Test.md) (2 shared connections)
- [Segment Codec and Range Planner](Segment_Codec_and_Range_Planner.md) (2 shared connections)
- [Dataencryption: Segmented Gcm Range](Dataencryption-_Segmented_Gcm_Range.md) (2 shared connections)
- [Tampering Harness](Tampering_Harness.md) (1 shared connections)

## Source Files

- `internal/orchestration/segmented_session.go`
- `internal/orchestration/segmented_session_test.go`

## Audit Trail

- EXTRACTED: 75 (69%)
- INFERRED: 33 (31%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*