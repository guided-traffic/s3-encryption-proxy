# Orchestration: Segmented Session

> 25 nodes · cohesion 0.14

## Key Concepts

- **SegmentedSession** (34 connections) — `internal/orchestration/segmented_session.go`
- **assembleSession()** (10 connections) — `internal/orchestration/segmented_session_test.go`
- **.SealPart()** (9 connections) — `internal/orchestration/segmented_session.go`
- **.RecordETag()** (8 connections) — `internal/orchestration/segmented_session.go`
- **.SealStreamingPart()** (8 connections) — `internal/orchestration/segmented_session.go`
- **sinceStart()** (7 connections) — `internal/orchestration/segmented_session.go`
- **segStreamPart()** (7 connections) — `internal/orchestration/segmented_session_test.go`
- **.RecordStreamedPart()** (7 connections) — `internal/orchestration/segmented_session.go`
- **.touch()** (7 connections) — `internal/orchestration/segmented_session.go`
- **touchingReader** (5 connections) — `internal/orchestration/segmented_session.go`
- **sessionPart** (4 connections) — `internal/orchestration/segmented_session.go`
- **CanStreamPart()** (3 connections) — `internal/orchestration/segmented_session.go`
- **.dropPendingLocked()** (3 connections) — `internal/orchestration/segmented_session.go`
- **.idleFor()** (3 connections) — `internal/orchestration/segmented_session.go`
- **.PartChecksum()** (3 connections) — `internal/orchestration/segmented_session.go`
- **.PartETag()** (3 connections) — `internal/orchestration/segmented_session.go`
- **SessionPart** (3 connections) — `internal/orchestration/segmented_session.go`
- **.NewSegmentedSession()** (2 connections) — `internal/orchestration/segmented_session.go`
- **.PartNumbers()** (2 connections) — `internal/orchestration/segmented_session.go`
- **.Parts()** (2 connections) — `internal/orchestration/segmented_session.go`
- **.reserveLocked()** (2 connections) — `internal/orchestration/segmented_session.go`
- **.Read()** (2 connections) — `internal/orchestration/segmented_session.go`
- **.RegisterSegmentedSession()** (1 connections) — `internal/orchestration/segmented_session.go`
- **.releaseSessionBudget()** (1 connections) — `internal/orchestration/segmented_session.go`
- **.Close()** (1 connections) — `internal/orchestration/segmented_session.go`

## Relationships

- [Segmented Session Tests](Segmented_Session_Tests.md) (12 shared connections)
- [Request Documents and Owner Guard](Request_Documents_and_Owner_Guard.md) (11 shared connections)
- [Segment Seal and Trailer](Segment_Seal_and_Trailer.md) (8 shared connections)
- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (6 shared connections)
- [Server and Listings](Server_and_Listings.md) (3 shared connections)
- [Keygen and Encrypt Readers](Keygen_and_Encrypt_Readers.md) (3 shared connections)
- [Etag: Etag](Etag-_Etag.md) (2 shared connections)
- [Velero E2E Suite](Velero_E2E_Suite.md) (2 shared connections)
- [Shutdown and Test Contexts](Shutdown_and_Test_Contexts.md) (2 shared connections)
- [Multipart Handlers and Manager](Multipart_Handlers_and_Manager.md) (1 shared connections)
- [Orchestration: Providers Coverage Test (2)](Orchestration-_Providers_Coverage_Test_2.md) (1 shared connections)
- [Object Checksum Agreement Tests](Object_Checksum_Agreement_Tests.md) (1 shared connections)

## Source Files

- `internal/orchestration/segmented_session.go`
- `internal/orchestration/segmented_session_test.go`

## Audit Trail

- EXTRACTED: 67 (70%)
- INFERRED: 29 (30%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*