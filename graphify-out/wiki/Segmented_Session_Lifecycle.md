# Segmented Session Lifecycle

> 35 nodes · cohesion 0.10

## Key Concepts

- **SegmentedSession** (37 connections) — `internal/orchestration/segmented_session.go`
- **Manager** (15 connections) — `internal/orchestration/segmented_session.go`
- **segmented_session.go** (9 connections) — `internal/orchestration/segmented_session.go`
- **.SealPart()** (7 connections) — `internal/orchestration/segmented_session.go`
- **.touch()** (7 connections) — `internal/orchestration/segmented_session.go`
- **.releaseSessionBudget()** (6 connections) — `internal/orchestration/segmented_session.go`
- **sessionPart** (5 connections) — `internal/orchestration/segmented_session.go`
- **touchingReader** (5 connections) — `internal/orchestration/segmented_session.go`
- **.releaseShortPart()** (4 connections) — `internal/orchestration/segmented_session.go`
- **.reserveShortPart()** (4 connections) — `internal/orchestration/segmented_session.go`
- **.dropPendingLocked()** (4 connections) — `internal/orchestration/segmented_session.go`
- **.RecordStreamedPart()** (4 connections) — `internal/orchestration/segmented_session.go`
- **CanStreamPart()** (3 connections) — `internal/orchestration/segmented_session.go`
- **FinalPart** (3 connections) — `internal/orchestration/segmented_session.go`
- **.AbandonAllSessions()** (3 connections) — `internal/orchestration/segmented_session.go`
- **.NewSegmentedSession()** (3 connections) — `internal/orchestration/segmented_session.go`
- **.Complete()** (3 connections) — `internal/orchestration/segmented_session.go`
- **.reserveLocked()** (3 connections) — `internal/orchestration/segmented_session.go`
- **.CloseSegmentedSession()** (2 connections) — `internal/orchestration/segmented_session.go`
- **.RegisterSegmentedSession()** (2 connections) — `internal/orchestration/segmented_session.go`
- **.ReleaseTransientBuffer()** (2 connections) — `internal/orchestration/segmented_session.go`
- **.ReserveTransientBuffer()** (2 connections) — `internal/orchestration/segmented_session.go`
- **.SegmentedSession()** (2 connections) — `internal/orchestration/segmented_session.go`
- **.ShortPartBufferSize()** (2 connections) — `internal/orchestration/segmented_session.go`
- **.Parts()** (2 connections) — `internal/orchestration/segmented_session.go`
- *... and 10 more nodes in this community*

## Relationships

- [Segmented Manager Streaming IO](Segmented_Manager_Streaming_IO.md) (7 shared connections)
- [Velero E2E Backup Suite](Velero_E2E_Backup_Suite.md) (6 shared connections)
- [Segmented Session Tests](Segmented_Session_Tests.md) (6 shared connections)
- [Multipart ListParts Handler](Multipart_ListParts_Handler.md) (5 shared connections)
- [Segment Seal and Open Internals](Segment_Seal_and_Open_Internals.md) (4 shared connections)
- [Health Probes and Request Tracker](Health_Probes_and_Request_Tracker.md) (2 shared connections)
- [Hostile Backend and Key Material ADRs](Hostile_Backend_and_Key_Material_ADRs.md) (1 shared connections)
- [Transfer Bounds and Shutdown](Transfer_Bounds_and_Shutdown.md) (1 shared connections)
- [Multipart Handler Wiring](Multipart_Handler_Wiring.md) (1 shared connections)
- [Integration Corpus Seed and Budget](Integration_Corpus_Seed_and_Budget.md) (1 shared connections)
- [DEK Cache and Provider Manager](DEK_Cache_and_Provider_Manager.md) (1 shared connections)
- [MockS3Backend Tagging and Policy](MockS3Backend_Tagging_and_Policy.md) (1 shared connections)

## Source Files

- `internal/orchestration/segmented_session.go`

## Audit Trail

- EXTRACTED: 94 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*