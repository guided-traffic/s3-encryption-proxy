# Segmented Session Tests

> 41 nodes · cohesion 0.14

## Key Concepts

- **segManager()** (35 connections) — `internal/orchestration/segmented_test.go`
- **segPlaintext()** (26 connections) — `internal/orchestration/segmented_test.go`
- **segmented_session_test.go** (22 connections) — `internal/orchestration/segmented_session_test.go`
- **segRegisteredSession()** (20 connections) — `internal/orchestration/segmented_session_test.go`
- **segmented_test.go** (14 connections) — `internal/orchestration/segmented_test.go`
- **TestSegmentedSessionEveryPartMovesTheIdleClock()** (8 connections) — `internal/orchestration/segmented_session_test.go`
- **TestSegmentedSessionASlowPartOutlivesTheIdleTimeout()** (7 connections) — `internal/orchestration/segmented_session_test.go`
- **TestSegmentedSessionShortLastPart()** (7 connections) — `internal/orchestration/segmented_session_test.go`
- **TestSegmentedSessionHeldPartReplacedByAStreamedOne()** (6 connections) — `internal/orchestration/segmented_session_test.go`
- **TestSegmentedSessionShortPartBudgetIsReleasedOnEveryEnding()** (6 connections) — `internal/orchestration/segmented_session_test.go`
- **TestSegmentedSessionTrailerAsItsOwnPart()** (6 connections) — `internal/orchestration/segmented_session_test.go`
- **TestSegmentedTrailerAnswersHead()** (6 connections) — `internal/orchestration/segmented_test.go`
- **slowReader** (6 connections) — `internal/orchestration/segmented_session_test.go`
- **assembleSession()** (5 connections) — `internal/orchestration/segmented_session_test.go`
- **segCompleted()** (5 connections) — `internal/orchestration/segmented_session_test.go`
- **TestSegmentedSessionAlignedLastPartOutOfOrderIsRefused()** (5 connections) — `internal/orchestration/segmented_session_test.go`
- **TestSegmentedSessionFailedStreamKeepsTheHeldPart()** (5 connections) — `internal/orchestration/segmented_session_test.go`
- **TestSegmentedSessionHeldPartReplacedByAStorableOne()** (5 connections) — `internal/orchestration/segmented_session_test.go`
- **TestSegmentedSessionInfersThePartSizeWhateverArrivesFirst()** (5 connections) — `internal/orchestration/segmented_session_test.go`
- **TestSegmentedSessionLifecycle()** (5 connections) — `internal/orchestration/segmented_session_test.go`
- **TestSegmentedSessionPartReupload()** (5 connections) — `internal/orchestration/segmented_session_test.go`
- **TestSegmentedSessionRefusesABufferAboveTheLimit()** (5 connections) — `internal/orchestration/segmented_session_test.go`
- **TestSegmentedSessionRefusesALayoutItCannotStore()** (5 connections) — `internal/orchestration/segmented_session_test.go`
- **TestSegmentedSessionRefusesASecondShortPart()** (5 connections) — `internal/orchestration/segmented_session_test.go`
- **TestSegmentedSessionShortPartBudgetIsSharedAcrossSessions()** (5 connections) — `internal/orchestration/segmented_session_test.go`
- *... and 16 more nodes in this community*

## Relationships

- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (34 shared connections)
- [Segmented Session Lifecycle](Segmented_Session_Lifecycle.md) (6 shared connections)
- [Velero E2E Backup Suite](Velero_E2E_Backup_Suite.md) (3 shared connections)
- [Segment Encrypt Reader Tests](Segment_Encrypt_Reader_Tests.md) (2 shared connections)
- [Segmented GCM](Segmented_GCM.md) (2 shared connections)
- [Object Response Header Helpers](Object_Response_Header_Helpers.md) (2 shared connections)
- [Orchestration Manager Coverage](Orchestration_Manager_Coverage.md) (2 shared connections)
- [DEK Cache and Provider Manager](DEK_Cache_and_Provider_Manager.md) (2 shared connections)
- [Segmented Manager Streaming IO](Segmented_Manager_Streaming_IO.md) (2 shared connections)
- [Health Probes and Request Tracker](Health_Probes_and_Request_Tracker.md) (1 shared connections)

## Source Files

- `internal/orchestration/segmented_session_test.go`
- `internal/orchestration/segmented_test.go`

## Audit Trail

- EXTRACTED: 131 (77%)
- INFERRED: 39 (23%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*