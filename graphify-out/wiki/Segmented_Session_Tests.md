# Segmented Session Tests

> 39 nodes · cohesion 0.13

## Key Concepts

- **segmented_session_test.go** (60 connections) — `internal/orchestration/segmented_session_test.go`
- **segManager()** (35 connections) — `internal/orchestration/segmented_test.go`
- **segPlaintext()** (26 connections) — `internal/orchestration/segmented_test.go`
- **segRegisteredSession()** (20 connections) — `internal/orchestration/segmented_session_test.go`
- **TestSegmentedSessionEveryPartMovesTheIdleClock()** (11 connections) — `internal/orchestration/segmented_session_test.go`
- **TestSegmentedSessionASlowPartOutlivesTheIdleTimeout()** (8 connections) — `internal/orchestration/segmented_session_test.go`
- **TestSegmentedSessionShortLastPart()** (7 connections) — `internal/orchestration/segmented_session_test.go`
- **segCompleted()** (6 connections) — `internal/orchestration/segmented_session_test.go`
- **TestSegmentedSessionHeldPartReplacedByAStreamedOne()** (6 connections) — `internal/orchestration/segmented_session_test.go`
- **TestSegmentedSessionShortPartBudgetIsReleasedOnEveryEnding()** (6 connections) — `internal/orchestration/segmented_session_test.go`
- **TestSegmentedSessionTrailerAsItsOwnPart()** (6 connections) — `internal/orchestration/segmented_session_test.go`
- **TestSegmentedTrailerAnswersHead()** (6 connections) — `internal/orchestration/segmented_test.go`
- **TestSegmentedUploadRoundTrip()** (6 connections) — `internal/orchestration/segmented_test.go`
- **TestSegmentedWriteDrawsAFreshDataKeyPerObject()** (6 connections) — `internal/orchestration/segmented_test.go`
- **.SetMultipartAbandoner()** (6 connections) — `internal/orchestration/manager.go`
- **slowReader** (6 connections) — `internal/orchestration/segmented_session_test.go`
- **TestSegmentedSessionAlignedLastPartOutOfOrderIsRefused()** (5 connections) — `internal/orchestration/segmented_session_test.go`
- **TestSegmentedSessionFailedStreamKeepsTheHeldPart()** (5 connections) — `internal/orchestration/segmented_session_test.go`
- **TestSegmentedSessionHeldPartReplacedByAStorableOne()** (5 connections) — `internal/orchestration/segmented_session_test.go`
- **TestSegmentedSessionInfersThePartSizeWhateverArrivesFirst()** (5 connections) — `internal/orchestration/segmented_session_test.go`
- **TestSegmentedSessionPartReupload()** (5 connections) — `internal/orchestration/segmented_session_test.go`
- **TestSegmentedSessionRefusesABufferAboveTheLimit()** (5 connections) — `internal/orchestration/segmented_session_test.go`
- **TestSegmentedSessionRefusesALayoutItCannotStore()** (5 connections) — `internal/orchestration/segmented_session_test.go`
- **TestSegmentedSessionRefusesASecondShortPart()** (5 connections) — `internal/orchestration/segmented_session_test.go`
- **TestSegmentedSessionShortPartBudgetIsSharedAcrossSessions()** (5 connections) — `internal/orchestration/segmented_session_test.go`
- *... and 14 more nodes in this community*

## Relationships

- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (49 shared connections)
- [Shutdown and Test Contexts](Shutdown_and_Test_Contexts.md) (33 shared connections)
- [Orchestration: Segmented Session](Orchestration-_Segmented_Session.md) (12 shared connections)
- [Segment Codec and Range Planner](Segment_Codec_and_Range_Planner.md) (6 shared connections)
- [Multipart Handlers and Manager](Multipart_Handlers_and_Manager.md) (5 shared connections)
- [Object Checksum and Tagging Tests](Object_Checksum_and_Tagging_Tests.md) (2 shared connections)
- [Segment Seal and Trailer](Segment_Seal_and_Trailer.md) (2 shared connections)
- [Velero E2E Suite](Velero_E2E_Suite.md) (2 shared connections)
- [Orchestration: Providers Coverage Test](Orchestration-_Providers_Coverage_Test.md) (2 shared connections)
- [Storedobject: Storedobject](Storedobject-_Storedobject.md) (2 shared connections)
- [Multipart Checksum Answers](Multipart_Checksum_Answers.md) (1 shared connections)
- [Object Checksum Agreement Tests](Object_Checksum_Agreement_Tests.md) (1 shared connections)

## Source Files

- `internal/orchestration/manager.go`
- `internal/orchestration/metadata_coverage_test.go`
- `internal/orchestration/segmented_session_test.go`
- `internal/orchestration/segmented_test.go`

## Audit Trail

- EXTRACTED: 172 (79%)
- INFERRED: 47 (21%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*