# Segmented Session Tests

> 33 nodes · cohesion 0.13

## Key Concepts

- **segManager()** (35 connections) — `internal/orchestration/segmented_test.go`
- **segPlaintext()** (26 connections) — `internal/orchestration/segmented_test.go`
- **segRegisteredSession()** (20 connections) — `internal/orchestration/segmented_session_test.go`
- **TestSegmentedSessionASlowPartOutlivesTheIdleTimeout()** (8 connections) — `internal/orchestration/segmented_session_test.go`
- **TestSegmentedSessionShortLastPart()** (7 connections) — `internal/orchestration/segmented_session_test.go`
- **TestSegmentedSessionHeldPartReplacedByAStreamedOne()** (6 connections) — `internal/orchestration/segmented_session_test.go`
- **TestSegmentedSessionShortPartBudgetIsReleasedOnEveryEnding()** (6 connections) — `internal/orchestration/segmented_session_test.go`
- **TestSegmentedSessionTrailerAsItsOwnPart()** (6 connections) — `internal/orchestration/segmented_session_test.go`
- **TestSegmentedTrailerAnswersHead()** (6 connections) — `internal/orchestration/segmented_test.go`
- **TestSegmentedUploadRoundTrip()** (6 connections) — `internal/orchestration/segmented_test.go`
- **TestSegmentedWriteDrawsAFreshDataKeyPerObject()** (6 connections) — `internal/orchestration/segmented_test.go`
- **TestSegmentedSessionAlignedLastPartOutOfOrderIsRefused()** (5 connections) — `internal/orchestration/segmented_session_test.go`
- **TestSegmentedSessionFailedStreamKeepsTheHeldPart()** (5 connections) — `internal/orchestration/segmented_session_test.go`
- **TestSegmentedSessionHeldPartReplacedByAStorableOne()** (5 connections) — `internal/orchestration/segmented_session_test.go`
- **TestSegmentedSessionInfersThePartSizeWhateverArrivesFirst()** (5 connections) — `internal/orchestration/segmented_session_test.go`
- **TestSegmentedSessionPartReupload()** (5 connections) — `internal/orchestration/segmented_session_test.go`
- **TestSegmentedSessionRefusesABufferAboveTheLimit()** (5 connections) — `internal/orchestration/segmented_session_test.go`
- **TestSegmentedSessionRefusesALayoutItCannotStore()** (5 connections) — `internal/orchestration/segmented_session_test.go`
- **TestSegmentedSessionRefusesASecondShortPart()** (5 connections) — `internal/orchestration/segmented_session_test.go`
- **TestSegmentedSessionShortPartBudgetIsSharedAcrossSessions()** (5 connections) — `internal/orchestration/segmented_session_test.go`
- **TestSegmentedRangeRead()** (5 connections) — `internal/orchestration/segmented_test.go`
- **.SetMultipartAbandoner()** (5 connections) — `internal/orchestration/manager.go`
- **TestSegmentedSessionLifecycle()** (4 connections) — `internal/orchestration/segmented_session_test.go`
- **TestSegmentedAssociatedDataDoesNotBindTheBucket()** (4 connections) — `internal/orchestration/segmented_test.go`
- **TestSegmentedOpenRefusesAnEditedKeyWrap()** (4 connections) — `internal/orchestration/segmented_test.go`
- *... and 8 more nodes in this community*

## Relationships

- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (32 shared connections)
- [Shutdown and Test Contexts](Shutdown_and_Test_Contexts.md) (31 shared connections)
- [Orchestration: Segmented Session](Orchestration-_Segmented_Session.md) (8 shared connections)
- [Multipart Handlers and Manager](Multipart_Handlers_and_Manager.md) (4 shared connections)
- [GET Response Writing](GET_Response_Writing.md) (2 shared connections)
- [Orchestration: Providers Coverage Test](Orchestration-_Providers_Coverage_Test.md) (2 shared connections)
- [Storedobject: Storedobject](Storedobject-_Storedobject.md) (2 shared connections)
- [Shutdown: Shutdown Test](Shutdown-_Shutdown_Test.md) (1 shared connections)
- [Manager Tests](Manager_Tests.md) (1 shared connections)
- [Dataencryption: Segmented Gcm Range](Dataencryption-_Segmented_Gcm_Range.md) (1 shared connections)
- [Segment Codec and Range Planner](Segment_Codec_and_Range_Planner.md) (1 shared connections)
- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (1 shared connections)

## Source Files

- `internal/orchestration/manager.go`
- `internal/orchestration/metadata_coverage_test.go`
- `internal/orchestration/segmented_session_test.go`
- `internal/orchestration/segmented_test.go`

## Audit Trail

- EXTRACTED: 117 (75%)
- INFERRED: 40 (25%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*