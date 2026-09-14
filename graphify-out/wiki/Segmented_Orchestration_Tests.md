# Segmented Orchestration Tests

> 26 nodes · cohesion 0.20

## Key Concepts

- **segManager()** (25 connections) — `internal/orchestration/segmented_test.go`
- **segPlaintext()** (16 connections) — `internal/orchestration/segmented_test.go`
- **segRegisteredSession()** (12 connections) — `internal/orchestration/segmented_session_test.go`
- **segmented_test.go** (12 connections) — `internal/orchestration/segmented_test.go`
- **segmented_session_test.go** (10 connections) — `internal/orchestration/segmented_session_test.go`
- **TestSegmentedSessionShortLastPart()** (7 connections) — `internal/orchestration/segmented_session_test.go`
- **TestSegmentedSessionTrailerAsItsOwnPart()** (6 connections) — `internal/orchestration/segmented_session_test.go`
- **assembleSession()** (5 connections) — `internal/orchestration/segmented_session_test.go`
- **TestSegmentedSessionInfersThePartSizeWhateverArrivesFirst()** (5 connections) — `internal/orchestration/segmented_session_test.go`
- **TestSegmentedSessionLifecycle()** (5 connections) — `internal/orchestration/segmented_session_test.go`
- **TestSegmentedSessionPartReupload()** (5 connections) — `internal/orchestration/segmented_session_test.go`
- **TestSegmentedSessionRefusesABufferAboveTheLimit()** (5 connections) — `internal/orchestration/segmented_session_test.go`
- **TestSegmentedSessionRefusesALayoutItCannotStore()** (5 connections) — `internal/orchestration/segmented_session_test.go`
- **TestSegmentedSessionRefusesASecondShortPart()** (5 connections) — `internal/orchestration/segmented_session_test.go`
- **TestSegmentedRangeRead()** (5 connections) — `internal/orchestration/segmented_test.go`
- **TestSegmentedTrailerAnswersHead()** (5 connections) — `internal/orchestration/segmented_test.go`
- **TestSegmentedUploadRoundTrip()** (5 connections) — `internal/orchestration/segmented_test.go`
- **TestSegmentedOpenRefusesAnEditedKeyWrap()** (4 connections) — `internal/orchestration/segmented_test.go`
- **TestSegmentedPartRetryReSealsTheSamePlaintext()** (4 connections) — `internal/orchestration/segmented_test.go`
- **TestSegmentedReadRefusesAnotherObjectsBytes()** (4 connections) — `internal/orchestration/segmented_test.go`
- **TestSegmentedWriteRoundTrip()** (4 connections) — `internal/orchestration/segmented_test.go`
- **TestSegmentedOpenRefusesForeignObjects()** (3 connections) — `internal/orchestration/segmented_test.go`
- **TestSegmentedPartRefusesLayoutsTheReaderCannotOpen()** (3 connections) — `internal/orchestration/segmented_test.go`
- **TestSegmentedWriteMetadataSet()** (3 connections) — `internal/orchestration/segmented_test.go`
- **Manager** (1 connections)
- *... and 1 more nodes in this community*

## Relationships

- [Config Env Expansion](Config_Env_Expansion.md) (22 shared connections)
- [Multipart Session Table](Multipart_Session_Table.md) (3 shared connections)
- [Segment Codec Tests](Segment_Codec_Tests.md) (2 shared connections)
- [Provider Manager](Provider_Manager.md) (2 shared connections)
- [Metadata Manager Tests](Metadata_Manager_Tests.md) (1 shared connections)
- [Orchestration Manager](Orchestration_Manager.md) (1 shared connections)
- [Sealed Part Arithmetic](Sealed_Part_Arithmetic.md) (1 shared connections)
- [Object Operations Handler](Object_Operations_Handler.md) (1 shared connections)

## Source Files

- `internal/orchestration/segmented_session_test.go`
- `internal/orchestration/segmented_test.go`

## Audit Trail

- EXTRACTED: 78 (79%)
- INFERRED: 21 (21%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*