# Segmented Manager Streaming IO

> 40 nodes · cohesion 0.08

## Key Concepts

- **io.Reader** (42 connections)
- **SealedPart** (13 connections) — `internal/orchestration/segmented.go`
- **Manager** (9 connections) — `internal/orchestration/segmented.go`
- **PlaintextSize()** (9 connections) — `internal/orchestration/segmented.go`
- **SegmentedUpload** (9 connections) — `internal/orchestration/segmented.go`
- **io.ReadCloser** (7 connections)
- **.codecFor()** (7 connections) — `internal/orchestration/segmented.go`
- **segmented.go** (6 connections) — `internal/orchestration/segmented.go`
- **PartStoredLen()** (5 connections) — `internal/orchestration/segmented.go`
- **.newSegmentedObject()** (5 connections) — `internal/orchestration/segmented.go`
- **.NewSegmentedWrite()** (5 connections) — `internal/orchestration/segmented.go`
- **.OpenSegmentedRange()** (5 connections) — `internal/orchestration/segmented.go`
- **SegmentedWrite** (5 connections) — `internal/orchestration/segmented.go`
- **fillPart()** (4 connections) — `internal/proxy/handlers/object/operations.go`
- **MpuCountingReader** (4 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **.OpenSegmented()** (4 connections) — `internal/orchestration/segmented.go`
- **.BodyWithTrailer()** (4 connections) — `internal/orchestration/segmented.go`
- **.SealPart()** (4 connections) — `internal/orchestration/segmented.go`
- **.SealStreamingPart()** (4 connections) — `internal/orchestration/segmented.go`
- **.NewReader()** (3 connections) — `pkg/encryption/dataencryption/segmented_gcm_io.go`
- **countingBody** (3 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **ObjGetclosedBody** (3 connections) — `internal/proxy/handlers/object/getobject_coverage_test.go`
- **ObjGetcloseErrReader** (3 connections) — `internal/proxy/handlers/object/getobject_coverage_test.go`
- **.IsSegmentedObject()** (3 connections) — `internal/orchestration/segmented.go`
- **.NewSegmentedUpload()** (3 connections) — `internal/orchestration/segmented.go`
- *... and 15 more nodes in this community*

## Relationships

- [Segmented GCM Reader and Writer](Segmented_GCM_Reader_and_Writer.md) (9 shared connections)
- [Segment Seal and Open Internals](Segment_Seal_and_Open_Internals.md) (9 shared connections)
- [Segmented Session Lifecycle](Segmented_Session_Lifecycle.md) (6 shared connections)
- [Segmented GCM Range Reader](Segmented_GCM_Range_Reader.md) (5 shared connections)
- [Multipart Handler Coverage Tests](Multipart_Handler_Coverage_Tests.md) (4 shared connections)
- [Response Header Helpers](Response_Header_Helpers.md) (4 shared connections)
- [Request Parser and Framing Tests](Request_Parser_and_Framing_Tests.md) (3 shared connections)
- [Ranged GET Path and Window](Ranged_GET_Path_and_Window.md) (3 shared connections)
- [Segmented GCM](Segmented_GCM.md) (3 shared connections)
- [Object GET Coverage Tests](Object_GET_Coverage_Tests.md) (3 shared connections)
- [Segmented Session Tests](Segmented_Session_Tests.md) (2 shared connections)
- [Multipart Semantics and ETag Marker](Multipart_Semantics_and_ETag_Marker.md) (2 shared connections)

## Source Files

- `internal/orchestration/segmented.go`
- `internal/orchestration/segmented_session.go`
- `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- `internal/proxy/handlers/object/getobject_coverage_test.go`
- `internal/proxy/handlers/object/operations.go`
- `pkg/encryption/dataencryption/segmented_gcm_io.go`
- `test/integration/s3-methods/encryption_at_rest_test.go`

## Audit Trail

- EXTRACTED: 132 (99%)
- INFERRED: 1 (1%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*