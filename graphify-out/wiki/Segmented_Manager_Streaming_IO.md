# Segmented Manager Streaming IO

> 36 nodes · cohesion 0.10

## Key Concepts

- **io.Reader** (42 connections)
- **SealedPart** (13 connections) — `internal/orchestration/segmented.go`
- **Manager** (9 connections) — `internal/orchestration/segmented.go`
- **SegmentedUpload** (9 connections) — `internal/orchestration/segmented.go`
- **segmented.go** (8 connections) — `internal/orchestration/segmented.go`
- **io.ReadCloser** (7 connections)
- **.codecFor()** (7 connections) — `internal/orchestration/segmented.go`
- **PartStoredLen()** (5 connections) — `internal/orchestration/segmented.go`
- **PlanRange()** (5 connections) — `internal/orchestration/segmented.go`
- **.newSegmentedObject()** (5 connections) — `internal/orchestration/segmented.go`
- **.NewSegmentedWrite()** (5 connections) — `internal/orchestration/segmented.go`
- **.OpenSegmentedRange()** (5 connections) — `internal/orchestration/segmented.go`
- **.SealStreamingPart()** (5 connections) — `internal/orchestration/segmented_session.go`
- **SegmentedWrite** (5 connections) — `internal/orchestration/segmented.go`
- **.OpenSegmented()** (4 connections) — `internal/orchestration/segmented.go`
- **.BodyWithTrailer()** (4 connections) — `internal/orchestration/segmented.go`
- **.SealPart()** (4 connections) — `internal/orchestration/segmented.go`
- **.SealStreamingPart()** (4 connections) — `internal/orchestration/segmented.go`
- **.NewReader()** (3 connections) — `pkg/encryption/dataencryption/segmented_gcm_io.go`
- **ObjGetclosedBody** (3 connections) — `internal/proxy/handlers/object/getobject_coverage_test.go`
- **ObjGetcloseErrReader** (3 connections) — `internal/proxy/handlers/object/getobject_coverage_test.go`
- **.IsSegmentedObject()** (3 connections) — `internal/orchestration/segmented.go`
- **.NewSegmentedUpload()** (3 connections) — `internal/orchestration/segmented.go`
- **.OpenSegmentedTrailer()** (3 connections) — `internal/orchestration/segmented.go`
- **.Body()** (3 connections) — `internal/orchestration/segmented.go`
- *... and 11 more nodes in this community*

## Relationships

- [Segment Seal and Open Internals](Segment_Seal_and_Open_Internals.md) (9 shared connections)
- [Segmented GCM Reader and Writer](Segmented_GCM_Reader_and_Writer.md) (7 shared connections)
- [Segmented Session Lifecycle](Segmented_Session_Lifecycle.md) (7 shared connections)
- [Segmented GCM Range Reader](Segmented_GCM_Range_Reader.md) (5 shared connections)
- [Segment Encrypt Reader Tests](Segment_Encrypt_Reader_Tests.md) (4 shared connections)
- [Request Parser and Framing Tests](Request_Parser_and_Framing_Tests.md) (3 shared connections)
- [Bucket ACL and Accelerate Handlers](Bucket_ACL_and_Accelerate_Handlers.md) (3 shared connections)
- [Object Response Header Helpers](Object_Response_Header_Helpers.md) (3 shared connections)
- [Multipart Counting Readers](Multipart_Counting_Readers.md) (2 shared connections)
- [Segmented Session Tests](Segmented_Session_Tests.md) (2 shared connections)
- [Checksum](Checksum.md) (2 shared connections)
- [GET Copy Benchmarks](GET_Copy_Benchmarks.md) (2 shared connections)

## Source Files

- `internal/orchestration/segmented.go`
- `internal/orchestration/segmented_session.go`
- `internal/proxy/handlers/object/getobject_coverage_test.go`
- `pkg/encryption/dataencryption/segmented_gcm_io.go`
- `test/integration/s3-methods/encryption_at_rest_test.go`

## Audit Trail

- EXTRACTED: 126 (99%)
- INFERRED: 1 (1%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*