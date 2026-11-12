# Dataencryption: Segmented Gcm Range

> 30 nodes · cohesion 0.09

## Key Concepts

- **io.Reader** (45 connections)
- **io.ReadCloser** (9 connections)
- **copyWithPooledBuffer()** (9 connections) — `internal/proxy/handlers/object/helpers.go`
- **rangeReader** (8 connections) — `pkg/encryption/dataencryption/segmented_gcm_range.go`
- **Window** (6 connections) — `pkg/encryption/dataencryption/segmented_gcm_range.go`
- **PlanRange()** (5 connections) — `internal/orchestration/segmented.go`
- **.BodyWithTrailer()** (5 connections) — `internal/orchestration/segmented.go`
- **SegmentedWrite** (5 connections) — `internal/orchestration/segmented.go`
- **.NewRangeReader()** (4 connections) — `pkg/encryption/dataencryption/segmented_gcm_range.go`
- **forwardingWriter** (4 connections) — `internal/proxy/handlers/object/copy_bench_test.go`
- **.Body()** (4 connections) — `internal/orchestration/segmented.go`
- **.NewReader()** (3 connections) — `pkg/encryption/dataencryption/segmented_gcm_io.go`
- **TestObjMiscCopyWithPooledBufferPropagatesReadErrors()** (3 connections) — `internal/proxy/handlers/object/metadata_coverage_test.go`
- **countingBody** (3 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **.NewSegmentedWrite()** (3 connections) — `internal/orchestration/segmented.go`
- **.OpenSegmentedRange()** (3 connections) — `internal/orchestration/segmented.go`
- **countingReader** (3 connections) — `internal/proxy/request/parser_test.go`
- **EncUnseekable** (3 connections) — `test/integration/s3-methods/encryption_at_rest_test.go`
- **.finish()** (2 connections) — `pkg/encryption/dataencryption/segmented_gcm_range.go`
- **.Read()** (2 connections) — `pkg/encryption/dataencryption/segmented_gcm_range.go`
- **.ReadFrom()** (2 connections) — `internal/proxy/handlers/object/copy_bench_test.go`
- **.Unwrap()** (2 connections) — `internal/proxy/handlers/object/copy_bench_test.go`
- **.OpenSegmented()** (2 connections) — `internal/orchestration/segmented.go`
- **unknownLength** (2 connections) — `test/integration/s3enc/helpers_test.go`
- **.Close()** (1 connections) — `pkg/encryption/dataencryption/segmented_gcm_range.go`
- *... and 5 more nodes in this community*

## Relationships

- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (9 shared connections)
- [Keygen and Encrypt Readers](Keygen_and_Encrypt_Readers.md) (7 shared connections)
- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (7 shared connections)
- [Request Documents and Owner Guard](Request_Documents_and_Owner_Guard.md) (7 shared connections)
- [Segment Seal and Trailer](Segment_Seal_and_Trailer.md) (7 shared connections)
- [Segment Codec and Range Planner](Segment_Codec_and_Range_Planner.md) (3 shared connections)
- [Shutdown and Test Contexts](Shutdown_and_Test_Contexts.md) (3 shared connections)
- [Storedobject: Storedobject](Storedobject-_Storedobject.md) (2 shared connections)
- [Orchestration: Segmented Session](Orchestration-_Segmented_Session.md) (2 shared connections)
- [Multipart Checksum Answers](Multipart_Checksum_Answers.md) (2 shared connections)
- [Object Checksum and Tagging Tests](Object_Checksum_and_Tagging_Tests.md) (2 shared connections)
- [DeleteObjects Handling](DeleteObjects_Handling.md) (2 shared connections)

## Source Files

- `internal/orchestration/segmented.go`
- `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- `internal/proxy/handlers/object/copy_bench_test.go`
- `internal/proxy/handlers/object/helpers.go`
- `internal/proxy/handlers/object/metadata_coverage_test.go`
- `internal/proxy/request/parser_test.go`
- `pkg/encryption/dataencryption/segmented_gcm_io.go`
- `pkg/encryption/dataencryption/segmented_gcm_range.go`
- `test/integration/s3-methods/encryption_at_rest_test.go`
- `test/integration/s3enc/helpers_test.go`

## Audit Trail

- EXTRACTED: 96 (91%)
- INFERRED: 10 (9%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*