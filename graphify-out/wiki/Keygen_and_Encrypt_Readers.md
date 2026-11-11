# Keygen and Encrypt Readers

> 44 nodes · cohesion 0.06

## Key Concepts

- **io.Reader** (45 connections)
- **EncryptReader** (12 connections) — `pkg/encryption/dataencryption/segmented_gcm_io.go`
- **Object** (10 connections) — `pkg/s3enc/read.go`
- **io.ReadCloser** (9 connections)
- **io.Writer** (8 connections)
- **Codec** (6 connections) — `pkg/encryption/dataencryption/segmented_gcm_io.go`
- **printKey()** (5 connections) — `cmd/keygen/main.go`
- **.TouchWhileReading()** (5 connections) — `internal/orchestration/segmented_session.go`
- **SegmentedWrite** (5 connections) — `internal/orchestration/segmented.go`
- **TestKeygenOutput()** (4 connections) — `cmd/keygen/main_test.go`
- **.NewPartWriter()** (4 connections) — `pkg/encryption/dataencryption/segmented_gcm_io.go`
- **.NewRangeReader()** (4 connections) — `pkg/encryption/dataencryption/segmented_gcm_range.go`
- **sealSink** (4 connections) — `pkg/encryption/dataencryption/segmented_gcm_io.go`
- **copyWithSize()** (4 connections) — `internal/proxy/handlers/object/copy_bench_test.go`
- **TestKeygenDrawsAFreshKeyEachTime()** (3 connections) — `cmd/keygen/main_test.go`
- **.NewEncryptReader()** (3 connections) — `pkg/encryption/dataencryption/segmented_gcm_io.go`
- **.NewPartEncryptReader()** (3 connections) — `pkg/encryption/dataencryption/segmented_gcm_io.go`
- **.NewReader()** (3 connections) — `pkg/encryption/dataencryption/segmented_gcm_io.go`
- **.NewWriter()** (3 connections) — `pkg/encryption/dataencryption/segmented_gcm_io.go`
- **countingBody** (3 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **ObjGetclosedBody** (3 connections) — `internal/proxy/handlers/object/getobject_coverage_test.go`
- **ObjGetcloseErrReader** (3 connections) — `internal/proxy/handlers/object/getobject_coverage_test.go`
- **.NewSegmentedWrite()** (3 connections) — `internal/orchestration/segmented.go`
- **.OpenSegmentedRange()** (3 connections) — `internal/orchestration/segmented.go`
- **countingReader** (3 connections) — `internal/proxy/request/parser_test.go`
- *... and 19 more nodes in this community*

## Relationships

- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (12 shared connections)
- [Segment Seal and Trailer](Segment_Seal_and_Trailer.md) (7 shared connections)
- [Request Documents and Owner Guard](Request_Documents_and_Owner_Guard.md) (6 shared connections)
- [Shutdown and Test Contexts](Shutdown_and_Test_Contexts.md) (4 shared connections)
- [Dataencryption: Segmented Gcm Io](Dataencryption-_Segmented_Gcm_Io.md) (4 shared connections)
- [Segment Codec and Range Planner](Segment_Codec_and_Range_Planner.md) (3 shared connections)
- [Orchestration: Segmented Session](Orchestration-_Segmented_Session.md) (3 shared connections)
- [S3 Methods: Sealed Checksum Test](S3_Methods-_Sealed_Checksum_Test.md) (3 shared connections)
- [Multipart Checksum Answers](Multipart_Checksum_Answers.md) (3 shared connections)
- [Dataencryption: Segmented Gcm Io (2)](Dataencryption-_Segmented_Gcm_Io_2.md) (2 shared connections)
- [Object: Metadata Coverage Test](Object-_Metadata_Coverage_Test.md) (2 shared connections)
- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (2 shared connections)

## Source Files

- `cmd/keygen/main.go`
- `cmd/keygen/main_test.go`
- `internal/orchestration/segmented.go`
- `internal/orchestration/segmented_session.go`
- `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- `internal/proxy/handlers/object/copy_bench_test.go`
- `internal/proxy/handlers/object/getobject_coverage_test.go`
- `internal/proxy/handlers/object/helpers.go`
- `internal/proxy/request/parser_test.go`
- `pkg/encryption/dataencryption/segmented_gcm_io.go`
- `pkg/encryption/dataencryption/segmented_gcm_range.go`
- `pkg/s3enc/read.go`
- `test/integration/s3-methods/encryption_at_rest_test.go`
- `test/integration/s3enc/helpers_test.go`

## Audit Trail

- EXTRACTED: 123 (95%)
- INFERRED: 6 (5%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*