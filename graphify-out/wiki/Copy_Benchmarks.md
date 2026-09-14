# Copy Benchmarks

> 23 nodes · cohesion 0.13

## Key Concepts

- **io.Reader** (26 connections)
- **io.Writer** (7 connections)
- **copy_bench_test.go** (6 connections) — `internal/proxy/handlers/object/copy_bench_test.go`
- **benchGetResponse()** (6 connections) — `internal/proxy/handlers/object/copy_bench_test.go`
- **Codec** (6 connections) — `pkg/encryption/dataencryption/segmented_gcm_io.go`
- **.NewPartEncryptReader()** (5 connections) — `pkg/encryption/dataencryption/segmented_gcm_io.go`
- **.NewPartWriter()** (5 connections) — `pkg/encryption/dataencryption/segmented_gcm_io.go`
- **.NewWriter()** (5 connections) — `pkg/encryption/dataencryption/segmented_gcm_io.go`
- **.NewEncryptReader()** (4 connections) — `pkg/encryption/dataencryption/segmented_gcm_io.go`
- **BenchmarkGetResponseCopy()** (4 connections) — `internal/proxy/handlers/object/copy_bench_test.go`
- **copyWithSize()** (4 connections) — `internal/proxy/handlers/object/copy_bench_test.go`
- **forwardingWriter** (4 connections) — `internal/proxy/handlers/object/copy_bench_test.go`
- **.NewReader()** (3 connections) — `pkg/encryption/dataencryption/segmented_gcm_io.go`
- **ObjGetcloseErrReader** (3 connections) — `internal/proxy/handlers/object/getobject_coverage_test.go`
- **EncUnseekable** (3 connections) — `test/integration/s3-methods/encryption_at_rest_test.go`
- **benchReader** (2 connections) — `internal/proxy/handlers/object/copy_bench_test.go`
- **.ReadFrom()** (2 connections) — `internal/proxy/handlers/object/copy_bench_test.go`
- **.Unwrap()** (2 connections) — `internal/proxy/handlers/object/copy_bench_test.go`
- **hidingWriter** (2 connections) — `internal/proxy/handlers/object/copy_bench_test.go`
- **writerOnly** (2 connections) — `internal/proxy/handlers/object/helpers.go`
- **.Read()** (1 connections) — `internal/proxy/handlers/object/copy_bench_test.go`
- **.Close()** (1 connections) — `internal/proxy/handlers/object/getobject_coverage_test.go`
- **.Read()** (1 connections) — `test/integration/s3-methods/encryption_at_rest_test.go`

## Relationships

- [Codec Streaming IO](Codec_Streaming_IO.md) (9 shared connections)
- [Segmented Object Entry Points](Segmented_Object_Entry_Points.md) (5 shared connections)
- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (5 shared connections)
- [Object Operations Handler](Object_Operations_Handler.md) (4 shared connections)
- [Request Parser Tests](Request_Parser_Tests.md) (3 shared connections)
- [Range Reader](Range_Reader.md) (2 shared connections)
- [Sealed Part Arithmetic](Sealed_Part_Arithmetic.md) (2 shared connections)
- [Performance Benchmarks](Performance_Benchmarks.md) (2 shared connections)
- [Chunked Upload Tests](Chunked_Upload_Tests.md) (1 shared connections)
- [Object Sub-Resource Refusals](Object_Sub-Resource_Refusals.md) (1 shared connections)
- [Object GET Handler Tests](Object_GET_Handler_Tests.md) (1 shared connections)
- [Encryption-at-Rest Integration Tests](Encryption-at-Rest_Integration_Tests.md) (1 shared connections)

## Source Files

- `internal/proxy/handlers/object/copy_bench_test.go`
- `internal/proxy/handlers/object/getobject_coverage_test.go`
- `internal/proxy/handlers/object/helpers.go`
- `pkg/encryption/dataencryption/segmented_gcm_io.go`
- `test/integration/s3-methods/encryption_at_rest_test.go`

## Audit Trail

- EXTRACTED: 70 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*