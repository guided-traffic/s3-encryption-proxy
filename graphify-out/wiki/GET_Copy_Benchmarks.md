# GET Copy Benchmarks

> 9 nodes · cohesion 0.31

## Key Concepts

- **io.Writer** (8 connections)
- **copy_bench_test.go** (6 connections) — `internal/proxy/handlers/object/copy_bench_test.go`
- **benchGetResponse()** (6 connections) — `internal/proxy/handlers/object/copy_bench_test.go`
- **BenchmarkGetResponseCopy()** (4 connections) — `internal/proxy/handlers/object/copy_bench_test.go`
- **copyWithSize()** (4 connections) — `internal/proxy/handlers/object/copy_bench_test.go`
- **benchReader** (2 connections) — `internal/proxy/handlers/object/copy_bench_test.go`
- **hidingWriter** (2 connections) — `internal/proxy/handlers/object/copy_bench_test.go`
- **writerOnly** (2 connections) — `internal/proxy/handlers/object/helpers.go`
- **.Read()** (1 connections) — `internal/proxy/handlers/object/copy_bench_test.go`

## Relationships

- [Segmented GCM Reader and Writer](Segmented_GCM_Reader_and_Writer.md) (3 shared connections)
- [Bucket ACL and Accelerate Handlers](Bucket_ACL_and_Accelerate_Handlers.md) (3 shared connections)
- [Segmented Manager Streaming IO](Segmented_Manager_Streaming_IO.md) (2 shared connections)
- [Performance](Performance.md) (2 shared connections)
- [Keygen Command](Keygen_Command.md) (1 shared connections)
- [Object Metadata Coverage Tests](Object_Metadata_Coverage_Tests.md) (1 shared connections)
- [Object Response Header Helpers](Object_Response_Header_Helpers.md) (1 shared connections)

## Source Files

- `internal/proxy/handlers/object/copy_bench_test.go`
- `internal/proxy/handlers/object/helpers.go`

## Audit Trail

- EXTRACTED: 24 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*