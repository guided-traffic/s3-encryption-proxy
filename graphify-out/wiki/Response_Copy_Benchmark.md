# Response Copy Benchmark

> 9 nodes · cohesion 0.31

## Key Concepts

- **copy_bench_test.go** (6 connections) — `internal/proxy/handlers/object/copy_bench_test.go`
- **benchGetResponse()** (6 connections) — `internal/proxy/handlers/object/copy_bench_test.go`
- **io.Writer** (4 connections)
- **BenchmarkGetResponseCopy()** (4 connections) — `internal/proxy/handlers/object/copy_bench_test.go`
- **copyWithSize()** (4 connections) — `internal/proxy/handlers/object/copy_bench_test.go`
- **benchReader** (2 connections) — `internal/proxy/handlers/object/copy_bench_test.go`
- **hidingWriter** (2 connections) — `internal/proxy/handlers/object/copy_bench_test.go`
- **writerOnly** (2 connections) — `internal/proxy/handlers/object/helpers.go`
- **.Read()** (1 connections) — `internal/proxy/handlers/object/copy_bench_test.go`

## Relationships

- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (4 shared connections)
- [Manager Envelope Encryption](Manager_Envelope_Encryption.md) (2 shared connections)
- [Throughput Benchmark Suite](Throughput_Benchmark_Suite.md) (2 shared connections)
- [DeleteObjects Handler Tests](DeleteObjects_Handler_Tests.md) (1 shared connections)

## Source Files

- `internal/proxy/handlers/object/copy_bench_test.go`
- `internal/proxy/handlers/object/helpers.go`

## Audit Trail

- EXTRACTED: 20 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*