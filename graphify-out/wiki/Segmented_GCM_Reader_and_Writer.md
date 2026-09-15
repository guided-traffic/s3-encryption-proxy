# Segmented GCM Reader and Writer

> 37 nodes · cohesion 0.10

## Key Concepts

- **Writer** (13 connections) — `pkg/encryption/dataencryption/segmented_gcm_io.go`
- **EncryptReader** (12 connections) — `pkg/encryption/dataencryption/segmented_gcm_io.go`
- **reader** (10 connections) — `pkg/encryption/dataencryption/segmented_gcm_io.go`
- **io.Writer** (8 connections)
- **copy_bench_test.go** (6 connections) — `internal/proxy/handlers/object/copy_bench_test.go`
- **benchGetResponse()** (6 connections) — `internal/proxy/handlers/object/copy_bench_test.go`
- **Codec** (6 connections) — `pkg/encryption/dataencryption/segmented_gcm_io.go`
- **.NewPartEncryptReader()** (5 connections) — `pkg/encryption/dataencryption/segmented_gcm_io.go`
- **.NewPartWriter()** (5 connections) — `pkg/encryption/dataencryption/segmented_gcm_io.go`
- **.NewWriter()** (5 connections) — `pkg/encryption/dataencryption/segmented_gcm_io.go`
- **.fill()** (5 connections) — `pkg/encryption/dataencryption/segmented_gcm_io.go`
- **.flushSegment()** (5 connections) — `pkg/encryption/dataencryption/segmented_gcm_io.go`
- **.NewEncryptReader()** (4 connections) — `pkg/encryption/dataencryption/segmented_gcm_io.go`
- **.Checksum()** (4 connections) — `pkg/encryption/dataencryption/segmented_gcm_io.go`
- **sealSink** (4 connections) — `pkg/encryption/dataencryption/segmented_gcm_io.go`
- **.Write()** (4 connections) — `pkg/encryption/dataencryption/segmented_gcm_io.go`
- **.Close()** (4 connections) — `pkg/encryption/dataencryption/segmented_gcm_io.go`
- **.sealFrom()** (4 connections) — `pkg/encryption/dataencryption/segmented_gcm_io.go`
- **BenchmarkGetResponseCopy()** (4 connections) — `internal/proxy/handlers/object/copy_bench_test.go`
- **copyWithSize()** (4 connections) — `internal/proxy/handlers/object/copy_bench_test.go`
- **segmented_gcm_io.go** (4 connections) — `pkg/encryption/dataencryption/segmented_gcm_io.go`
- **.consumeTail()** (3 connections) — `pkg/encryption/dataencryption/segmented_gcm_io.go`
- **.fill()** (3 connections) — `pkg/encryption/dataencryption/segmented_gcm_io.go`
- **.openInto()** (3 connections) — `pkg/encryption/dataencryption/segmented_gcm_io.go`
- **.FinishPart()** (3 connections) — `pkg/encryption/dataencryption/segmented_gcm_io.go`
- *... and 12 more nodes in this community*

## Relationships

- [Segmented Manager Streaming IO](Segmented_Manager_Streaming_IO.md) (9 shared connections)
- [Segment Seal and Open Internals](Segment_Seal_and_Open_Internals.md) (4 shared connections)
- [Bucket Website and Create/Delete](Bucket_Website_and_Create-Delete.md) (3 shared connections)
- [Performance](Performance.md) (2 shared connections)
- [Keygen and KEK Factory](Keygen_and_KEK_Factory.md) (1 shared connections)
- [DeleteObjects Handler Tests](DeleteObjects_Handler_Tests.md) (1 shared connections)
- [Response Header Helpers](Response_Header_Helpers.md) (1 shared connections)

## Source Files

- `internal/proxy/handlers/object/copy_bench_test.go`
- `pkg/encryption/dataencryption/segmented_gcm_io.go`

## Audit Trail

- EXTRACTED: 88 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*