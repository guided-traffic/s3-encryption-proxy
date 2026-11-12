# Keygen and Encrypt Readers

> 28 nodes · cohesion 0.10

## Key Concepts

- **Writer** (13 connections) — `pkg/encryption/dataencryption/segmented_gcm_io.go`
- **EncryptReader** (12 connections) — `pkg/encryption/dataencryption/segmented_gcm_io.go`
- **io.Writer** (8 connections)
- **Codec** (6 connections) — `pkg/encryption/dataencryption/segmented_gcm_io.go`
- **printKey()** (5 connections) — `cmd/keygen/main.go`
- **.flushSegment()** (5 connections) — `pkg/encryption/dataencryption/segmented_gcm_io.go`
- **TestKeygenOutput()** (4 connections) — `cmd/keygen/main_test.go`
- **.NewPartWriter()** (4 connections) — `pkg/encryption/dataencryption/segmented_gcm_io.go`
- **sealSink** (4 connections) — `pkg/encryption/dataencryption/segmented_gcm_io.go`
- **copyWithSize()** (4 connections) — `internal/proxy/handlers/object/copy_bench_test.go`
- **TestKeygenDrawsAFreshKeyEachTime()** (3 connections) — `cmd/keygen/main_test.go`
- **.NewEncryptReader()** (3 connections) — `pkg/encryption/dataencryption/segmented_gcm_io.go`
- **.NewPartEncryptReader()** (3 connections) — `pkg/encryption/dataencryption/segmented_gcm_io.go`
- **.NewWriter()** (3 connections) — `pkg/encryption/dataencryption/segmented_gcm_io.go`
- **.Checksum()** (3 connections) — `pkg/encryption/dataencryption/segmented_gcm_io.go`
- **.Close()** (3 connections) — `pkg/encryption/dataencryption/segmented_gcm_io.go`
- **.FinishPart()** (3 connections) — `pkg/encryption/dataencryption/segmented_gcm_io.go`
- **.sealFrom()** (3 connections) — `pkg/encryption/dataencryption/segmented_gcm_io.go`
- **.Write()** (3 connections) — `pkg/encryption/dataencryption/segmented_gcm_io.go`
- **main()** (2 connections) — `cmd/keygen/main.go`
- **.fill()** (2 connections) — `pkg/encryption/dataencryption/segmented_gcm_io.go`
- **.Read()** (2 connections) — `pkg/encryption/dataencryption/segmented_gcm_io.go`
- **writerOnly** (2 connections) — `internal/proxy/handlers/object/helpers.go`
- **.Close()** (1 connections) — `pkg/encryption/dataencryption/segmented_gcm_io.go`
- **.reset()** (1 connections) — `pkg/encryption/dataencryption/segmented_gcm_io.go`
- *... and 3 more nodes in this community*

## Relationships

- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (9 shared connections)
- [Dataencryption: Segmented Gcm Range](Dataencryption-_Segmented_Gcm_Range.md) (7 shared connections)
- [Segment Seal and Trailer](Segment_Seal_and_Trailer.md) (4 shared connections)
- [Shutdown and Test Contexts](Shutdown_and_Test_Contexts.md) (2 shared connections)
- [Client Library and Storage Format](Client_Library_and_Storage_Format.md) (2 shared connections)
- [S3 Methods: Sealed Checksum Test](S3_Methods-_Sealed_Checksum_Test.md) (2 shared connections)
- [Factory: Factory](Factory-_Factory.md) (1 shared connections)

## Source Files

- `cmd/keygen/main.go`
- `cmd/keygen/main_test.go`
- `internal/proxy/handlers/object/copy_bench_test.go`
- `internal/proxy/handlers/object/helpers.go`
- `pkg/encryption/dataencryption/segmented_gcm_io.go`

## Audit Trail

- EXTRACTED: 57 (86%)
- INFERRED: 9 (14%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*