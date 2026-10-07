# Segmented GCM Reader and Writer

> 30 nodes · cohesion 0.13

## Key Concepts

- **Writer** (13 connections) — `pkg/encryption/dataencryption/segmented_gcm_io.go`
- **EncryptReader** (12 connections) — `pkg/encryption/dataencryption/segmented_gcm_io.go`
- **reader** (10 connections) — `pkg/encryption/dataencryption/segmented_gcm_io.go`
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
- **segmented_gcm_io.go** (4 connections) — `pkg/encryption/dataencryption/segmented_gcm_io.go`
- **.consumeTail()** (3 connections) — `pkg/encryption/dataencryption/segmented_gcm_io.go`
- **.fill()** (3 connections) — `pkg/encryption/dataencryption/segmented_gcm_io.go`
- **.openInto()** (3 connections) — `pkg/encryption/dataencryption/segmented_gcm_io.go`
- **.FinishPart()** (3 connections) — `pkg/encryption/dataencryption/segmented_gcm_io.go`
- **.Write()** (3 connections) — `pkg/encryption/dataencryption/segmented_gcm_io.go`
- **.Read()** (2 connections) — `pkg/encryption/dataencryption/segmented_gcm_io.go`
- **.Checksum()** (2 connections) — `pkg/encryption/dataencryption/segmented_gcm_io.go`
- **.Read()** (2 connections) — `pkg/encryption/dataencryption/segmented_gcm_io.go`
- **.reset()** (2 connections) — `pkg/encryption/dataencryption/segmented_gcm_io.go`
- *... and 5 more nodes in this community*

## Relationships

- [Segmented Manager Streaming IO](Segmented_Manager_Streaming_IO.md) (7 shared connections)
- [Segment Seal and Open Internals](Segment_Seal_and_Open_Internals.md) (4 shared connections)
- [GET Copy Benchmarks](GET_Copy_Benchmarks.md) (3 shared connections)

## Source Files

- `pkg/encryption/dataencryption/segmented_gcm_io.go`

## Audit Trail

- EXTRACTED: 69 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*