# Codec Streaming IO

> 23 nodes · cohesion 0.15

## Key Concepts

- **Writer** (12 connections) — `pkg/encryption/dataencryption/segmented_gcm_io.go`
- **EncryptReader** (11 connections) — `pkg/encryption/dataencryption/segmented_gcm_io.go`
- **reader** (10 connections) — `pkg/encryption/dataencryption/segmented_gcm_io.go`
- **.fill()** (5 connections) — `pkg/encryption/dataencryption/segmented_gcm_io.go`
- **.flushSegment()** (5 connections) — `pkg/encryption/dataencryption/segmented_gcm_io.go`
- **sealSink** (4 connections) — `pkg/encryption/dataencryption/segmented_gcm_io.go`
- **.Write()** (4 connections) — `pkg/encryption/dataencryption/segmented_gcm_io.go`
- **.Close()** (4 connections) — `pkg/encryption/dataencryption/segmented_gcm_io.go`
- **.sealFrom()** (4 connections) — `pkg/encryption/dataencryption/segmented_gcm_io.go`
- **segmented_gcm_io.go** (4 connections) — `pkg/encryption/dataencryption/segmented_gcm_io.go`
- **.Checksum()** (3 connections) — `pkg/encryption/dataencryption/segmented_gcm_io.go`
- **.consumeTail()** (3 connections) — `pkg/encryption/dataencryption/segmented_gcm_io.go`
- **.fill()** (3 connections) — `pkg/encryption/dataencryption/segmented_gcm_io.go`
- **.openInto()** (3 connections) — `pkg/encryption/dataencryption/segmented_gcm_io.go`
- **.FinishPart()** (3 connections) — `pkg/encryption/dataencryption/segmented_gcm_io.go`
- **.Write()** (3 connections) — `pkg/encryption/dataencryption/segmented_gcm_io.go`
- **.Read()** (2 connections) — `pkg/encryption/dataencryption/segmented_gcm_io.go`
- **.Checksum()** (2 connections) — `pkg/encryption/dataencryption/segmented_gcm_io.go`
- **.Read()** (2 connections) — `pkg/encryption/dataencryption/segmented_gcm_io.go`
- **.reset()** (2 connections) — `pkg/encryption/dataencryption/segmented_gcm_io.go`
- **.Close()** (1 connections) — `pkg/encryption/dataencryption/segmented_gcm_io.go`
- **.Close()** (1 connections) — `pkg/encryption/dataencryption/segmented_gcm_io.go`
- **Codec** (1 connections)

## Relationships

- [Copy Benchmarks](Copy_Benchmarks.md) (9 shared connections)
- [Segment Codec Core](Segment_Codec_Core.md) (4 shared connections)
- [Segmented Object Entry Points](Segmented_Object_Entry_Points.md) (1 shared connections)

## Source Files

- `pkg/encryption/dataencryption/segmented_gcm_io.go`

## Audit Trail

- EXTRACTED: 53 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*