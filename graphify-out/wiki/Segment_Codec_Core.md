# Segment Codec Core

> 21 nodes · cohesion 0.17

## Key Concepts

- **Checksum** (17 connections) — `pkg/encryption/dataencryption/segmented_gcm.go`
- **Codec** (13 connections) — `pkg/encryption/dataencryption/segmented_gcm.go`
- **segmented_gcm.go** (10 connections) — `pkg/encryption/dataencryption/segmented_gcm.go`
- **Codec** (5 connections) — `pkg/encryption/dataencryption/export_test.go`
- **.openTrailer()** (4 connections) — `pkg/encryption/dataencryption/segmented_gcm.go`
- **.sealTrailer()** (4 connections) — `pkg/encryption/dataencryption/segmented_gcm.go`
- **crc32Combine()** (4 connections) — `pkg/encryption/dataencryption/segmented_gcm.go`
- **.aad()** (3 connections) — `pkg/encryption/dataencryption/segmented_gcm.go`
- **.openSegment()** (3 connections) — `pkg/encryption/dataencryption/segmented_gcm.go`
- **.OpenTrailer()** (3 connections) — `pkg/encryption/dataencryption/segmented_gcm.go`
- **.sealSegment()** (3 connections) — `pkg/encryption/dataencryption/segmented_gcm.go`
- **.SealTrailer()** (3 connections) — `pkg/encryption/dataencryption/segmented_gcm.go`
- **gf2MatrixSquare()** (3 connections) — `pkg/encryption/dataencryption/segmented_gcm.go`
- **gf2MatrixTimes()** (3 connections) — `pkg/encryption/dataencryption/segmented_gcm.go`
- **.Append()** (2 connections) — `pkg/encryption/dataencryption/segmented_gcm.go`
- **.OpenTrailerForTest()** (2 connections) — `pkg/encryption/dataencryption/export_test.go`
- **.SealTrailerForTest()** (2 connections) — `pkg/encryption/dataencryption/export_test.go`
- **.Checksum()** (2 connections) — `pkg/encryption/dataencryption/segmented_gcm_io.go`
- **.AADForTest()** (1 connections) — `pkg/encryption/dataencryption/export_test.go`
- **.OpenSegmentForTest()** (1 connections) — `pkg/encryption/dataencryption/export_test.go`
- **.SealSegmentForTest()** (1 connections) — `pkg/encryption/dataencryption/export_test.go`

## Relationships

- [Segment Codec Tests](Segment_Codec_Tests.md) (6 shared connections)
- [Codec Streaming IO](Codec_Streaming_IO.md) (4 shared connections)
- [Sealed Part Arithmetic](Sealed_Part_Arithmetic.md) (4 shared connections)
- [Segmented Object Entry Points](Segmented_Object_Entry_Points.md) (2 shared connections)
- [Range Reader](Range_Reader.md) (1 shared connections)
- [Multipart Session Table](Multipart_Session_Table.md) (1 shared connections)
- [Performance Harness](Performance_Harness.md) (1 shared connections)

## Source Files

- `pkg/encryption/dataencryption/export_test.go`
- `pkg/encryption/dataencryption/segmented_gcm.go`
- `pkg/encryption/dataencryption/segmented_gcm_io.go`

## Audit Trail

- EXTRACTED: 54 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*