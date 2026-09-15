# Segment Seal and Open Internals

> 20 nodes · cohesion 0.16

## Key Concepts

- **Checksum** (26 connections) — `pkg/encryption/dataencryption/segmented_gcm.go`
- **Codec** (13 connections) — `pkg/encryption/dataencryption/segmented_gcm.go`
- **Codec** (5 connections) — `pkg/encryption/dataencryption/export_test.go`
- **.openTrailer()** (4 connections) — `pkg/encryption/dataencryption/segmented_gcm.go`
- **.sealTrailer()** (4 connections) — `pkg/encryption/dataencryption/segmented_gcm.go`
- **.aad()** (3 connections) — `pkg/encryption/dataencryption/segmented_gcm.go`
- **.openSegment()** (3 connections) — `pkg/encryption/dataencryption/segmented_gcm.go`
- **.OpenTrailer()** (3 connections) — `pkg/encryption/dataencryption/segmented_gcm.go`
- **.sealSegment()** (3 connections) — `pkg/encryption/dataencryption/segmented_gcm.go`
- **.SealTrailer()** (3 connections) — `pkg/encryption/dataencryption/segmented_gcm.go`
- **.Checksum()** (3 connections) — `internal/orchestration/segmented.go`
- **.Checksum()** (3 connections) — `internal/orchestration/segmented.go`
- **.OpenTrailerForTest()** (2 connections) — `pkg/encryption/dataencryption/export_test.go`
- **.SealTrailerForTest()** (2 connections) — `pkg/encryption/dataencryption/export_test.go`
- **.Checksum()** (2 connections) — `pkg/encryption/dataencryption/segmented_gcm_io.go`
- **.PartChecksum()** (2 connections) — `internal/orchestration/segmented_session.go`
- **.Base64()** (1 connections) — `pkg/encryption/dataencryption/segmented_gcm.go`
- **.AADForTest()** (1 connections) — `pkg/encryption/dataencryption/export_test.go`
- **.OpenSegmentForTest()** (1 connections) — `pkg/encryption/dataencryption/export_test.go`
- **.SealSegmentForTest()** (1 connections) — `pkg/encryption/dataencryption/export_test.go`

## Relationships

- [Segmented Manager Streaming IO](Segmented_Manager_Streaming_IO.md) (9 shared connections)
- [Segmented GCM Reader and Writer](Segmented_GCM_Reader_and_Writer.md) (4 shared connections)
- [Segmented Session Lifecycle](Segmented_Session_Lifecycle.md) (4 shared connections)
- [Segmented GCM](Segmented_GCM.md) (3 shared connections)
- [Response Header Helpers](Response_Header_Helpers.md) (2 shared connections)
- [Segment Encrypt Reader Tests](Segment_Encrypt_Reader_Tests.md) (1 shared connections)
- [Cryptofloor](Cryptofloor.md) (1 shared connections)
- [Segmented GCM Vector](Segmented_GCM_Vector.md) (1 shared connections)

## Source Files

- `internal/orchestration/segmented.go`
- `internal/orchestration/segmented_session.go`
- `pkg/encryption/dataencryption/export_test.go`
- `pkg/encryption/dataencryption/segmented_gcm.go`
- `pkg/encryption/dataencryption/segmented_gcm_io.go`

## Audit Trail

- EXTRACTED: 55 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*