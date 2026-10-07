# Segment Seal and Open Internals

> 25 nodes · cohesion 0.13

## Key Concepts

- **Checksum** (26 connections) — `pkg/encryption/dataencryption/segmented_gcm.go`
- **segmented_gcm.go** (13 connections) — `pkg/encryption/dataencryption/segmented_gcm.go`
- **Codec** (13 connections) — `pkg/encryption/dataencryption/segmented_gcm.go`
- **objectTail** (5 connections) — `internal/proxy/handlers/object/tail.go`
- **Codec** (5 connections) — `pkg/encryption/dataencryption/export_test.go`
- **.openTrailer()** (4 connections) — `pkg/encryption/dataencryption/segmented_gcm.go`
- **.sealTrailer()** (4 connections) — `pkg/encryption/dataencryption/segmented_gcm.go`
- **crc32Combine()** (4 connections) — `pkg/encryption/dataencryption/segmented_gcm.go`
- **.aad()** (3 connections) — `pkg/encryption/dataencryption/segmented_gcm.go`
- **.openSegment()** (3 connections) — `pkg/encryption/dataencryption/segmented_gcm.go`
- **.OpenTrailer()** (3 connections) — `pkg/encryption/dataencryption/segmented_gcm.go`
- **.sealSegment()** (3 connections) — `pkg/encryption/dataencryption/segmented_gcm.go`
- **.SealTrailer()** (3 connections) — `pkg/encryption/dataencryption/segmented_gcm.go`
- **Handlers that reach past orchestration into the format package** (3 connections) — `docs/developer/package-map.md`
- **gf2MatrixSquare()** (3 connections) — `pkg/encryption/dataencryption/segmented_gcm.go`
- **gf2MatrixTimes()** (3 connections) — `pkg/encryption/dataencryption/segmented_gcm.go`
- **.Append()** (2 connections) — `pkg/encryption/dataencryption/segmented_gcm.go`
- **.OpenTrailerForTest()** (2 connections) — `pkg/encryption/dataencryption/export_test.go`
- **.SealTrailerForTest()** (2 connections) — `pkg/encryption/dataencryption/export_test.go`
- **.PartChecksum()** (2 connections) — `internal/orchestration/segmented_session.go`
- **.Base64()** (1 connections) — `pkg/encryption/dataencryption/segmented_gcm.go`
- **.AADForTest()** (1 connections) — `pkg/encryption/dataencryption/export_test.go`
- **.OpenSegmentForTest()** (1 connections) — `pkg/encryption/dataencryption/export_test.go`
- **.SealSegmentForTest()** (1 connections) — `pkg/encryption/dataencryption/export_test.go`
- **.coversWholeObject()** (1 connections) — `internal/proxy/handlers/object/tail.go`

## Relationships

- [Segmented Manager Streaming IO](Segmented_Manager_Streaming_IO.md) (9 shared connections)
- [Segmented Session Lifecycle](Segmented_Session_Lifecycle.md) (4 shared connections)
- [Segment Encrypt Reader Tests](Segment_Encrypt_Reader_Tests.md) (4 shared connections)
- [Segmented GCM Reader and Writer](Segmented_GCM_Reader_and_Writer.md) (4 shared connections)
- [Object Response Header Helpers](Object_Response_Header_Helpers.md) (3 shared connections)
- [Storage Format Integrity Guarantees](Storage_Format_Integrity_Guarantees.md) (3 shared connections)
- [Segmented GCM](Segmented_GCM.md) (2 shared connections)
- [MockS3Backend Multipart Operations](MockS3Backend_Multipart_Operations.md) (1 shared connections)
- [Segmented GCM Range Reader](Segmented_GCM_Range_Reader.md) (1 shared connections)
- [Hostile Backend and Key Material ADRs](Hostile_Backend_and_Key_Material_ADRs.md) (1 shared connections)
- [Cryptofloor](Cryptofloor.md) (1 shared connections)

## Source Files

- `docs/developer/package-map.md`
- `internal/orchestration/segmented_session.go`
- `internal/proxy/handlers/object/tail.go`
- `pkg/encryption/dataencryption/export_test.go`
- `pkg/encryption/dataencryption/segmented_gcm.go`

## Audit Trail

- EXTRACTED: 72 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*