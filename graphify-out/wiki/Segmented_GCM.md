# Segmented GCM

> 17 nodes · cohesion 0.18

## Key Concepts

- **CiphertextSize()** (21 connections) — `pkg/encryption/dataencryption/segmented_gcm.go`
- **segmented_gcm.go** (10 connections) — `pkg/encryption/dataencryption/segmented_gcm.go`
- **PlaintextSize()** (8 connections) — `pkg/encryption/dataencryption/segmented_gcm.go`
- **Invariant 2: The Stored Length Is a Pure Function of the Plaintext Length** (7 connections) — `docs/developer/storage-format.md`
- **SegmentSize** (6 connections) — `docs/developer/storage-format.md`
- **crc32Combine()** (4 connections) — `pkg/encryption/dataencryption/segmented_gcm.go`
- **segmentCount()** (4 connections) — `pkg/encryption/dataencryption/segmented_gcm.go`
- **TestSegOversizeRefused()** (4 connections) — `pkg/encryption/dataencryption/segmented_gcm_test.go`
- **TestSegSizeFunctionsRoundTrip()** (4 connections) — `pkg/encryption/dataencryption/segmented_gcm_test.go`
- **TestSegSizeGuardRejectsUnreachableLengths()** (4 connections) — `pkg/encryption/dataencryption/segmented_gcm_test.go`
- **.next()** (3 connections) — `pkg/encryption/dataencryption/segmented_gcm_range.go`
- **gf2MatrixSquare()** (3 connections) — `pkg/encryption/dataencryption/segmented_gcm.go`
- **gf2MatrixTimes()** (3 connections) — `pkg/encryption/dataencryption/segmented_gcm.go`
- **.Append()** (2 connections) — `pkg/encryption/dataencryption/segmented_gcm.go`
- **maxWindowOverAsk** (1 connections) — `docs/developer/storage-format.md`
- **SegmentOverhead** (1 connections) — `docs/developer/storage-format.md`
- **TrailerSize** (1 connections) — `docs/developer/storage-format.md`

## Relationships

- [Segment Encrypt Reader Tests](Segment_Encrypt_Reader_Tests.md) (6 shared connections)
- [Segment Seal and Open Internals](Segment_Seal_and_Open_Internals.md) (3 shared connections)
- [Segmented GCM Range Reader](Segmented_GCM_Range_Reader.md) (3 shared connections)
- [Multipart Semantics and ETag Marker](Multipart_Semantics_and_ETag_Marker.md) (3 shared connections)
- [Segmented Manager Streaming IO](Segmented_Manager_Streaming_IO.md) (3 shared connections)
- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (3 shared connections)
- [Segmented GCM Vector](Segmented_GCM_Vector.md) (2 shared connections)
- [Segmented Session Tests](Segmented_Session_Tests.md) (2 shared connections)
- [Object GET Coverage Tests](Object_GET_Coverage_Tests.md) (2 shared connections)
- [Configuration Loading and Upload Sweeper](Configuration_Loading_and_Upload_Sweeper.md) (1 shared connections)
- [Bucket Handler Error Fixtures](Bucket_Handler_Error_Fixtures.md) (1 shared connections)
- [Multipart Handler Coverage Tests](Multipart_Handler_Coverage_Tests.md) (1 shared connections)

## Source Files

- `docs/developer/storage-format.md`
- `pkg/encryption/dataencryption/segmented_gcm.go`
- `pkg/encryption/dataencryption/segmented_gcm_range.go`
- `pkg/encryption/dataencryption/segmented_gcm_test.go`

## Audit Trail

- EXTRACTED: 50 (81%)
- INFERRED: 12 (19%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*