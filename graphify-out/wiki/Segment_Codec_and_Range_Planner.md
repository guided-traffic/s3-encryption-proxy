# Segment Codec and Range Planner

> 55 nodes · cohesion 0.07

## Key Concepts

- **segmented_gcm_test.go** (65 connections) — `pkg/encryption/dataencryption/segmented_gcm_test.go`
- **testCodec()** (31 connections) — `pkg/encryption/dataencryption/segmented_gcm_test.go`
- **seal()** (21 connections) — `pkg/encryption/dataencryption/segmented_gcm_test.go`
- **PlanRange()** (15 connections) — `pkg/encryption/dataencryption/segmented_gcm_range.go`
- **NewCodec()** (13 connections) — `pkg/encryption/dataencryption/segmented_gcm.go`
- **NewChecksum()** (10 connections) — `pkg/encryption/dataencryption/segmented_gcm.go`
- **vecCodec()** (8 connections) — `pkg/encryption/dataencryption/segmented_gcm_vector_test.go`
- **TestSegForgedTrailerChecksumFails()** (7 connections) — `pkg/encryption/dataencryption/segmented_gcm_test.go`
- **TestSegRangeExhaustive()** (6 connections) — `pkg/encryption/dataencryption/segmented_gcm_range_test.go`
- **TestSegNoncesAreUnique()** (6 connections) — `pkg/encryption/dataencryption/segmented_gcm_test.go`
- **vecBytes()** (6 connections) — `pkg/encryption/dataencryption/segmented_gcm_vector_test.go`
- **TestSegRangeSegmentFromAnotherOffsetFails()** (5 connections) — `pkg/encryption/dataencryption/segmented_gcm_range_test.go`
- **TestSegRangeShortWindowFails()** (5 connections) — `pkg/encryption/dataencryption/segmented_gcm_range_test.go`
- **TestSegRangeTailVerifiesTheAuthenticatedLength()** (5 connections) — `pkg/encryption/dataencryption/segmented_gcm_range_test.go`
- **TestSegRangeTamperedSegmentFails()** (5 connections) — `pkg/encryption/dataencryption/segmented_gcm_range_test.go`
- **TestSegForgedTrailerLengthFails()** (5 connections) — `pkg/encryption/dataencryption/segmented_gcm_test.go`
- **TestSegRoundTrip()** (5 connections) — `pkg/encryption/dataencryption/segmented_gcm_test.go`
- **TestSegVectorObjectIsBoundToItsKey()** (5 connections) — `pkg/encryption/dataencryption/segmented_gcm_vector_test.go`
- **TestSegVectorWholeObjectReadsBack()** (5 connections) — `pkg/encryption/dataencryption/segmented_gcm_vector_test.go`
- **TestSegEncryptReaderMatchesWriter()** (4 connections) — `pkg/encryption/dataencryption/segmented_gcm_encrypt_reader_test.go`
- **segmentCount()** (4 connections) — `pkg/encryption/dataencryption/segmented_gcm.go`
- **TestSegChecksumMatchesTrailer()** (4 connections) — `pkg/encryption/dataencryption/segmented_gcm_test.go`
- **TestSegExtendedFails()** (4 connections) — `pkg/encryption/dataencryption/segmented_gcm_test.go`
- **TestSegFlippedBitFails()** (4 connections) — `pkg/encryption/dataencryption/segmented_gcm_test.go`
- **TestSegIdenticalSegmentsCannotBeReordered()** (4 connections) — `pkg/encryption/dataencryption/segmented_gcm_test.go`
- *... and 30 more nodes in this community*

## Relationships

- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (62 shared connections)
- [Shutdown and Test Contexts](Shutdown_and_Test_Contexts.md) (42 shared connections)
- [Client Library and Storage Format](Client_Library_and_Storage_Format.md) (6 shared connections)
- [GET Response Writing](GET_Response_Writing.md) (6 shared connections)
- [Storedobject: Storedobject](Storedobject-_Storedobject.md) (4 shared connections)
- [Dataencryption: Segmented Gcm Range](Dataencryption-_Segmented_Gcm_Range.md) (3 shared connections)
- [Segment Seal and Trailer](Segment_Seal_and_Trailer.md) (3 shared connections)
- [Orchestration: Segmented Session](Orchestration-_Segmented_Session.md) (2 shared connections)
- [Object Checksum and Tagging Tests](Object_Checksum_and_Tagging_Tests.md) (2 shared connections)
- [ADR Corpus and Release History](ADR_Corpus_and_Release_History.md) (2 shared connections)
- [Segmented Session Tests](Segmented_Session_Tests.md) (1 shared connections)
- [Orchestration: Providers Coverage Test (2)](Orchestration-_Providers_Coverage_Test_2.md) (1 shared connections)

## Source Files

- `docs/developer/storage-format.md`
- `pkg/encryption/dataencryption/segmented_gcm.go`
- `pkg/encryption/dataencryption/segmented_gcm_encrypt_reader_test.go`
- `pkg/encryption/dataencryption/segmented_gcm_range.go`
- `pkg/encryption/dataencryption/segmented_gcm_range_test.go`
- `pkg/encryption/dataencryption/segmented_gcm_test.go`
- `pkg/encryption/dataencryption/segmented_gcm_vector_test.go`

## Audit Trail

- EXTRACTED: 199 (83%)
- INFERRED: 41 (17%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*