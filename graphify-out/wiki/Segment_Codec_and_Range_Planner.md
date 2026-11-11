# Segment Codec and Range Planner

> 70 nodes · cohesion 0.05

## Key Concepts

- **segmented_gcm_test.go** (66 connections) — `pkg/encryption/dataencryption/segmented_gcm_test.go`
- **testCodec()** (31 connections) — `pkg/encryption/dataencryption/segmented_gcm_test.go`
- **CiphertextSize()** (24 connections) — `pkg/encryption/dataencryption/segmented_gcm.go`
- **seal()** (21 connections) — `pkg/encryption/dataencryption/segmented_gcm_test.go`
- **PlanRange()** (15 connections) — `pkg/encryption/dataencryption/segmented_gcm_range.go`
- **NewCodec()** (14 connections) — `pkg/encryption/dataencryption/segmented_gcm.go`
- **NewChecksum()** (10 connections) — `pkg/encryption/dataencryption/segmented_gcm.go`
- **partCodec()** (10 connections) — `pkg/encryption/dataencryption/segmented_gcm_part_test.go`
- **vecCodec()** (8 connections) — `pkg/encryption/dataencryption/segmented_gcm_vector_test.go`
- **TestSegForgedTrailerChecksumFails()** (7 connections) — `pkg/encryption/dataencryption/segmented_gcm_test.go`
- **TestForeignObjectIsRefusedOnGetAndHead()** (6 connections) — `internal/proxy/handlers/object/object_test.go`
- **sealInParts()** (6 connections) — `pkg/encryption/dataencryption/segmented_gcm_part_test.go`
- **Window** (6 connections) — `pkg/encryption/dataencryption/segmented_gcm_range.go`
- **TestSegRangeExhaustive()** (6 connections) — `pkg/encryption/dataencryption/segmented_gcm_range_test.go`
- **TestSegNoncesAreUnique()** (6 connections) — `pkg/encryption/dataencryption/segmented_gcm_test.go`
- **vecBytes()** (6 connections) — `pkg/encryption/dataencryption/segmented_gcm_vector_test.go`
- **PlanRange()** (5 connections) — `internal/orchestration/segmented.go`
- **TestSegPartWriterRoundTrip()** (5 connections) — `pkg/encryption/dataencryption/segmented_gcm_part_test.go`
- **TestSegRangeSegmentFromAnotherOffsetFails()** (5 connections) — `pkg/encryption/dataencryption/segmented_gcm_range_test.go`
- **TestSegRangeShortWindowFails()** (5 connections) — `pkg/encryption/dataencryption/segmented_gcm_range_test.go`
- **TestSegRangeTailVerifiesTheAuthenticatedLength()** (5 connections) — `pkg/encryption/dataencryption/segmented_gcm_range_test.go`
- **TestSegRangeTamperedSegmentFails()** (5 connections) — `pkg/encryption/dataencryption/segmented_gcm_range_test.go`
- **TestSegForgedTrailerLengthFails()** (5 connections) — `pkg/encryption/dataencryption/segmented_gcm_test.go`
- **TestSegRoundTrip()** (5 connections) — `pkg/encryption/dataencryption/segmented_gcm_test.go`
- **TestSegVectorObjectIsBoundToItsKey()** (5 connections) — `pkg/encryption/dataencryption/segmented_gcm_vector_test.go`
- *... and 45 more nodes in this community*

## Relationships

- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (74 shared connections)
- [Shutdown and Test Contexts](Shutdown_and_Test_Contexts.md) (53 shared connections)
- [Client Library and Storage Format](Client_Library_and_Storage_Format.md) (8 shared connections)
- [Segmented Session Tests](Segmented_Session_Tests.md) (6 shared connections)
- [S3 API Behaviour](S3_API_Behaviour.md) (6 shared connections)
- [Segment Seal and Trailer](Segment_Seal_and_Trailer.md) (4 shared connections)
- [Storedobject: Storedobject](Storedobject-_Storedobject.md) (4 shared connections)
- [GET Response Writing](GET_Response_Writing.md) (3 shared connections)
- [Object Checksum and Tagging Tests](Object_Checksum_and_Tagging_Tests.md) (3 shared connections)
- [Keygen and Encrypt Readers](Keygen_and_Encrypt_Readers.md) (3 shared connections)
- [Dataencryption: Segmented Gcm Range](Dataencryption-_Segmented_Gcm_Range.md) (2 shared connections)
- [Multipart Checksum Answers](Multipart_Checksum_Answers.md) (2 shared connections)

## Source Files

- `docs/developer/storage-format.md`
- `internal/orchestration/segmented.go`
- `internal/proxy/handlers/object/object_test.go`
- `pkg/encryption/dataencryption/segmented_gcm.go`
- `pkg/encryption/dataencryption/segmented_gcm_encrypt_reader_test.go`
- `pkg/encryption/dataencryption/segmented_gcm_part_test.go`
- `pkg/encryption/dataencryption/segmented_gcm_range.go`
- `pkg/encryption/dataencryption/segmented_gcm_range_test.go`
- `pkg/encryption/dataencryption/segmented_gcm_test.go`
- `pkg/encryption/dataencryption/segmented_gcm_vector_test.go`

## Audit Trail

- EXTRACTED: 256 (83%)
- INFERRED: 51 (17%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*