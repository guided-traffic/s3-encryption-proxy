# Segment Codec Tests

> 53 nodes · cohesion 0.09

## Key Concepts

- **testCodec()** (30 connections) — `pkg/encryption/dataencryption/segmented_gcm_test.go`
- **segmented_gcm_test.go** (25 connections) — `pkg/encryption/dataencryption/segmented_gcm_test.go`
- **seal()** (21 connections) — `pkg/encryption/dataencryption/segmented_gcm_test.go`
- **CiphertextSize()** (17 connections) — `pkg/encryption/dataencryption/segmented_gcm.go`
- **PlanRange()** (14 connections) — `pkg/encryption/dataencryption/segmented_gcm_range.go`
- **segmented_gcm_range_test.go** (10 connections) — `pkg/encryption/dataencryption/segmented_gcm_range_test.go`
- **NewCodec()** (9 connections) — `pkg/encryption/dataencryption/segmented_gcm.go`
- **NewChecksum()** (8 connections) — `pkg/encryption/dataencryption/segmented_gcm.go`
- **segmented_gcm_encrypt_reader_test.go** (7 connections) — `pkg/encryption/dataencryption/segmented_gcm_encrypt_reader_test.go`
- **PlaintextSize()** (6 connections) — `pkg/encryption/dataencryption/segmented_gcm.go`
- **TestSegRangeExhaustive()** (6 connections) — `pkg/encryption/dataencryption/segmented_gcm_range_test.go`
- **TestSegRangeSegmentFromAnotherOffsetFails()** (5 connections) — `pkg/encryption/dataencryption/segmented_gcm_range_test.go`
- **TestSegRangeShortWindowFails()** (5 connections) — `pkg/encryption/dataencryption/segmented_gcm_range_test.go`
- **TestSegRangeTailVerifiesTheAuthenticatedLength()** (5 connections) — `pkg/encryption/dataencryption/segmented_gcm_range_test.go`
- **TestSegRangeTamperedSegmentFails()** (5 connections) — `pkg/encryption/dataencryption/segmented_gcm_range_test.go`
- **TestSegForgedTrailerChecksumFails()** (5 connections) — `pkg/encryption/dataencryption/segmented_gcm_test.go`
- **TestSegForgedTrailerLengthFails()** (5 connections) — `pkg/encryption/dataencryption/segmented_gcm_test.go`
- **TestSegRoundTrip()** (5 connections) — `pkg/encryption/dataencryption/segmented_gcm_test.go`
- **TestSegEncryptReaderMatchesWriter()** (4 connections) — `pkg/encryption/dataencryption/segmented_gcm_encrypt_reader_test.go`
- **TestSegEncryptReaderRoundTrip()** (4 connections) — `pkg/encryption/dataencryption/segmented_gcm_encrypt_reader_test.go`
- **TestSegEncryptReaderStaysFailedAfterAnError()** (4 connections) — `pkg/encryption/dataencryption/segmented_gcm_encrypt_reader_test.go`
- **TestSegEncryptReaderTinyReads()** (4 connections) — `pkg/encryption/dataencryption/segmented_gcm_encrypt_reader_test.go`
- **TestSegChecksumMatchesTrailer()** (4 connections) — `pkg/encryption/dataencryption/segmented_gcm_test.go`
- **TestSegExtendedFails()** (4 connections) — `pkg/encryption/dataencryption/segmented_gcm_test.go`
- **TestSegFlippedBitFails()** (4 connections) — `pkg/encryption/dataencryption/segmented_gcm_test.go`
- *... and 28 more nodes in this community*

## Relationships

- [Config Env Expansion](Config_Env_Expansion.md) (39 shared connections)
- [Segment Codec Core](Segment_Codec_Core.md) (6 shared connections)
- [Range Reader](Range_Reader.md) (5 shared connections)
- [Segmented Object Entry Points](Segmented_Object_Entry_Points.md) (3 shared connections)
- [Segmented Orchestration Tests](Segmented_Orchestration_Tests.md) (2 shared connections)
- [Part Codec Tests](Part_Codec_Tests.md) (2 shared connections)
- [Sealed Part Arithmetic](Sealed_Part_Arithmetic.md) (2 shared connections)
- [Bucket Handler Tests](Bucket_Handler_Tests.md) (1 shared connections)
- [Multipart Handler Tests](Multipart_Handler_Tests.md) (1 shared connections)
- [Multipart Handler Unit Tests](Multipart_Handler_Unit_Tests.md) (1 shared connections)
- [Object GET Handler Tests](Object_GET_Handler_Tests.md) (1 shared connections)
- [Object PUT Handler Tests](Object_PUT_Handler_Tests.md) (1 shared connections)

## Source Files

- `pkg/encryption/dataencryption/segmented_gcm.go`
- `pkg/encryption/dataencryption/segmented_gcm_encrypt_reader_test.go`
- `pkg/encryption/dataencryption/segmented_gcm_range.go`
- `pkg/encryption/dataencryption/segmented_gcm_range_test.go`
- `pkg/encryption/dataencryption/segmented_gcm_test.go`

## Audit Trail

- EXTRACTED: 143 (76%)
- INFERRED: 44 (24%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*