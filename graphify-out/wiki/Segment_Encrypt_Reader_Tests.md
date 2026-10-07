# Segment Encrypt Reader Tests

> 49 nodes · cohesion 0.09

## Key Concepts

- **testCodec()** (31 connections) — `pkg/encryption/dataencryption/segmented_gcm_test.go`
- **segmented_gcm_test.go** (25 connections) — `pkg/encryption/dataencryption/segmented_gcm_test.go`
- **seal()** (21 connections) — `pkg/encryption/dataencryption/segmented_gcm_test.go`
- **PlanRange()** (15 connections) — `pkg/encryption/dataencryption/segmented_gcm_range.go`
- **NewCodec()** (11 connections) — `pkg/encryption/dataencryption/segmented_gcm.go`
- **NewChecksum()** (10 connections) — `pkg/encryption/dataencryption/segmented_gcm.go`
- **segmented_gcm_range_test.go** (10 connections) — `pkg/encryption/dataencryption/segmented_gcm_range_test.go`
- **segmented_gcm_encrypt_reader_test.go** (8 connections) — `pkg/encryption/dataencryption/segmented_gcm_encrypt_reader_test.go`
- **TestSegRangeExhaustive()** (6 connections) — `pkg/encryption/dataencryption/segmented_gcm_range_test.go`
- **TestSegForgedTrailerChecksumFails()** (6 connections) — `pkg/encryption/dataencryption/segmented_gcm_test.go`
- **TestSegRangeSegmentFromAnotherOffsetFails()** (5 connections) — `pkg/encryption/dataencryption/segmented_gcm_range_test.go`
- **TestSegRangeShortWindowFails()** (5 connections) — `pkg/encryption/dataencryption/segmented_gcm_range_test.go`
- **TestSegRangeTailVerifiesTheAuthenticatedLength()** (5 connections) — `pkg/encryption/dataencryption/segmented_gcm_range_test.go`
- **TestSegRangeTamperedSegmentFails()** (5 connections) — `pkg/encryption/dataencryption/segmented_gcm_range_test.go`
- **TestSegForgedTrailerLengthFails()** (5 connections) — `pkg/encryption/dataencryption/segmented_gcm_test.go`
- **TestSegRoundTrip()** (5 connections) — `pkg/encryption/dataencryption/segmented_gcm_test.go`
- **TestSegEncryptReaderMatchesWriter()** (4 connections) — `pkg/encryption/dataencryption/segmented_gcm_encrypt_reader_test.go`
- **TestSegEncryptReaderRoundTrip()** (4 connections) — `pkg/encryption/dataencryption/segmented_gcm_encrypt_reader_test.go`
- **TestSegEncryptReaderStaysFailedAfterAnError()** (4 connections) — `pkg/encryption/dataencryption/segmented_gcm_encrypt_reader_test.go`
- **TestSegEncryptReaderTinyReads()** (4 connections) — `pkg/encryption/dataencryption/segmented_gcm_encrypt_reader_test.go`
- **TestSegChecksumMatchesTrailer()** (4 connections) — `pkg/encryption/dataencryption/segmented_gcm_test.go`
- **TestSegExtendedFails()** (4 connections) — `pkg/encryption/dataencryption/segmented_gcm_test.go`
- **TestSegFlippedBitFails()** (4 connections) — `pkg/encryption/dataencryption/segmented_gcm_test.go`
- **TestSegIdenticalSegmentsCannotBeReordered()** (4 connections) — `pkg/encryption/dataencryption/segmented_gcm_test.go`
- **TestSegNoncesAreUnique()** (4 connections) — `pkg/encryption/dataencryption/segmented_gcm_test.go`
- *... and 24 more nodes in this community*

## Relationships

- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (39 shared connections)
- [Segmented GCM](Segmented_GCM.md) (5 shared connections)
- [Segmented Manager Streaming IO](Segmented_Manager_Streaming_IO.md) (4 shared connections)
- [Segment Seal and Open Internals](Segment_Seal_and_Open_Internals.md) (4 shared connections)
- [Segmented GCM Range Reader](Segmented_GCM_Range_Reader.md) (4 shared connections)
- [Segmented Session Tests](Segmented_Session_Tests.md) (2 shared connections)
- [Segmented Session Lifecycle](Segmented_Session_Lifecycle.md) (1 shared connections)
- [Cryptofloor](Cryptofloor.md) (1 shared connections)
- [Segmented GCM Part](Segmented_GCM_Part.md) (1 shared connections)
- [Storage Format Invariants](Storage_Format_Invariants.md) (1 shared connections)
- [Integrity Operator Notes](Integrity_Operator_Notes.md) (1 shared connections)

## Source Files

- `pkg/encryption/dataencryption/segmented_gcm.go`
- `pkg/encryption/dataencryption/segmented_gcm_encrypt_reader_test.go`
- `pkg/encryption/dataencryption/segmented_gcm_range.go`
- `pkg/encryption/dataencryption/segmented_gcm_range_test.go`
- `pkg/encryption/dataencryption/segmented_gcm_test.go`

## Audit Trail

- EXTRACTED: 132 (77%)
- INFERRED: 40 (23%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*