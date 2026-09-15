# Segment Encrypt Reader Tests

> 36 nodes · cohesion 0.12

## Key Concepts

- **testCodec()** (31 connections) — `pkg/encryption/dataencryption/segmented_gcm_test.go`
- **segmented_gcm_test.go** (25 connections) — `pkg/encryption/dataencryption/segmented_gcm_test.go`
- **seal()** (21 connections) — `pkg/encryption/dataencryption/segmented_gcm_test.go`
- **NewChecksum()** (10 connections) — `pkg/encryption/dataencryption/segmented_gcm.go`
- **segmented_gcm_encrypt_reader_test.go** (8 connections) — `pkg/encryption/dataencryption/segmented_gcm_encrypt_reader_test.go`
- **TestSegForgedTrailerChecksumFails()** (6 connections) — `pkg/encryption/dataencryption/segmented_gcm_test.go`
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
- **TestSegSegmentFromAnotherObjectFails()** (4 connections) — `pkg/encryption/dataencryption/segmented_gcm_test.go`
- **TestSegSwappedSegmentsFail()** (4 connections) — `pkg/encryption/dataencryption/segmented_gcm_test.go`
- **TestSegTrailerIsNotABareChecksum()** (4 connections) — `pkg/encryption/dataencryption/segmented_gcm_test.go`
- **TestSegTrailerSubstitutedFromAnotherObjectFails()** (4 connections) — `pkg/encryption/dataencryption/segmented_gcm_test.go`
- **TestSegTruncatedFails()** (4 connections) — `pkg/encryption/dataencryption/segmented_gcm_test.go`
- **.Read()** (3 connections) — `pkg/encryption/dataencryption/segmented_gcm_encrypt_reader_test.go`
- **TestSegEncryptReaderChecksum()** (3 connections) — `pkg/encryption/dataencryption/segmented_gcm_encrypt_reader_test.go`
- **TestSegEncryptReaderPropagatesSourceError()** (3 connections) — `pkg/encryption/dataencryption/segmented_gcm_encrypt_reader_test.go`
- *... and 11 more nodes in this community*

## Relationships

- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (28 shared connections)
- [Segmented GCM Range Reader](Segmented_GCM_Range_Reader.md) (10 shared connections)
- [Segmented GCM](Segmented_GCM.md) (6 shared connections)
- [Segmented GCM Vector](Segmented_GCM_Vector.md) (3 shared connections)
- [Segmented Session Tests](Segmented_Session_Tests.md) (2 shared connections)
- [Segmented Session Lifecycle](Segmented_Session_Lifecycle.md) (1 shared connections)
- [Segmented Manager Streaming IO](Segmented_Manager_Streaming_IO.md) (1 shared connections)
- [Segment Seal and Open Internals](Segment_Seal_and_Open_Internals.md) (1 shared connections)
- [Client E2E Verdicts](Client_E2E_Verdicts.md) (1 shared connections)

## Source Files

- `pkg/encryption/dataencryption/segmented_gcm.go`
- `pkg/encryption/dataencryption/segmented_gcm_encrypt_reader_test.go`
- `pkg/encryption/dataencryption/segmented_gcm_test.go`

## Audit Trail

- EXTRACTED: 102 (79%)
- INFERRED: 27 (21%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*