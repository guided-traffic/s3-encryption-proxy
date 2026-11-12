# Storedobject: Storedobject

> 20 nodes · cohesion 0.15

## Key Concepts

- **TestNewKeysAnObjectThatItsMetadataOpens()** (10 connections) — `pkg/encryption/storedobject/storedobject_test.go`
- **Object** (10 connections) — `pkg/s3enc/read.go`
- **.codecFor()** (10 connections) — `pkg/s3enc/client.go`
- **WrappedDEK()** (8 connections) — `pkg/encryption/storedobject/storedobject.go`
- **Fingerprint()** (7 connections) — `pkg/encryption/storedobject/storedobject.go`
- **ClaimsFormat()** (6 connections) — `pkg/encryption/storedobject/storedobject.go`
- **TestGettersReportMissingAndMalformedFields()** (6 connections) — `pkg/encryption/storedobject/storedobject_test.go`
- **.GetRange()** (6 connections) — `pkg/s3enc/read.go`
- **.codecFor()** (5 connections) — `internal/orchestration/segmented.go`
- **testKEK()** (5 connections) — `pkg/encryption/storedobject/storedobject_test.go`
- **TestUnprefixedKeysAreNeverRead()** (5 connections) — `pkg/encryption/storedobject/storedobject_test.go`
- **.Get()** (5 connections) — `pkg/s3enc/read.go`
- **.Stat()** (5 connections) — `pkg/s3enc/read.go`
- **KEKAlgorithm()** (4 connections) — `pkg/encryption/storedobject/storedobject.go`
- **Info** (3 connections) — `pkg/s3enc/read.go`
- **.ClaimsSegmentedFormat()** (2 connections) — `internal/orchestration/segmented.go`
- **.IsSegmentedObject()** (2 connections) — `internal/orchestration/segmented.go`
- **.Close()** (2 connections) — `pkg/s3enc/read.go`
- **.Checksum()** (1 connections) — `pkg/s3enc/read.go`
- **.Read()** (1 connections) — `pkg/s3enc/read.go`

## Relationships

- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (10 shared connections)
- [Segment Codec and Range Planner](Segment_Codec_and_Range_Planner.md) (4 shared connections)
- [Shutdown and Test Contexts](Shutdown_and_Test_Contexts.md) (4 shared connections)
- [Orchestration: Providers Coverage Test (2)](Orchestration-_Providers_Coverage_Test_2.md) (4 shared connections)
- [Misc (15)](Misc_15.md) (4 shared connections)
- [Client Library and Storage Format](Client_Library_and_Storage_Format.md) (2 shared connections)
- [Segment Seal and Trailer](Segment_Seal_and_Trailer.md) (2 shared connections)
- [Segmented Session Tests](Segmented_Session_Tests.md) (2 shared connections)
- [Server and Listings](Server_and_Listings.md) (2 shared connections)
- [Dataencryption: Segmented Gcm Range](Dataencryption-_Segmented_Gcm_Range.md) (2 shared connections)
- [S3Enc: Helpers Test](S3Enc-_Helpers_Test.md) (2 shared connections)
- [ADR Corpus and Release History](ADR_Corpus_and_Release_History.md) (2 shared connections)

## Source Files

- `internal/orchestration/segmented.go`
- `pkg/encryption/storedobject/storedobject.go`
- `pkg/encryption/storedobject/storedobject_test.go`
- `pkg/s3enc/client.go`
- `pkg/s3enc/read.go`

## Audit Trail

- EXTRACTED: 57 (77%)
- INFERRED: 17 (23%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*