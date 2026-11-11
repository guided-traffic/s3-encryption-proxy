# Storedobject: Storedobject

> 25 nodes · cohesion 0.13

## Key Concepts

- **TestNewKeysAnObjectThatItsMetadataOpens()** (10 connections) — `pkg/encryption/storedobject/storedobject_test.go`
- **.codecFor()** (10 connections) — `pkg/s3enc/client.go`
- **IsReserved()** (8 connections) — `pkg/encryption/storedobject/storedobject.go`
- **WrappedDEK()** (8 connections) — `pkg/encryption/storedobject/storedobject.go`
- **s3ep- metadata namespace, filtered out and refused in** (7 connections) — `docs/security/stored-objects.md`
- **Fingerprint()** (7 connections) — `pkg/encryption/storedobject/storedobject.go`
- **UserMetadata()** (7 connections) — `pkg/encryption/storedobject/storedobject.go`
- **ClaimsFormat()** (6 connections) — `pkg/encryption/storedobject/storedobject.go`
- **TestGettersReportMissingAndMalformedFields()** (6 connections) — `pkg/encryption/storedobject/storedobject_test.go`
- **.GetRange()** (6 connections) — `pkg/s3enc/read.go`
- **.codecFor()** (5 connections) — `internal/orchestration/segmented.go`
- **testKEK()** (5 connections) — `pkg/encryption/storedobject/storedobject_test.go`
- **TestUnprefixedKeysAreNeverRead()** (5 connections) — `pkg/encryption/storedobject/storedobject_test.go`
- **.Get()** (5 connections) — `pkg/s3enc/read.go`
- **.Stat()** (5 connections) — `pkg/s3enc/read.go`
- **Response composed from an allowlist, never proxied** (4 connections) — `docs/developer/request-paths.md`
- **.cleanMetadata()** (4 connections) — `internal/proxy/handlers/object/helpers.go`
- **KEKAlgorithm()** (4 connections) — `pkg/encryption/storedobject/storedobject.go`
- **Metadata()** (4 connections) — `pkg/encryption/storedobject/storedobject.go`
- **TestIsReservedIgnoresCase()** (3 connections) — `pkg/encryption/storedobject/storedobject_test.go`
- **TestMetadataDropsEveryUserKeyInsideTheNamespace()** (3 connections) — `pkg/encryption/storedobject/storedobject_test.go`
- **Info** (3 connections) — `pkg/s3enc/read.go`
- **formatKeys()** (3 connections) — `test/integration/s3enc/helpers_test.go`
- **.ClaimsSegmentedFormat()** (2 connections) — `internal/orchestration/segmented.go`
- **.IsSegmentedObject()** (2 connections) — `internal/orchestration/segmented.go`

## Relationships

- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (15 shared connections)
- [Shutdown and Test Contexts](Shutdown_and_Test_Contexts.md) (6 shared connections)
- [Tampering Harness](Tampering_Harness.md) (5 shared connections)
- [S3 API Behaviour](S3_API_Behaviour.md) (4 shared connections)
- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (4 shared connections)
- [Segment Codec and Range Planner](Segment_Codec_and_Range_Planner.md) (4 shared connections)
- [Client Library and Storage Format](Client_Library_and_Storage_Format.md) (3 shared connections)
- [Segment Seal and Trailer](Segment_Seal_and_Trailer.md) (2 shared connections)
- [Segmented Session Tests](Segmented_Session_Tests.md) (2 shared connections)
- [S3Enc: Client](S3Enc-_Client.md) (2 shared connections)
- [Orchestration: Providers Coverage Test (2)](Orchestration-_Providers_Coverage_Test_2.md) (2 shared connections)
- [Keygen and Encrypt Readers](Keygen_and_Encrypt_Readers.md) (2 shared connections)

## Source Files

- `docs/developer/request-paths.md`
- `docs/security/stored-objects.md`
- `internal/orchestration/segmented.go`
- `internal/proxy/handlers/object/helpers.go`
- `pkg/encryption/storedobject/storedobject.go`
- `pkg/encryption/storedobject/storedobject_test.go`
- `pkg/s3enc/client.go`
- `pkg/s3enc/read.go`
- `test/integration/s3enc/helpers_test.go`

## Audit Trail

- EXTRACTED: 72 (77%)
- INFERRED: 22 (23%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*