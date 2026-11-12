# S3 Methods: Range Conformance Test

> 19 nodes · cohesion 0.27

## Key Concepts

- **range_conformance_test.go** (32 connections) — `test/integration/s3-methods/range_conformance_test.go`
- **rngNewFixture()** (13 connections) — `test/integration/s3-methods/range_conformance_test.go`
- **rngViaMinIO()** (10 connections) — `test/integration/s3-methods/range_conformance_test.go`
- **rngViaProxy()** (10 connections) — `test/integration/s3-methods/range_conformance_test.go`
- **TestRngRangedGetMatchesMinIO()** (9 connections) — `test/integration/s3-methods/range_conformance_test.go`
- **rngRawGet()** (8 connections) — `test/integration/s3-methods/range_conformance_test.go`
- **TestRngGCMOverheadNeverLeaksIntoRangedReads()** (8 connections) — `test/integration/s3-methods/range_conformance_test.go`
- **TestRngMalformedRangeHeader()** (8 connections) — `test/integration/s3-methods/range_conformance_test.go`
- **TestRngMultipleRanges()** (8 connections) — `test/integration/s3-methods/range_conformance_test.go`
- **TestRngUnsatisfiableRangeContentRange()** (8 connections) — `test/integration/s3-methods/range_conformance_test.go`
- **rngPayload()** (7 connections) — `test/integration/s3-methods/range_conformance_test.go`
- **SignHTTPRequestForS3()** (7 connections) — `test/integration/s3_signing_helper.go`
- **rngObserved** (5 connections) — `test/integration/s3-methods/range_conformance_test.go`
- **rngFixture** (4 connections) — `test/integration/s3-methods/range_conformance_test.go`
- **.putPair()** (3 connections) — `test/integration/s3-methods/range_conformance_test.go`
- **rngCasesFor()** (3 connections) — `test/integration/s3-methods/range_conformance_test.go`
- **NewAWSV4Signer()** (3 connections) — `test/integration/s3_signing_helper.go`
- **rngCase** (2 connections) — `test/integration/s3-methods/range_conformance_test.go`
- **.String()** (1 connections) — `test/integration/s3-methods/range_conformance_test.go`

## Relationships

- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (19 shared connections)
- [Shutdown and Test Contexts](Shutdown_and_Test_Contexts.md) (11 shared connections)
- [Chunked Encoding Tests](Chunked_Encoding_Tests.md) (8 shared connections)
- [Delete and Checksum Integration](Delete_and_Checksum_Integration.md) (7 shared connections)
- [Misc (15)](Misc_15.md) (5 shared connections)
- [In-Process Provider Instances](In-Process_Provider_Instances.md) (2 shared connections)
- [S3 Methods: Sealed Checksum Test](S3_Methods-_Sealed_Checksum_Test.md) (1 shared connections)
- [Streaming Integration Helpers](Streaming_Integration_Helpers.md) (1 shared connections)
- [Server and Listings](Server_and_Listings.md) (1 shared connections)
- [ListObjects Conformance](ListObjects_Conformance.md) (1 shared connections)
- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (1 shared connections)

## Source Files

- `test/integration/s3-methods/range_conformance_test.go`
- `test/integration/s3_signing_helper.go`

## Audit Trail

- EXTRACTED: 103 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*