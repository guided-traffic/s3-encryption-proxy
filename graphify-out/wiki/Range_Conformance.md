# Range Conformance

> 17 nodes · cohesion 0.36

## Key Concepts

- **range_conformance_test.go** (14 connections) — `test/integration/s3-methods/range_conformance_test.go`
- **rngNewFixture()** (12 connections) — `test/integration/s3-methods/range_conformance_test.go`
- **rngViaMinIO()** (10 connections) — `test/integration/s3-methods/range_conformance_test.go`
- **rngViaProxy()** (10 connections) — `test/integration/s3-methods/range_conformance_test.go`
- **TestRngRangedGetMatchesMinIO()** (10 connections) — `test/integration/s3-methods/range_conformance_test.go`
- **TestRngGCMOverheadNeverLeaksIntoRangedReads()** (9 connections) — `test/integration/s3-methods/range_conformance_test.go`
- **TestRngMalformedRangeHeader()** (9 connections) — `test/integration/s3-methods/range_conformance_test.go`
- **TestRngMultipleRanges()** (9 connections) — `test/integration/s3-methods/range_conformance_test.go`
- **TestRngUnsatisfiableRangeContentRange()** (9 connections) — `test/integration/s3-methods/range_conformance_test.go`
- **.putPair()** (8 connections) — `test/integration/s3-methods/range_conformance_test.go`
- **rngRawGet()** (8 connections) — `test/integration/s3-methods/range_conformance_test.go`
- **rngPayload()** (7 connections) — `test/integration/s3-methods/range_conformance_test.go`
- **rngObserved** (5 connections) — `test/integration/s3-methods/range_conformance_test.go`
- **rngFixture** (4 connections) — `test/integration/s3-methods/range_conformance_test.go`
- **rngCasesFor()** (3 connections) — `test/integration/s3-methods/range_conformance_test.go`
- **rngCase** (2 connections) — `test/integration/s3-methods/range_conformance_test.go`
- **.String()** (1 connections) — `test/integration/s3-methods/range_conformance_test.go`

## Relationships

- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (11 shared connections)
- [S3 Method Error Mapping Tests](S3_Method_Error_Mapping_Tests.md) (6 shared connections)
- [MockS3Backend Bucket Operations](MockS3Backend_Bucket_Operations.md) (5 shared connections)
- [Ranged Read and Passthrough Tests](Ranged_Read_and_Passthrough_Tests.md) (5 shared connections)
- [Authentication Integration Tests](Authentication_Integration_Tests.md) (2 shared connections)
- [Streaming Upload and Sealed Checksum](Streaming_Upload_and_Sealed_Checksum.md) (1 shared connections)
- [Multipart Conformance Suite](Multipart_Conformance_Suite.md) (1 shared connections)
- [Chunked Streaming Test Harness](Chunked_Streaming_Test_Harness.md) (1 shared connections)

## Source Files

- `test/integration/s3-methods/range_conformance_test.go`

## Audit Trail

- EXTRACTED: 81 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*