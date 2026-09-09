# Range Request Conformance Tests

> 18 nodes · cohesion 0.35

## Key Concepts

- **range_conformance_test.go** (15 connections) — `test/integration/s3-methods/range_conformance_test.go`
- **rngNewFixture()** (12 connections) — `test/integration/s3-methods/range_conformance_test.go`
- **rngViaMinIO()** (10 connections) — `test/integration/s3-methods/range_conformance_test.go`
- **rngViaProxy()** (10 connections) — `test/integration/s3-methods/range_conformance_test.go`
- **TestRngMalformedRangeHeader()** (10 connections) — `test/integration/s3-methods/range_conformance_test.go`
- **TestRngMultipleRanges()** (10 connections) — `test/integration/s3-methods/range_conformance_test.go`
- **TestRngRangedGetMatchesMinIO()** (10 connections) — `test/integration/s3-methods/range_conformance_test.go`
- **TestRngUnsatisfiableRangeContentRange()** (10 connections) — `test/integration/s3-methods/range_conformance_test.go`
- **TestRngGCMOverheadNeverLeaksIntoRangedReads()** (9 connections) — `test/integration/s3-methods/range_conformance_test.go`
- **.putPair()** (8 connections) — `test/integration/s3-methods/range_conformance_test.go`
- **rngRawGet()** (8 connections) — `test/integration/s3-methods/range_conformance_test.go`
- **rngPayload()** (7 connections) — `test/integration/s3-methods/range_conformance_test.go`
- **rngObserved** (5 connections) — `test/integration/s3-methods/range_conformance_test.go`
- **rngFixture** (4 connections) — `test/integration/s3-methods/range_conformance_test.go`
- **rngIsGCM()** (4 connections) — `test/integration/s3-methods/range_conformance_test.go`
- **rngCasesFor()** (3 connections) — `test/integration/s3-methods/range_conformance_test.go`
- **rngCase** (2 connections) — `test/integration/s3-methods/range_conformance_test.go`
- **.String()** (1 connections) — `test/integration/s3-methods/range_conformance_test.go`

## Relationships

- [Config Accessor Tests](Config_Accessor_Tests.md) (11 shared connections)
- [Range Read Integration Tests](Range_Read_Integration_Tests.md) (7 shared connections)
- [Encryption At Rest Tests](Encryption_At_Rest_Tests.md) (6 shared connections)
- [S3 Backend Interface Types](S3_Backend_Interface_Types.md) (5 shared connections)
- [AES and RSA Provider Tests](AES_and_RSA_Provider_Tests.md) (1 shared connections)
- [SigV4 Test Signer](SigV4_Test_Signer.md) (1 shared connections)
- [AWS Chunked Body Tests](AWS_Chunked_Body_Tests.md) (1 shared connections)

## Source Files

- `test/integration/s3-methods/range_conformance_test.go`

## Audit Trail

- EXTRACTED: 85 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*