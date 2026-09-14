# Range Conformance Tests

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

- [Config Env Expansion](Config_Env_Expansion.md) (11 shared connections)
- [Object Sub-Resource Refusals](Object_Sub-Resource_Refusals.md) (7 shared connections)
- [Encryption-at-Rest Integration Tests](Encryption-at-Rest_Integration_Tests.md) (6 shared connections)
- [Mock Backend Helpers](Mock_Backend_Helpers.md) (5 shared connections)
- [Provider Mode Integration Tests](Provider_Mode_Integration_Tests.md) (1 shared connections)
- [SigV4 Signing Helper](SigV4_Signing_Helper.md) (1 shared connections)
- [Chunked Upload Tests](Chunked_Upload_Tests.md) (1 shared connections)

## Source Files

- `test/integration/s3-methods/range_conformance_test.go`

## Audit Trail

- EXTRACTED: 81 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*