# Segment Tamper

> 15 nodes · cohesion 0.36

## Key Concepts

- **TestSegmentChainRefusesTamperedBytes()** (15 connections) — `test/integration/360-degree-variants/segment_tamper_test.go`
- **TamSetup()** (10 connections) — `test/integration/360-degree-variants/segment_tamper_test.go`
- **TestSegmentChainRefusesTamperedMetadata()** (10 connections) — `test/integration/360-degree-variants/segment_tamper_test.go`
- **segment_tamper_test.go** (9 connections) — `test/integration/360-degree-variants/segment_tamper_test.go`
- **TestSegmentChainVerifiesRangedReads()** (9 connections) — `test/integration/360-degree-variants/segment_tamper_test.go`
- **TamEnv** (7 connections) — `test/integration/360-degree-variants/segment_tamper_test.go`
- **.TamRead()** (6 connections) — `test/integration/360-degree-variants/segment_tamper_test.go`
- **.TamReplace()** (6 connections) — `test/integration/360-degree-variants/segment_tamper_test.go`
- **.TamStored()** (6 connections) — `test/integration/360-degree-variants/segment_tamper_test.go`
- **.TamWrite()** (6 connections) — `test/integration/360-degree-variants/segment_tamper_test.go`
- **TamAssertRefused()** (5 connections) — `test/integration/360-degree-variants/segment_tamper_test.go`
- **TamDigest()** (4 connections) — `test/integration/360-degree-variants/segment_tamper_test.go`
- **TamInspect()** (4 connections) — `test/integration/360-degree-variants/segment_tamper_test.go`
- **TamShape** (3 connections) — `test/integration/360-degree-variants/segment_tamper_test.go`
- **.String()** (1 connections) — `test/integration/360-degree-variants/segment_tamper_test.go`

## Relationships

- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (9 shared connections)
- [MockS3Backend Bucket Operations](MockS3Backend_Bucket_Operations.md) (5 shared connections)
- [Chunked Streaming Test Harness](Chunked_Streaming_Test_Harness.md) (3 shared connections)
- [Ranged Read and Passthrough Tests](Ranged_Read_and_Passthrough_Tests.md) (3 shared connections)
- [Hardening History](Hardening_History.md) (3 shared connections)
- [Large Multipart and DEK Cache Tests](Large_Multipart_and_DEK_Cache_Tests.md) (1 shared connections)
- [Client E2E Verdicts](Client_E2E_Verdicts.md) (1 shared connections)

## Source Files

- `test/integration/360-degree-variants/segment_tamper_test.go`

## Audit Trail

- EXTRACTED: 63 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*