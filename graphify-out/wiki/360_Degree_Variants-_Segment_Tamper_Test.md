# 360 Degree Variants: Segment Tamper Test

> 9 nodes · cohesion 0.33

## Key Concepts

- **TamSetup()** (10 connections) — `test/integration/360-degree-variants/segment_tamper_test.go`
- **TestSegmentChainRefusesTamperedBytes()** (8 connections) — `test/integration/360-degree-variants/segment_tamper_test.go`
- **TestSegmentChainRefusesTamperedMetadata()** (6 connections) — `test/integration/360-degree-variants/segment_tamper_test.go`
- **TamAssertRefused()** (5 connections) — `test/integration/360-degree-variants/segment_tamper_test.go`
- **TestSegmentChainVerifiesRangedReads()** (5 connections) — `test/integration/360-degree-variants/segment_tamper_test.go`
- **TamDigest()** (4 connections) — `test/integration/360-degree-variants/segment_tamper_test.go`
- **TamInspect()** (4 connections) — `test/integration/360-degree-variants/segment_tamper_test.go`
- **TamShape** (3 connections) — `test/integration/360-degree-variants/segment_tamper_test.go`
- **.String()** (1 connections) — `test/integration/360-degree-variants/segment_tamper_test.go`

## Relationships

- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (8 shared connections)
- [Shutdown and Test Contexts](Shutdown_and_Test_Contexts.md) (5 shared connections)
- [Chunked Encoding Tests](Chunked_Encoding_Tests.md) (3 shared connections)
- [Streaming Integration Helpers](Streaming_Integration_Helpers.md) (2 shared connections)
- [Misc (15)](Misc_15.md) (2 shared connections)
- [In-Process Provider Instances](In-Process_Provider_Instances.md) (1 shared connections)
- [Client Library and Storage Format](Client_Library_and_Storage_Format.md) (1 shared connections)

## Source Files

- `test/integration/360-degree-variants/segment_tamper_test.go`

## Audit Trail

- EXTRACTED: 34 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*