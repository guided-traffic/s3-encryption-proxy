# Segment Tamper Tests

> 15 nodes · cohesion 0.35

## Key Concepts

- **TamSetup()** (10 connections) — `test/integration/360-degree-variants/segment_tamper_test.go`
- **TestSegmentChainRefusesTamperedBytes()** (10 connections) — `test/integration/360-degree-variants/segment_tamper_test.go`
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
- **TamShape** (3 connections) — `test/integration/360-degree-variants/segment_tamper_test.go`
- **TamInspect()** (3 connections) — `test/integration/360-degree-variants/segment_tamper_test.go`
- **.String()** (1 connections) — `test/integration/360-degree-variants/segment_tamper_test.go`

## Relationships

- [Config Env Expansion](Config_Env_Expansion.md) (9 shared connections)
- [Mock Backend Helpers](Mock_Backend_Helpers.md) (5 shared connections)
- [360-Degree Singlepart Tests](360-Degree_Singlepart_Tests.md) (3 shared connections)
- [Object Sub-Resource Refusals](Object_Sub-Resource_Refusals.md) (3 shared connections)
- [Provider Mode Integration Tests](Provider_Mode_Integration_Tests.md) (1 shared connections)

## Source Files

- `test/integration/360-degree-variants/segment_tamper_test.go`

## Audit Trail

- EXTRACTED: 58 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*