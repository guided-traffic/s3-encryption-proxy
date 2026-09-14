# Streaming Performance Test

> 4 nodes · cohesion 0.83

## Key Concepts

- **TestStreamingVsStandardPerformance()** (5 connections) — `test/integration/performance-test/streaming_test.go`
- **streaming_test.go** (4 connections) — `test/integration/performance-test/streaming_test.go`
- **downloadAndVerifyWithSDK()** (4 connections) — `test/integration/performance-test/streaming_test.go`
- **performMultipartUploadWithSDK()** (4 connections) — `test/integration/performance-test/streaming_test.go`

## Relationships

- [Config Env Expansion](Config_Env_Expansion.md) (3 shared connections)
- [Passthrough Operation Tests](Passthrough_Operation_Tests.md) (2 shared connections)
- [Object Sub-Resource Refusals](Object_Sub-Resource_Refusals.md) (2 shared connections)

## Source Files

- `test/integration/performance-test/streaming_test.go`

## Audit Trail

- EXTRACTED: 11 (92%)
- INFERRED: 1 (8%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*