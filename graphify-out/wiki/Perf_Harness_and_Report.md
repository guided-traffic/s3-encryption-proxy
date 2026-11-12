# Perf Harness and Report

> 70 nodes · cohesion 0.06

## Key Concepts

- **perf/harness.go** (35 connections) — `test/perf/harness.go`
- **TestProxyMemory()** (15 connections) — `test/perf/memory_test.go`
- **TestSmallObjectRate()** (14 connections) — `test/perf/smallobject_test.go`
- **TestCPUProfiles()** (13 connections) — `test/perf/memory_test.go`
- **TestRangeRead()** (12 connections) — `test/perf/rangeread_test.go`
- **report.go** (12 connections) — `test/perf/report.go`
- **humanBytes()** (12 connections) — `test/perf/report.go`
- **Record()** (11 connections) — `test/perf/harness.go`
- **renderReport()** (10 connections) — `test/perf/report.go`
- **net/http.Client** (9 connections)
- **Run** (9 connections) — `test/perf/harness.go`
- **TestCryptoFloor()** (9 connections) — `test/perf/cryptofloor_test.go`
- **Reps()** (9 connections) — `test/perf/harness.go`
- **SetStatus()** (9 connections) — `test/perf/harness.go`
- **legsFor()** (8 connections) — `test/perf/client.go`
- **Emit()** (8 connections) — `test/perf/harness.go`
- **TestUnwrapMicrobenchmark()** (8 connections) — `test/perf/unwrap_test.go`
- **renderPlainSection()** (7 connections) — `test/perf/report.go`
- **TestMain()** (6 connections) — `test/perf/main_test.go`
- **TestThroughput()** (6 connections) — `test/perf/throughput_test.go`
- **caTrustingHTTPClient()** (5 connections) — `test/e2e/harness/backend.go`
- **newS3Client()** (5 connections) — `test/perf/client.go`
- **collectHardware()** (5 connections) — `test/perf/harness.go`
- **detectStack()** (5 connections) — `test/perf/main_test.go`
- **startRSSSampler()** (5 connections) — `test/perf/memory_test.go`
- *... and 45 more nodes in this community*

## Relationships

- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (50 shared connections)
- [Misc (15)](Misc_15.md) (28 shared connections)
- [Shutdown and Test Contexts](Shutdown_and_Test_Contexts.md) (8 shared connections)
- [Streaming Integration Helpers](Streaming_Integration_Helpers.md) (3 shared connections)
- [Segment Seal and Trailer](Segment_Seal_and_Trailer.md) (1 shared connections)
- [Tampering Harness](Tampering_Harness.md) (1 shared connections)
- [Velero E2E Suite](Velero_E2E_Suite.md) (1 shared connections)
- [Conformance Suite](Conformance_Suite.md) (1 shared connections)
- [Chunked Encoding Tests](Chunked_Encoding_Tests.md) (1 shared connections)
- [Harness: Backend](Harness-_Backend.md) (1 shared connections)
- [Harness: Exec](Harness-_Exec.md) (1 shared connections)
- [Segment Codec and Range Planner](Segment_Codec_and_Range_Planner.md) (1 shared connections)

## Source Files

- `test/e2e/harness/backend.go`
- `test/perf/client.go`
- `test/perf/cryptofloor_test.go`
- `test/perf/harness.go`
- `test/perf/main_test.go`
- `test/perf/memory_test.go`
- `test/perf/rangeread_test.go`
- `test/perf/report.go`
- `test/perf/smallobject_test.go`
- `test/perf/throughput_test.go`
- `test/perf/unwrap_test.go`

## Audit Trail

- EXTRACTED: 184 (77%)
- INFERRED: 56 (23%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*