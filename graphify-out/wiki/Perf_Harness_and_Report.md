# Perf Harness and Report

> 76 nodes · cohesion 0.06

## Key Concepts

- **perf/harness.go** (35 connections) — `test/perf/harness.go`
- **TestProxyMemory()** (15 connections) — `test/perf/memory_test.go`
- **TestSmallObjectRate()** (14 connections) — `test/perf/smallobject_test.go`
- **TestCPUProfiles()** (13 connections) — `test/perf/memory_test.go`
- **measureThroughput()** (13 connections) — `test/perf/throughput_test.go`
- **TestRangeRead()** (12 connections) — `test/perf/rangeread_test.go`
- **report.go** (12 connections) — `test/perf/report.go`
- **humanBytes()** (12 connections) — `test/perf/report.go`
- **Record()** (11 connections) — `test/perf/harness.go`
- **ensureBucket()** (10 connections) — `test/perf/client.go`
- **renderReport()** (10 connections) — `test/perf/report.go`
- **TestUploadPathComparison()** (10 connections) — `test/perf/uploadpath_test.go`
- **net/http.Client** (9 connections)
- **Run** (9 connections) — `test/perf/harness.go`
- **emptyBucket()** (9 connections) — `test/perf/client.go`
- **TestCryptoFloor()** (9 connections) — `test/perf/cryptofloor_test.go`
- **Reps()** (9 connections) — `test/perf/harness.go`
- **SetStatus()** (9 connections) — `test/perf/harness.go`
- **legsFor()** (8 connections) — `test/perf/client.go`
- **Emit()** (8 connections) — `test/perf/harness.go`
- **TestUnwrapMicrobenchmark()** (8 connections) — `test/perf/unwrap_test.go`
- **renderPlainSection()** (7 connections) — `test/perf/report.go`
- **TestMain()** (6 connections) — `test/perf/main_test.go`
- **TestThroughput()** (6 connections) — `test/perf/throughput_test.go`
- **median()** (6 connections) — `test/perf/unwrap_test.go`
- *... and 51 more nodes in this community*

## Relationships

- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (56 shared connections)
- [Tampering Harness](Tampering_Harness.md) (12 shared connections)
- [Shutdown and Test Contexts](Shutdown_and_Test_Contexts.md) (9 shared connections)
- [Streaming Integration Helpers](Streaming_Integration_Helpers.md) (3 shared connections)
- [Velero E2E Suite](Velero_E2E_Suite.md) (2 shared connections)
- [In-Process Provider Instances](In-Process_Provider_Instances.md) (2 shared connections)
- [Segment Seal and Trailer](Segment_Seal_and_Trailer.md) (1 shared connections)
- [Harness: Backend](Harness-_Backend.md) (1 shared connections)
- [Conformance Suite](Conformance_Suite.md) (1 shared connections)
- [Chunked Encoding Tests](Chunked_Encoding_Tests.md) (1 shared connections)
- [Segment Codec and Range Planner](Segment_Codec_and_Range_Planner.md) (1 shared connections)
- [Object Checksum Agreement Tests](Object_Checksum_Agreement_Tests.md) (1 shared connections)

## Source Files

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
- `test/perf/uploadpath_test.go`

## Audit Trail

- EXTRACTED: 198 (76%)
- INFERRED: 61 (24%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*