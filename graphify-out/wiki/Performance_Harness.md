# Performance Harness

> 95 nodes · cohesion 0.05

## Key Concepts

- **harness.go** (20 connections) — `test/perf/harness.go`
- **TestProxyMemory()** (16 connections) — `test/perf/memory_test.go`
- **TestSmallObjectRate()** (14 connections) — `test/perf/smallobject_test.go`
- **TestCPUProfiles()** (13 connections) — `test/perf/memory_test.go`
- **measureThroughput()** (13 connections) — `test/perf/throughput_test.go`
- **leg** (12 connections) — `test/perf/client.go`
- **TestRangeRead()** (12 connections) — `test/perf/rangeread_test.go`
- **humanBytes()** (12 connections) — `test/perf/report.go`
- **Record()** (11 connections) — `test/perf/harness.go`
- **ensureBucket()** (10 connections) — `test/perf/client.go`
- **memory_test.go** (10 connections) — `test/perf/memory_test.go`
- **TestUploadPathComparison()** (10 connections) — `test/perf/uploadpath_test.go`
- **Run** (9 connections) — `test/perf/harness.go`
- **emptyBucket()** (9 connections) — `test/perf/client.go`
- **TestCryptoFloor()** (9 connections) — `test/perf/cryptofloor_test.go`
- **Reps()** (9 connections) — `test/perf/harness.go`
- **SetStatus()** (9 connections) — `test/perf/harness.go`
- **report.go** (9 connections) — `test/perf/report.go`
- **renderReport()** (9 connections) — `test/perf/report.go`
- **client.go** (8 connections) — `test/perf/client.go`
- **legsFor()** (8 connections) — `test/perf/client.go`
- **Emit()** (8 connections) — `test/perf/harness.go`
- **TestUnwrapMicrobenchmark()** (8 connections) — `test/perf/unwrap_test.go`
- **net/http.Client** (7 connections)
- **renderPlainSection()** (7 connections) — `test/perf/report.go`
- *... and 70 more nodes in this community*

## Relationships

- [Mock Backend Helpers](Mock_Backend_Helpers.md) (10 shared connections)
- [Config Env Expansion](Config_Env_Expansion.md) (10 shared connections)
- [Velero E2E Suite](Velero_E2E_Suite.md) (5 shared connections)
- [360-Degree Singlepart Tests](360-Degree_Singlepart_Tests.md) (4 shared connections)
- [AES KEK Provider](AES_KEK_Provider.md) (2 shared connections)
- [MinIO Test Helper](MinIO_Test_Helper.md) (2 shared connections)
- [Segment Codec Core](Segment_Codec_Core.md) (1 shared connections)
- [Chunked Upload Tests](Chunked_Upload_Tests.md) (1 shared connections)
- [Segment Codec Tests](Segment_Codec_Tests.md) (1 shared connections)

## Source Files

- `test/e2e/velero/e2e_test.go`
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

- EXTRACTED: 211 (78%)
- INFERRED: 59 (22%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*