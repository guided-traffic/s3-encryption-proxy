# Performance

> 20 nodes · cohesion 0.21

## Key Concepts

- **performance_test.go** (15 connections) — `test/integration/performance-test/performance_test.go`
- **testing.B** (8 connections)
- **clearPerformanceTestBucket()** (7 connections) — `test/integration/performance-test/performance_test.go`
- **TestPerformanceComparison()** (7 connections) — `test/integration/performance-test/performance_test.go`
- **measureComparisonPerformance()** (6 connections) — `test/integration/performance-test/performance_test.go`
- **printComparisonSummary()** (6 connections) — `test/integration/performance-test/performance_test.go`
- **runPerformanceTest()** (6 connections) — `test/integration/performance-test/performance_test.go`
- **TestStreamingPerformance()** (6 connections) — `test/integration/performance-test/performance_test.go`
- **PerformanceResult** (5 connections) — `test/integration/performance-test/performance_test.go`
- **BenchmarkStreamingDownload()** (5 connections) — `test/integration/performance-test/performance_test.go`
- **BenchmarkStreamingUpload()** (5 connections) — `test/integration/performance-test/performance_test.go`
- **EnsureBenchmarkEnvironment()** (5 connections) — `test/integration/performance-test/performance_test.go`
- **weighLeg()** (5 connections) — `test/integration/performance-test/performance_test.go`
- **writeSummary()** (5 connections) — `test/integration/performance-test/performance_test.go`
- **ComparisonResult** (4 connections) — `test/integration/performance-test/performance_test.go`
- **BenchmarkChkAlgorithms()** (3 connections) — `internal/proxy/request/checksum_test.go`
- **chkKey()** (3 connections) — `internal/proxy/request/checksum_test.go`
- **weightedLeg** (3 connections) — `test/integration/performance-test/performance_test.go`
- **chkAlgorithm** (2 connections) — `internal/proxy/request/checksum_test.go`
- **summaryPath()** (2 connections) — `test/integration/performance-test/performance_test.go`

## Relationships

- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (7 shared connections)
- [Checksum Verifier Tests](Checksum_Verifier_Tests.md) (4 shared connections)
- [Multipart Conformance Suite](Multipart_Conformance_Suite.md) (4 shared connections)
- [Streaming Integration Test Harness](Streaming_Integration_Test_Harness.md) (3 shared connections)
- [AWS-Chunked Reader Tests](AWS-Chunked_Reader_Tests.md) (3 shared connections)
- [GET Copy Benchmarks](GET_Copy_Benchmarks.md) (2 shared connections)
- [Velero E2E Backup Suite](Velero_E2E_Backup_Suite.md) (2 shared connections)
- [MockS3Backend Tagging and Policy](MockS3Backend_Tagging_and_Policy.md) (2 shared connections)
- [Crc64nvme](Crc64nvme.md) (1 shared connections)

## Source Files

- `internal/proxy/request/checksum_test.go`
- `test/integration/performance-test/performance_test.go`

## Audit Trail

- EXTRACTED: 61 (90%)
- INFERRED: 7 (10%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*