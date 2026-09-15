# Performance

> 17 nodes · cohesion 0.27

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
- **weightedLeg** (3 connections) — `test/integration/performance-test/performance_test.go`
- **summaryPath()** (2 connections) — `test/integration/performance-test/performance_test.go`

## Relationships

- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (7 shared connections)
- [Multipart Conformance Suite](Multipart_Conformance_Suite.md) (4 shared connections)
- [Large Multipart and DEK Cache Tests](Large_Multipart_and_DEK_Cache_Tests.md) (3 shared connections)
- [Ranged Read and Passthrough Tests](Ranged_Read_and_Passthrough_Tests.md) (3 shared connections)
- [Segmented GCM Reader and Writer](Segmented_GCM_Reader_and_Writer.md) (2 shared connections)
- [Shutdown](Shutdown.md) (2 shared connections)
- [MockS3Backend Bucket Operations](MockS3Backend_Bucket_Operations.md) (2 shared connections)
- [Checksum](Checksum.md) (1 shared connections)
- [Crc64nvme](Crc64nvme.md) (1 shared connections)
- [Checksum Verifier Tests](Checksum_Verifier_Tests.md) (1 shared connections)

## Source Files

- `test/integration/performance-test/performance_test.go`

## Audit Trail

- EXTRACTED: 56 (89%)
- INFERRED: 7 (11%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*