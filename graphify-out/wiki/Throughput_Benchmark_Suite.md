# Throughput Benchmark Suite

> 14 nodes · cohesion 0.32

## Key Concepts

- **performance_test.go** (12 connections) — `test/integration/performance-test/performance_test.go`
- **testing.B** (7 connections)
- **clearPerformanceTestBucket()** (7 connections) — `test/integration/performance-test/performance_test.go`
- **TestPerformanceComparison()** (7 connections) — `test/integration/performance-test/performance_test.go`
- **measureComparisonPerformance()** (6 connections) — `test/integration/performance-test/performance_test.go`
- **runPerformanceTest()** (6 connections) — `test/integration/performance-test/performance_test.go`
- **TestStreamingPerformance()** (6 connections) — `test/integration/performance-test/performance_test.go`
- **PerformanceResult** (5 connections) — `test/integration/performance-test/performance_test.go`
- **BenchmarkStreamingDownload()** (5 connections) — `test/integration/performance-test/performance_test.go`
- **BenchmarkStreamingUpload()** (5 connections) — `test/integration/performance-test/performance_test.go`
- **EnsureBenchmarkEnvironment()** (5 connections) — `test/integration/performance-test/performance_test.go`
- **printComparisonSummary()** (4 connections) — `test/integration/performance-test/performance_test.go`
- **ComparisonResult** (3 connections) — `test/integration/performance-test/performance_test.go`
- **cleanupBenchmarkBucket()** (3 connections) — `test/integration/performance-test/performance_test.go`

## Relationships

- [Range Read Integration Tests](Range_Read_Integration_Tests.md) (7 shared connections)
- [Config Accessor Tests](Config_Accessor_Tests.md) (6 shared connections)
- [HMAC and DEK Cache Tests](HMAC_and_DEK_Cache_Tests.md) (4 shared connections)
- [Response Copy Benchmark](Response_Copy_Benchmark.md) (2 shared connections)
- [S3 Backend Interface Types](S3_Backend_Interface_Types.md) (2 shared connections)
- [HKDF Derivation Tests](HKDF_Derivation_Tests.md) (1 shared connections)
- [Velero E2E Suite](Velero_E2E_Suite.md) (1 shared connections)

## Source Files

- `test/integration/performance-test/performance_test.go`

## Audit Trail

- EXTRACTED: 45 (87%)
- INFERRED: 7 (13%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*