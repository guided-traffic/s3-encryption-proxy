# Performance Benchmarks

> 14 nodes · cohesion 0.32

## Key Concepts

- **performance_test.go** (12 connections) — `test/integration/performance-test/performance_test.go`
- **clearPerformanceTestBucket()** (7 connections) — `test/integration/performance-test/performance_test.go`
- **TestPerformanceComparison()** (7 connections) — `test/integration/performance-test/performance_test.go`
- **testing.B** (6 connections)
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

- [Object Sub-Resource Refusals](Object_Sub-Resource_Refusals.md) (7 shared connections)
- [Config Env Expansion](Config_Env_Expansion.md) (6 shared connections)
- [360-Degree Singlepart Tests](360-Degree_Singlepart_Tests.md) (4 shared connections)
- [Copy Benchmarks](Copy_Benchmarks.md) (2 shared connections)
- [Mock Backend Helpers](Mock_Backend_Helpers.md) (2 shared connections)
- [Velero E2E Suite](Velero_E2E_Suite.md) (1 shared connections)

## Source Files

- `test/integration/performance-test/performance_test.go`

## Audit Trail

- EXTRACTED: 44 (86%)
- INFERRED: 7 (14%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*