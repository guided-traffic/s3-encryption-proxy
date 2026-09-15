# Pprof

> 9 nodes · cohesion 0.33

## Key Concepts

- **NewPprofServer()** (7 connections) — `internal/monitoring/pprof.go`
- **PprofServer** (5 connections) — `internal/monitoring/pprof.go`
- **pprof_coverage_test.go** (4 connections) — `internal/monitoring/pprof_coverage_test.go`
- **TestPprofServerServesOnlyProfiling()** (4 connections) — `internal/monitoring/pprof_coverage_test.go`
- **TestPprofServerStartServesAndShutsDownOnContextCancel()** (4 connections) — `internal/monitoring/pprof_coverage_test.go`
- **TestPprofNewServerConfiguration()** (3 connections) — `internal/monitoring/pprof_coverage_test.go`
- **TestPprofServerReportsItsFailures()** (3 connections) — `internal/monitoring/pprof_coverage_test.go`
- **pprof.go** (2 connections) — `internal/monitoring/pprof.go`
- **.Start()** (2 connections) — `internal/monitoring/pprof.go`

## Relationships

- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (4 shared connections)
- [Monitoring HTTP Server](Monitoring_HTTP_Server.md) (3 shared connections)
- [Main](Main.md) (1 shared connections)
- [Multipart Handler Constructors](Multipart_Handler_Constructors.md) (1 shared connections)
- [MockS3Backend Bucket Operations](MockS3Backend_Bucket_Operations.md) (1 shared connections)

## Source Files

- `internal/monitoring/pprof.go`
- `internal/monitoring/pprof_coverage_test.go`

## Audit Trail

- EXTRACTED: 16 (73%)
- INFERRED: 6 (27%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*