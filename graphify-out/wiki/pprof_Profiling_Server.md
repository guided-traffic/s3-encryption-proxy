# pprof Profiling Server

> 15 nodes · cohesion 0.18

## Key Concepts

- **NewPprofServer()** (8 connections) — `internal/monitoring/pprof.go`
- **PprofServer** (6 connections) — `internal/monitoring/pprof.go`
- **Server** (6 connections) — `internal/monitoring/server.go`
- **pprof_coverage_test.go** (5 connections) — `internal/monitoring/pprof_coverage_test.go`
- **TestPprofServerServesOnlyProfiling()** (4 connections) — `internal/monitoring/pprof_coverage_test.go`
- **TestPprofServerStartServesAndShutsDownOnContextCancel()** (4 connections) — `internal/monitoring/pprof_coverage_test.go`
- **TestPprofServerStopClosesTheListener()** (4 connections) — `internal/monitoring/pprof_coverage_test.go`
- **net/http.Server** (3 connections)
- **TestPprofNewServerConfiguration()** (3 connections) — `internal/monitoring/pprof_coverage_test.go`
- **TestPprofServerReportsItsFailures()** (3 connections) — `internal/monitoring/pprof_coverage_test.go`
- **pprof.go** (2 connections) — `internal/monitoring/pprof.go`
- **.Start()** (2 connections) — `internal/monitoring/pprof.go`
- **.Start()** (2 connections) — `internal/monitoring/server.go`
- **.Stop()** (1 connections) — `internal/monitoring/pprof.go`
- **.Stop()** (1 connections) — `internal/monitoring/server.go`

## Relationships

- [Config Accessor Tests](Config_Accessor_Tests.md) (5 shared connections)
- [Monitoring HTTP Server](Monitoring_HTTP_Server.md) (5 shared connections)
- [Multipart Handler Construction](Multipart_Handler_Construction.md) (2 shared connections)
- [S3 Backend Interface Types](S3_Backend_Interface_Types.md) (2 shared connections)
- [CORS Logging Tracking Middleware](CORS_Logging_Tracking_Middleware.md) (1 shared connections)
- [Main Entrypoint Call Graph](Main_Entrypoint_Call_Graph.md) (1 shared connections)

## Source Files

- `internal/monitoring/pprof.go`
- `internal/monitoring/pprof_coverage_test.go`
- `internal/monitoring/server.go`

## Audit Trail

- EXTRACTED: 27 (77%)
- INFERRED: 8 (23%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*