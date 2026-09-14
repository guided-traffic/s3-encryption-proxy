# pprof Listener

> 12 nodes · cohesion 0.23

## Key Concepts

- **NewPprofServer()** (7 connections) — `internal/monitoring/pprof.go`
- **PprofServer** (5 connections) — `internal/monitoring/pprof.go`
- **Server** (5 connections) — `internal/monitoring/server.go`
- **pprof_coverage_test.go** (4 connections) — `internal/monitoring/pprof_coverage_test.go`
- **TestPprofServerServesOnlyProfiling()** (4 connections) — `internal/monitoring/pprof_coverage_test.go`
- **TestPprofServerStartServesAndShutsDownOnContextCancel()** (4 connections) — `internal/monitoring/pprof_coverage_test.go`
- **net/http.Server** (3 connections)
- **TestPprofNewServerConfiguration()** (3 connections) — `internal/monitoring/pprof_coverage_test.go`
- **TestPprofServerReportsItsFailures()** (3 connections) — `internal/monitoring/pprof_coverage_test.go`
- **pprof.go** (2 connections) — `internal/monitoring/pprof.go`
- **.Start()** (2 connections) — `internal/monitoring/pprof.go`
- **.Start()** (2 connections) — `internal/monitoring/server.go`

## Relationships

- [Config Env Expansion](Config_Env_Expansion.md) (4 shared connections)
- [Monitoring Server](Monitoring_Server.md) (4 shared connections)
- [Multipart Handler](Multipart_Handler.md) (2 shared connections)
- [Mock Backend Helpers](Mock_Backend_Helpers.md) (2 shared connections)
- [Request Tracking Middleware](Request_Tracking_Middleware.md) (1 shared connections)
- [Metrics and Main Entry](Metrics_and_Main_Entry.md) (1 shared connections)

## Source Files

- `internal/monitoring/pprof.go`
- `internal/monitoring/pprof_coverage_test.go`
- `internal/monitoring/server.go`

## Audit Trail

- EXTRACTED: 23 (79%)
- INFERRED: 6 (21%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*