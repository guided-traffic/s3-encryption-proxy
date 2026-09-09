# Monitoring HTTP Server

> 25 nodes · cohesion 0.16

## Key Concepts

- **monitoring/server_coverage_test.go** (14 connections) — `internal/monitoring/server_coverage_test.go`
- **NewServer()** (14 connections) — `internal/monitoring/server.go`
- **Monserve()** (9 connections) — `internal/monitoring/server_coverage_test.go`
- **MonfreeAddr()** (7 connections) — `internal/monitoring/server_coverage_test.go`
- **TestMonServerMetricsEndpoint()** (6 connections) — `internal/monitoring/server_coverage_test.go`
- **TestMonServerInfoEndpoint()** (5 connections) — `internal/monitoring/server_coverage_test.go`
- **TestMonServerStartServesAndShutsDownOnContextCancel()** (5 connections) — `internal/monitoring/server_coverage_test.go`
- **TestMonServerStop()** (5 connections) — `internal/monitoring/server_coverage_test.go`
- **MonfailingListener** (5 connections) — `internal/monitoring/server_coverage_test.go`
- **.Close()** (5 connections) — `internal/monitoring/server_coverage_test.go`
- **MonfailingWriter** (5 connections) — `internal/monitoring/server_coverage_test.go`
- **.Header()** (5 connections) — `internal/monitoring/server_coverage_test.go`
- **TestMonServerEndpointsSurviveWriteFailures()** (4 connections) — `internal/monitoring/server_coverage_test.go`
- **TestMonServerHealthEndpoint()** (4 connections) — `internal/monitoring/server_coverage_test.go`
- **TestMonServerNeverServesPprof()** (4 connections) — `internal/monitoring/server_coverage_test.go`
- **TestMonServerStartLogsListenFailure()** (4 connections) — `internal/monitoring/server_coverage_test.go`
- **monitoring/server.go** (3 connections) — `internal/monitoring/server.go`
- **TestMonNewServerConfiguration()** (3 connections) — `internal/monitoring/server_coverage_test.go`
- **TestMonServerStartReportsShutdownFailure()** (3 connections) — `internal/monitoring/server_coverage_test.go`
- **Config** (2 connections) — `internal/monitoring/server.go`
- **.Accept()** (2 connections) — `internal/monitoring/server_coverage_test.go`
- **net.Listener** (1 connections)
- **Server** (1 connections)
- **.Write()** (1 connections) — `internal/monitoring/server_coverage_test.go`
- **.WriteHeader()** (1 connections) — `internal/monitoring/server_coverage_test.go`

## Relationships

- [Config Accessor Tests](Config_Accessor_Tests.md) (12 shared connections)
- [pprof Profiling Server](pprof_Profiling_Server.md) (5 shared connections)
- [Object Header Conformance Tests](Object_Header_Conformance_Tests.md) (2 shared connections)
- [DeleteObjects Handler Tests](DeleteObjects_Handler_Tests.md) (1 shared connections)
- [Monitoring Metric Recording](Monitoring_Metric_Recording.md) (1 shared connections)
- [Main Entrypoint Call Graph](Main_Entrypoint_Call_Graph.md) (1 shared connections)
- [License Claims Validation](License_Claims_Validation.md) (1 shared connections)
- [Monitoring Middleware Tests](Monitoring_Middleware_Tests.md) (1 shared connections)

## Source Files

- `internal/monitoring/server.go`
- `internal/monitoring/server_coverage_test.go`

## Audit Trail

- EXTRACTED: 57 (80%)
- INFERRED: 14 (20%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*