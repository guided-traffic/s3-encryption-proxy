# Monitoring HTTP Server

> 31 nodes · cohesion 0.12

## Key Concepts

- **NewServer()** (19 connections) — `internal/monitoring/server.go`
- **monitoring/server_coverage_test.go** (15 connections) — `internal/monitoring/server_coverage_test.go`
- **Monserve()** (12 connections) — `internal/monitoring/server_coverage_test.go`
- **SetServerInfo()** (9 connections) — `internal/monitoring/metrics.go`
- **MonfreeAddr()** (6 connections) — `internal/monitoring/server_coverage_test.go`
- **TestMonMetricsEndpointExportsTheRequestMetrics()** (6 connections) — `internal/monitoring/server_coverage_test.go`
- **TestMonServerMetricsEndpoint()** (6 connections) — `internal/monitoring/server_coverage_test.go`
- **TestMonServerStatusEndpoint()** (6 connections) — `internal/monitoring/server_coverage_test.go`
- **TestMonServerStartServesAndShutsDownOnContextCancel()** (5 connections) — `internal/monitoring/server_coverage_test.go`
- **MonfailingListener** (5 connections) — `internal/monitoring/server_coverage_test.go`
- **MonfailingWriter** (5 connections) — `internal/monitoring/server_coverage_test.go`
- **.Header()** (5 connections) — `internal/monitoring/server_coverage_test.go`
- **Server** (5 connections) — `internal/monitoring/server.go`
- **TestMonServerEndpointsSurviveWriteFailures()** (4 connections) — `internal/monitoring/server_coverage_test.go`
- **TestMonServerLivenessEndpoint()** (4 connections) — `internal/monitoring/server_coverage_test.go`
- **TestMonServerNeverServesPprof()** (4 connections) — `internal/monitoring/server_coverage_test.go`
- **TestMonServerNoLongerServesHealthOrInfo()** (4 connections) — `internal/monitoring/server_coverage_test.go`
- **TestMonServerStartLogsListenFailure()** (4 connections) — `internal/monitoring/server_coverage_test.go`
- **.Close()** (4 connections) — `internal/monitoring/server_coverage_test.go`
- **net/http.Server** (3 connections)
- **monitoring/server.go** (3 connections) — `internal/monitoring/server.go`
- **TestMonNewServerConfiguration()** (3 connections) — `internal/monitoring/server_coverage_test.go`
- **TestMonServerStartReportsShutdownFailure()** (3 connections) — `internal/monitoring/server_coverage_test.go`
- **sync/atomic.Bool** (2 connections)
- **Config** (2 connections) — `internal/monitoring/server.go`
- *... and 6 more nodes in this community*

## Relationships

- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (14 shared connections)
- [Monitoring Status Endpoint](Monitoring_Status_Endpoint.md) (5 shared connections)
- [Pprof](Pprof.md) (3 shared connections)
- [Metrics](Metrics.md) (3 shared connections)
- [Main](Main.md) (2 shared connections)
- [S3 Method Error Mapping Tests](S3_Method_Error_Mapping_Tests.md) (2 shared connections)
- [Server](Server.md) (1 shared connections)
- [Types](Types.md) (1 shared connections)
- [DeleteObjects Handler Tests](DeleteObjects_Handler_Tests.md) (1 shared connections)
- [Backend Call Observation](Backend_Call_Observation.md) (1 shared connections)
- [HTTP Middleware Coverage Tests](HTTP_Middleware_Coverage_Tests.md) (1 shared connections)
- [Multipart Handler Constructors](Multipart_Handler_Constructors.md) (1 shared connections)

## Source Files

- `internal/monitoring/metrics.go`
- `internal/monitoring/server.go`
- `internal/monitoring/server_coverage_test.go`

## Audit Trail

- EXTRACTED: 69 (73%)
- INFERRED: 25 (27%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*