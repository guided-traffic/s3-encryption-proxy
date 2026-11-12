# Monitoring: Server Coverage Test

> 23 nodes · cohesion 0.17

## Key Concepts

- **monitoring/server_coverage_test.go** (35 connections) — `internal/monitoring/server_coverage_test.go`
- **NewServer()** (19 connections) — `internal/monitoring/server.go`
- **Monserve()** (12 connections) — `internal/monitoring/server_coverage_test.go`
- **SetServerInfo()** (9 connections) — `internal/monitoring/metrics.go`
- **TestMonMetricsEndpointExportsTheRequestMetrics()** (6 connections) — `internal/monitoring/server_coverage_test.go`
- **MonfreeAddr()** (5 connections) — `internal/monitoring/server_coverage_test.go`
- **TestMonServerMetricsEndpoint()** (5 connections) — `internal/monitoring/server_coverage_test.go`
- **TestMonServerStatusEndpoint()** (5 connections) — `internal/monitoring/server_coverage_test.go`
- **MonfailingWriter** (5 connections) — `internal/monitoring/server_coverage_test.go`
- **TestMonSetServerInfo()** (4 connections) — `internal/monitoring/metrics_coverage_test.go`
- **TestMonServerEndpointsSurviveWriteFailures()** (4 connections) — `internal/monitoring/server_coverage_test.go`
- **TestMonServerLivenessEndpoint()** (4 connections) — `internal/monitoring/server_coverage_test.go`
- **TestMonServerNeverServesPprof()** (4 connections) — `internal/monitoring/server_coverage_test.go`
- **TestMonServerNoLongerServesHealthOrInfo()** (4 connections) — `internal/monitoring/server_coverage_test.go`
- **TestMonServerStartServesAndShutsDownOnContextCancel()** (4 connections) — `internal/monitoring/server_coverage_test.go`
- **TestMonNewServerConfiguration()** (3 connections) — `internal/monitoring/server_coverage_test.go`
- **TestMonServerStartLogsListenFailure()** (3 connections) — `internal/monitoring/server_coverage_test.go`
- **TestMonServerStartReportsShutdownFailure()** (3 connections) — `internal/monitoring/server_coverage_test.go`
- **.Header()** (3 connections) — `internal/monitoring/server_coverage_test.go`
- **Config** (2 connections) — `internal/monitoring/server.go`
- **Server** (1 connections)
- **.Write()** (1 connections) — `internal/monitoring/server_coverage_test.go`
- **.WriteHeader()** (1 connections) — `internal/monitoring/server_coverage_test.go`

## Relationships

- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (24 shared connections)
- [Shutdown and Test Contexts](Shutdown_and_Test_Contexts.md) (15 shared connections)
- [Dataencryption: Segmented Gcm Io](Dataencryption-_Segmented_Gcm_Io.md) (5 shared connections)
- [Monitoring: Status](Monitoring-_Status.md) (5 shared connections)
- [Monitoring: Backend Test](Monitoring-_Backend_Test.md) (2 shared connections)
- [Request Middleware Plumbing](Request_Middleware_Plumbing.md) (2 shared connections)
- [Misc](Misc.md) (1 shared connections)
- [Misc (19)](Misc_19.md) (1 shared connections)
- [Monitoring: Metrics Coverage Test](Monitoring-_Metrics_Coverage_Test.md) (1 shared connections)

## Source Files

- `internal/monitoring/metrics.go`
- `internal/monitoring/metrics_coverage_test.go`
- `internal/monitoring/server.go`
- `internal/monitoring/server_coverage_test.go`

## Audit Trail

- EXTRACTED: 73 (74%)
- INFERRED: 26 (26%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*