# Monitoring: Server Coverage Test

> 19 nodes · cohesion 0.16

## Key Concepts

- **NewServer()** (19 connections) — `internal/monitoring/server.go`
- **Monserve()** (12 connections) — `internal/monitoring/server_coverage_test.go`
- **runProxy()** (11 connections) — `cmd/s3-encryption-proxy/main.go`
- **SetServerInfo()** (9 connections) — `internal/monitoring/metrics.go`
- **TestMonMetricsEndpointExportsTheRequestMetrics()** (6 connections) — `internal/monitoring/server_coverage_test.go`
- **MonstatusBody()** (6 connections) — `internal/monitoring/status_test.go`
- **TestMonServerMetricsEndpoint()** (5 connections) — `internal/monitoring/server_coverage_test.go`
- **TestMonServerStatusEndpoint()** (5 connections) — `internal/monitoring/server_coverage_test.go`
- **Server** (5 connections) — `internal/monitoring/server.go`
- **TestMonServerLivenessEndpoint()** (4 connections) — `internal/monitoring/server_coverage_test.go`
- **TestMonServerNeverServesPprof()** (4 connections) — `internal/monitoring/server_coverage_test.go`
- **TestMonServerNoLongerServesHealthOrInfo()** (4 connections) — `internal/monitoring/server_coverage_test.go`
- **TestMonNewServerConfiguration()** (3 connections) — `internal/monitoring/server_coverage_test.go`
- **TestMonServerStartLogsListenFailure()** (3 connections) — `internal/monitoring/server_coverage_test.go`
- **TestMonServerStartReportsShutdownFailure()** (3 connections) — `internal/monitoring/server_coverage_test.go`
- **.Start()** (3 connections) — `internal/monitoring/server.go`
- **github.com/spf13/cobra.Command** (2 connections)
- **Config** (2 connections) — `internal/monitoring/server.go`
- **Server** (1 connections)

## Relationships

- [Shutdown and Test Contexts](Shutdown_and_Test_Contexts.md) (17 shared connections)
- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (17 shared connections)
- [Monitoring: Status](Monitoring-_Status.md) (5 shared connections)
- [Monitoring: Metrics Coverage Test](Monitoring-_Metrics_Coverage_Test.md) (2 shared connections)
- [Config: Config](Config-_Config.md) (1 shared connections)
- [Backend TLS Trust](Backend_TLS_Trust.md) (1 shared connections)
- [Config Types and Monitoring Plan](Config_Types_and_Monitoring_Plan.md) (1 shared connections)
- [Configuration Loading](Configuration_Loading.md) (1 shared connections)
- [DeleteObjects Handling](DeleteObjects_Handling.md) (1 shared connections)
- [Monitoring: Backend Test](Monitoring-_Backend_Test.md) (1 shared connections)
- [Monitoring: Server Coverage Test (2)](Monitoring-_Server_Coverage_Test_2.md) (1 shared connections)
- [Server and Listings](Server_and_Listings.md) (1 shared connections)

## Source Files

- `cmd/s3-encryption-proxy/main.go`
- `internal/monitoring/metrics.go`
- `internal/monitoring/server.go`
- `internal/monitoring/server_coverage_test.go`
- `internal/monitoring/status_test.go`

## Audit Trail

- EXTRACTED: 54 (68%)
- INFERRED: 25 (32%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*