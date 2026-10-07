# Metrics

> 19 nodes · cohesion 0.18

## Key Concepts

- **MondefaultMetric()** (16 connections) — `internal/monitoring/metrics_coverage_test.go`
- **metrics_coverage_test.go** (8 connections) — `internal/monitoring/metrics_coverage_test.go`
- **Gatherer()** (8 connections) — `internal/monitoring/metrics.go`
- **SetLicenseInfo()** (8 connections) — `internal/monitoring/metrics.go`
- **metrics.go** (7 connections) — `internal/monitoring/metrics.go`
- **MongatherMetric()** (6 connections) — `internal/monitoring/metrics_coverage_test.go`
- **SetServerInfo()** (6 connections) — `internal/monitoring/metrics.go`
- **TestMonLicenseInfoCarriesNoLicenseeIdentity()** (4 connections) — `internal/monitoring/metrics_coverage_test.go`
- **TestMonSetLicenseInfo()** (4 connections) — `internal/monitoring/metrics_coverage_test.go`
- **TestMonSetServerInfo()** (4 connections) — `internal/monitoring/metrics_coverage_test.go`
- **MonmetricValue** (4 connections) — `internal/monitoring/metrics_coverage_test.go`
- **TestMonGetKubernetesLabels()** (3 connections) — `internal/monitoring/metrics_coverage_test.go`
- **TestMonLicenseDaysRemainingIsGone()** (3 connections) — `internal/monitoring/metrics_coverage_test.go`
- **getKubernetesLabels()** (3 connections) — `internal/monitoring/metrics.go`
- **github.com/prometheus/client_golang/prometheus.Gatherer** (2 connections)
- **setStatusBuild()** (2 connections) — `internal/monitoring/status.go`
- **setStatusLicense()** (2 connections) — `internal/monitoring/status.go`
- **github.com/prometheus/client_golang/prometheus.Labels** (1 connections)
- **init()** (1 connections) — `internal/monitoring/metrics.go`

## Relationships

- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (7 shared connections)
- [Backend Call Observation](Backend_Call_Observation.md) (7 shared connections)
- [Monitoring Status Endpoint](Monitoring_Status_Endpoint.md) (6 shared connections)
- [Monitoring Middleware Tests](Monitoring_Middleware_Tests.md) (4 shared connections)
- [Monitoring Dashboard Contract](Monitoring_Dashboard_Contract.md) (3 shared connections)
- [Main](Main.md) (2 shared connections)
- [Object Response Header Helpers](Object_Response_Header_Helpers.md) (1 shared connections)
- [ADR Web: Auth, Checksums, Config](ADR_Web-_Auth,_Checksums,_Config.md) (1 shared connections)
- [Monitoring HTTP Server](Monitoring_HTTP_Server.md) (1 shared connections)

## Source Files

- `internal/monitoring/metrics.go`
- `internal/monitoring/metrics_coverage_test.go`
- `internal/monitoring/status.go`

## Audit Trail

- EXTRACTED: 34 (55%)
- INFERRED: 28 (45%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*