# Metrics

> 13 nodes · cohesion 0.21

## Key Concepts

- **metrics_coverage_test.go** (8 connections) — `internal/monitoring/metrics_coverage_test.go`
- **Gatherer()** (8 connections) — `internal/monitoring/metrics.go`
- **metrics.go** (6 connections) — `internal/monitoring/metrics.go`
- **MongatherMetric()** (6 connections) — `internal/monitoring/metrics_coverage_test.go`
- **TestMonLicenseInfoCarriesNoLicenseeIdentity()** (4 connections) — `internal/monitoring/metrics_coverage_test.go`
- **TestMonSetServerInfo()** (4 connections) — `internal/monitoring/metrics_coverage_test.go`
- **MonmetricValue** (4 connections) — `internal/monitoring/metrics_coverage_test.go`
- **TestMonGetKubernetesLabels()** (3 connections) — `internal/monitoring/metrics_coverage_test.go`
- **TestMonLicenseDaysRemainingIsGone()** (3 connections) — `internal/monitoring/metrics_coverage_test.go`
- **getKubernetesLabels()** (3 connections) — `internal/monitoring/metrics.go`
- **github.com/prometheus/client_golang/prometheus.Gatherer** (2 connections)
- **github.com/prometheus/client_golang/prometheus.Labels** (1 connections)
- **init()** (1 connections) — `internal/monitoring/metrics.go`

## Relationships

- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (6 shared connections)
- [Backend Call Observation](Backend_Call_Observation.md) (5 shared connections)
- [Monitoring HTTP Server](Monitoring_HTTP_Server.md) (3 shared connections)
- [Monitoring Status Endpoint](Monitoring_Status_Endpoint.md) (3 shared connections)
- [Monitoring Middleware Tests](Monitoring_Middleware_Tests.md) (3 shared connections)
- [Response Header Helpers](Response_Header_Helpers.md) (1 shared connections)

## Source Files

- `internal/monitoring/metrics.go`
- `internal/monitoring/metrics_coverage_test.go`

## Audit Trail

- EXTRACTED: 27 (73%)
- INFERRED: 10 (27%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*