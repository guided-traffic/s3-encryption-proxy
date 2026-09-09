# Prometheus Metrics

> 25 nodes · cohesion 0.15

## Key Concepts

- **MondefaultMetric()** (16 connections) — `internal/monitoring/metrics_coverage_test.go`
- **metrics_coverage_test.go** (13 connections) — `internal/monitoring/metrics_coverage_test.go`
- **metrics.go** (9 connections) — `internal/monitoring/metrics.go`
- **MongatherMetric()** (6 connections) — `internal/monitoring/metrics_coverage_test.go`
- **RecordHMACOperation()** (5 connections) — `internal/monitoring/metrics.go`
- **TestMonRecordDownloadThroughput()** (4 connections) — `internal/monitoring/metrics_coverage_test.go`
- **TestMonRecordHMACOperation()** (4 connections) — `internal/monitoring/metrics_coverage_test.go`
- **TestMonRecordHMACOperationSkipsThroughput()** (4 connections) — `internal/monitoring/metrics_coverage_test.go`
- **TestMonRecordProxyPerformance()** (4 connections) — `internal/monitoring/metrics_coverage_test.go`
- **TestMonSetLicenseInfo()** (4 connections) — `internal/monitoring/metrics_coverage_test.go`
- **TestMonSetProviderInfo()** (4 connections) — `internal/monitoring/metrics_coverage_test.go`
- **TestMonSetServerInfo()** (4 connections) — `internal/monitoring/metrics_coverage_test.go`
- **getObjectSizeCategory()** (4 connections) — `internal/monitoring/metrics.go`
- **prometheusFmtBool()** (4 connections) — `internal/monitoring/metrics.go`
- **RecordDownloadThroughput()** (4 connections) — `internal/monitoring/metrics.go`
- **RecordProxyPerformance()** (4 connections) — `internal/monitoring/metrics.go`
- **MonmetricValue** (4 connections) — `internal/monitoring/metrics_coverage_test.go`
- **TestMonGetKubernetesLabels()** (3 connections) — `internal/monitoring/metrics_coverage_test.go`
- **TestMonGetObjectSizeCategory()** (3 connections) — `internal/monitoring/metrics_coverage_test.go`
- **TestMonPrometheusFmtBool()** (3 connections) — `internal/monitoring/metrics_coverage_test.go`
- **getKubernetesLabels()** (3 connections) — `internal/monitoring/metrics.go`
- **SetProviderInfo()** (3 connections) — `internal/monitoring/metrics.go`
- **SetServerInfo()** (3 connections) — `internal/monitoring/metrics.go`
- **github.com/prometheus/client_golang/prometheus.Gatherer** (1 connections)
- **github.com/prometheus/client_golang/prometheus.Labels** (1 connections)

## Relationships

- [Config Accessor Tests](Config_Accessor_Tests.md) (12 shared connections)
- [Monitoring Middleware Tests](Monitoring_Middleware_Tests.md) (4 shared connections)
- [Main Entrypoint Call Graph](Main_Entrypoint_Call_Graph.md) (3 shared connections)
- [Monitoring Metric Recording](Monitoring_Metric_Recording.md) (3 shared connections)
- [Velero E2E Suite](Velero_E2E_Suite.md) (3 shared connections)

## Source Files

- `internal/monitoring/metrics.go`
- `internal/monitoring/metrics_coverage_test.go`

## Audit Trail

- EXTRACTED: 55 (77%)
- INFERRED: 16 (23%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*