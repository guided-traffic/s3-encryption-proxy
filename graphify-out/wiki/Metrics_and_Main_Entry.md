# Metrics and Main Entry

> 19 nodes · cohesion 0.15

## Key Concepts

- **runProxy()** (8 connections) — `cmd/s3-encryption-proxy/main.go`
- **MondefaultMetric()** (7 connections) — `internal/monitoring/metrics_coverage_test.go`
- **metrics_coverage_test.go** (6 connections) — `internal/monitoring/metrics_coverage_test.go`
- **MongatherMetric()** (6 connections) — `internal/monitoring/metrics_coverage_test.go`
- **s3-encryption-proxy/main.go** (4 connections) — `cmd/s3-encryption-proxy/main.go`
- **TestMonSetLicenseInfo()** (4 connections) — `internal/monitoring/metrics_coverage_test.go`
- **TestMonSetServerInfo()** (4 connections) — `internal/monitoring/metrics_coverage_test.go`
- **SetServerInfo()** (4 connections) — `internal/monitoring/metrics.go`
- **MonmetricValue** (4 connections) — `internal/monitoring/metrics_coverage_test.go`
- **metrics.go** (3 connections) — `internal/monitoring/metrics.go`
- **TestMonGetKubernetesLabels()** (3 connections) — `internal/monitoring/metrics_coverage_test.go`
- **getKubernetesLabels()** (3 connections) — `internal/monitoring/metrics.go`
- **SetLicenseInfo()** (3 connections) — `internal/monitoring/metrics.go`
- **initConfig()** (2 connections) — `cmd/s3-encryption-proxy/main.go`
- **init()** (1 connections) — `cmd/s3-encryption-proxy/main.go`
- **main()** (1 connections) — `cmd/s3-encryption-proxy/main.go`
- **github.com/prometheus/client_golang/prometheus.Gatherer** (1 connections)
- **github.com/prometheus/client_golang/prometheus.Labels** (1 connections)
- **github.com/spf13/cobra.Command** (1 connections)

## Relationships

- [Config Env Expansion](Config_Env_Expansion.md) (5 shared connections)
- [Monitoring Middleware](Monitoring_Middleware.md) (3 shared connections)
- [Config Loading Tests](Config_Loading_Tests.md) (2 shared connections)
- [Monitoring Server](Monitoring_Server.md) (2 shared connections)
- [Proxy Server Tests](Proxy_Server_Tests.md) (1 shared connections)
- [pprof Listener](pprof_Listener.md) (1 shared connections)

## Source Files

- `cmd/s3-encryption-proxy/main.go`
- `internal/monitoring/metrics.go`
- `internal/monitoring/metrics_coverage_test.go`

## Audit Trail

- EXTRACTED: 34 (85%)
- INFERRED: 6 (15%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*