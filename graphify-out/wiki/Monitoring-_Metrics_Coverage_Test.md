# Monitoring: Metrics Coverage Test

> 11 nodes · cohesion 0.22

## Key Concepts

- **MonrequestMetric()** (8 connections) — `internal/monitoring/middleware_coverage_test.go`
- **Gatherer()** (7 connections) — `internal/monitoring/metrics.go`
- **MongatherMetric()** (6 connections) — `internal/monitoring/metrics_coverage_test.go`
- **TestMonHTTPMiddlewareTracksActiveConnections()** (4 connections) — `internal/monitoring/middleware_coverage_test.go`
- **TestMonHTTPMiddlewareUnknownEndpoint()** (4 connections) — `internal/monitoring/middleware_coverage_test.go`
- **HTTPMiddleware()** (4 connections) — `internal/monitoring/middleware.go`
- **MonmetricValue** (4 connections) — `internal/monitoring/metrics_coverage_test.go`
- **TestMonNoLicenseSeriesIsExported()** (3 connections) — `internal/monitoring/metrics_coverage_test.go`
- **TestMonHTTPMiddlewareDefaultsToStatus200()** (3 connections) — `internal/monitoring/middleware_coverage_test.go`
- **TestMonHTTPMiddlewareRecordsRoutedRequest()** (3 connections) — `internal/monitoring/middleware_coverage_test.go`
- **github.com/prometheus/client_golang/prometheus.Gatherer** (2 connections)

## Relationships

- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (10 shared connections)
- [Shutdown and Test Contexts](Shutdown_and_Test_Contexts.md) (8 shared connections)
- [Monitoring: Backend Test](Monitoring-_Backend_Test.md) (4 shared connections)
- [Monitoring: Server Coverage Test](Monitoring-_Server_Coverage_Test.md) (1 shared connections)
- [CORS and Middleware](CORS_and_Middleware.md) (1 shared connections)

## Source Files

- `internal/monitoring/metrics.go`
- `internal/monitoring/metrics_coverage_test.go`
- `internal/monitoring/middleware.go`
- `internal/monitoring/middleware_coverage_test.go`

## Audit Trail

- EXTRACTED: 27 (75%)
- INFERRED: 9 (25%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*