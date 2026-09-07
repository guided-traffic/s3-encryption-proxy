# Monitoring Metrics Middleware

> 78 nodes · cohesion 0.04

## Key Concepts

- **MondefaultMetric()** (16 connections) — `internal/monitoring/metrics_coverage_test.go`
- **middleware_coverage_test.go** (15 connections) — `internal/monitoring/middleware_coverage_test.go`
- **responseWriter** (14 connections) — `internal/proxy/middleware/logging.go`
- **metrics_coverage_test.go** (13 connections) — `internal/monitoring/metrics_coverage_test.go`
- **HTTPMiddleware()** (13 connections) — `internal/monitoring/middleware.go`
- **TestMonResponseWriterForwardsToTheLiveWriter()** (12 connections) — `internal/monitoring/middleware_coverage_test.go`
- **metrics.go** (9 connections) — `internal/monitoring/metrics.go`
- **middleware.go** (7 connections) — `internal/monitoring/middleware.go`
- **MonrequestMetric()** (7 connections) — `internal/monitoring/middleware_coverage_test.go`
- **TestMonResponseWriterKeepsTheWriterCapabilities()** (7 connections) — `internal/monitoring/middleware_coverage_test.go`
- **responseWriter** (7 connections) — `internal/monitoring/middleware.go`
- **MonFlushErrorWriter** (6 connections) — `internal/monitoring/middleware_coverage_test.go`
- **TestMonSetLicenseInfo()** (5 connections) — `internal/monitoring/metrics_coverage_test.go`
- **getObjectSizeCategory()** (5 connections) — `internal/monitoring/metrics.go`
- **TestMonHTTPMiddlewareRecordsRoutedRequest()** (5 connections) — `internal/monitoring/middleware_coverage_test.go`
- **TestMonHTTPMiddlewareUnknownEndpoint()** (5 connections) — `internal/monitoring/middleware_coverage_test.go`
- **MonHijackWriter** (5 connections) — `internal/monitoring/middleware_coverage_test.go`
- **.Write()** (5 connections) — `internal/monitoring/middleware_coverage_test.go`
- **.WriteHeader()** (5 connections) — `internal/monitoring/middleware_coverage_test.go`
- **MongatherMetric()** (4 connections) — `internal/monitoring/metrics_coverage_test.go`
- **TestMonGetKubernetesLabels()** (4 connections) — `internal/monitoring/metrics_coverage_test.go`
- **TestMonRecordHMACOperationSkipsThroughput()** (4 connections) — `internal/monitoring/metrics_coverage_test.go`
- **TestMonSetProviderInfo()** (4 connections) — `internal/monitoring/metrics_coverage_test.go`
- **prometheusFmtBool()** (4 connections) — `internal/monitoring/metrics.go`
- **RecordHMACOperation()** (4 connections) — `internal/monitoring/metrics.go`
- *... and 53 more nodes in this community*

## Relationships

- No strong cross-community connections detected

## Source Files

- `docs/tickets/010-tier2/proxy-cpu-top20.txt`
- `internal/monitoring/metrics.go`
- `internal/monitoring/metrics_coverage_test.go`
- `internal/monitoring/middleware.go`
- `internal/monitoring/middleware_coverage_test.go`
- `internal/proxy/middleware/logging.go`

## Audit Trail

- EXTRACTED: 229 (74%)
- INFERRED: 82 (26%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [[index]] to navigate.*