# Monitoring Middleware Tests

> 24 nodes · cohesion 0.13

## Key Concepts

- **middleware_coverage_test.go** (11 connections) — `internal/monitoring/middleware_coverage_test.go`
- **MonrequestMetric()** (8 connections) — `internal/monitoring/middleware_coverage_test.go`
- **MonFlushErrorWriter** (6 connections) — `internal/monitoring/middleware_coverage_test.go`
- **MonHijackWriter** (6 connections) — `internal/monitoring/middleware_coverage_test.go`
- **TestMonHTTPMiddlewareRecordsRoutedRequest()** (5 connections) — `internal/monitoring/middleware_coverage_test.go`
- **TestMonHTTPMiddlewareTracksActiveConnections()** (5 connections) — `internal/monitoring/middleware_coverage_test.go`
- **TestMonHTTPMiddlewareUnknownEndpoint()** (5 connections) — `internal/monitoring/middleware_coverage_test.go`
- **TestMonResponseWriterForwardsToTheLiveWriter()** (5 connections) — `internal/monitoring/middleware_coverage_test.go`
- **.Write()** (5 connections) — `internal/monitoring/middleware_coverage_test.go`
- **.WriteHeader()** (5 connections) — `internal/monitoring/middleware_coverage_test.go`
- **TestMonHTTPMiddlewareDefaultsToStatus200()** (4 connections) — `internal/monitoring/middleware_coverage_test.go`
- **TestMonResponseWriterCapturesStatusCode()** (4 connections) — `internal/monitoring/middleware_coverage_test.go`
- **TestMonResponseWriterKeepsTheWriterCapabilities()** (4 connections) — `internal/monitoring/middleware_coverage_test.go`
- **HTTPMiddleware()** (4 connections) — `internal/monitoring/middleware.go`
- **MonNotAFlusher** (4 connections) — `internal/monitoring/middleware_coverage_test.go`
- **.FlushError()** (3 connections) — `internal/monitoring/middleware_coverage_test.go`
- **.Header()** (2 connections) — `internal/monitoring/middleware_coverage_test.go`
- **.Header()** (2 connections) — `internal/monitoring/middleware_coverage_test.go`
- **.Header()** (2 connections) — `internal/monitoring/middleware_coverage_test.go`
- **.Flush()** (1 connections) — `internal/monitoring/middleware_coverage_test.go`
- **.Write()** (1 connections) — `internal/monitoring/middleware_coverage_test.go`
- **.WriteHeader()** (1 connections) — `internal/monitoring/middleware_coverage_test.go`
- **.Write()** (1 connections) — `internal/monitoring/middleware_coverage_test.go`
- **.WriteHeader()** (1 connections) — `internal/monitoring/middleware_coverage_test.go`

## Relationships

- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (8 shared connections)
- [Monitoring Hijack Middleware](Monitoring_Hijack_Middleware.md) (5 shared connections)
- [Metrics](Metrics.md) (4 shared connections)
- [Integration Failing Writer Fixtures](Integration_Failing_Writer_Fixtures.md) (3 shared connections)
- [CORS Middleware and SSE-C Stripping](CORS_Middleware_and_SSE-C_Stripping.md) (1 shared connections)

## Source Files

- `internal/monitoring/middleware.go`
- `internal/monitoring/middleware_coverage_test.go`

## Audit Trail

- EXTRACTED: 53 (91%)
- INFERRED: 5 (9%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*