# Monitoring Middleware Tests

> 25 nodes · cohesion 0.13

## Key Concepts

- **middleware_coverage_test.go** (11 connections) — `internal/monitoring/middleware_coverage_test.go`
- **MonrequestMetric()** (8 connections) — `internal/monitoring/middleware_coverage_test.go`
- **MonFlushErrorWriter** (6 connections) — `internal/monitoring/middleware_coverage_test.go`
- **MonHijackWriter** (6 connections) — `internal/monitoring/middleware_coverage_test.go`
- **TestMonHTTPMiddlewareRecordsRoutedRequest()** (5 connections) — `internal/monitoring/middleware_coverage_test.go`
- **TestMonHTTPMiddlewareTracksActiveConnections()** (5 connections) — `internal/monitoring/middleware_coverage_test.go`
- **TestMonHTTPMiddlewareUnknownEndpoint()** (5 connections) — `internal/monitoring/middleware_coverage_test.go`
- **TestMonResponseWriterForwardsToTheLiveWriter()** (5 connections) — `internal/monitoring/middleware_coverage_test.go`
- **.Hijack()** (5 connections) — `internal/monitoring/middleware_coverage_test.go`
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
- [Metrics](Metrics.md) (3 shared connections)
- [S3 Method Error Mapping Tests](S3_Method_Error_Mapping_Tests.md) (3 shared connections)
- [HTTP Middleware Coverage Tests](HTTP_Middleware_Coverage_Tests.md) (3 shared connections)
- [Backend Call Observation](Backend_Call_Observation.md) (1 shared connections)
- [CORS Middleware and SSE-C Stripping](CORS_Middleware_and_SSE-C_Stripping.md) (1 shared connections)
- [Middleware](Middleware.md) (1 shared connections)

## Source Files

- `internal/monitoring/middleware.go`
- `internal/monitoring/middleware_coverage_test.go`

## Audit Trail

- EXTRACTED: 55 (92%)
- INFERRED: 5 (8%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*