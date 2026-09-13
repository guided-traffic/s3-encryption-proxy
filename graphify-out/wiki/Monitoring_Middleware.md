# Monitoring Middleware

> 20 nodes · cohesion 0.17

## Key Concepts

- **middleware_coverage_test.go** (11 connections) — `internal/monitoring/middleware_coverage_test.go`
- **MonrequestMetric()** (7 connections) — `internal/monitoring/middleware_coverage_test.go`
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
- **.FlushError()** (3 connections) — `internal/monitoring/middleware_coverage_test.go`
- **.Header()** (2 connections) — `internal/monitoring/middleware_coverage_test.go`
- **.Header()** (2 connections) — `internal/monitoring/middleware_coverage_test.go`
- **.Flush()** (1 connections) — `internal/monitoring/middleware_coverage_test.go`
- **.Write()** (1 connections) — `internal/monitoring/middleware_coverage_test.go`
- **.WriteHeader()** (1 connections) — `internal/monitoring/middleware_coverage_test.go`

## Relationships

- [Config Env Expansion](Config_Env_Expansion.md) (8 shared connections)
- [Response Writer Hijacking](Response_Writer_Hijacking.md) (5 shared connections)
- [Metrics and Main Entry](Metrics_and_Main_Entry.md) (3 shared connections)
- [Object Header Conformance](Object_Header_Conformance.md) (2 shared connections)
- [Monitoring Flusher Fallback](Monitoring_Flusher_Fallback.md) (1 shared connections)
- [CORS Middleware](CORS_Middleware.md) (1 shared connections)

## Source Files

- `internal/monitoring/middleware.go`
- `internal/monitoring/middleware_coverage_test.go`

## Audit Trail

- EXTRACTED: 49 (92%)
- INFERRED: 4 (8%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*