# Logging Response Writer

> 9 nodes · cohesion 0.22

## Key Concepts

- **responseWriter** (7 connections) — `internal/proxy/middleware/logging.go`
- **MonNotAFlusher** (4 connections) — `internal/monitoring/middleware_coverage_test.go`
- **.Flush()** (2 connections) — `internal/proxy/middleware/logging.go`
- **.FlushError()** (2 connections) — `internal/proxy/middleware/logging.go`
- **.Unwrap()** (2 connections) — `internal/proxy/middleware/logging.go`
- **.Header()** (2 connections) — `internal/monitoring/middleware_coverage_test.go`
- **.WriteHeader()** (1 connections) — `internal/proxy/middleware/logging.go`
- **.Write()** (1 connections) — `internal/monitoring/middleware_coverage_test.go`
- **.WriteHeader()** (1 connections) — `internal/monitoring/middleware_coverage_test.go`

## Relationships

- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (2 shared connections)
- [Monitoring Middleware Tests](Monitoring_Middleware_Tests.md) (2 shared connections)
- [CORS Logging Tracking Middleware](CORS_Logging_Tracking_Middleware.md) (1 shared connections)
- [Object Header Conformance Tests](Object_Header_Conformance_Tests.md) (1 shared connections)

## Source Files

- `internal/monitoring/middleware_coverage_test.go`
- `internal/proxy/middleware/logging.go`

## Audit Trail

- EXTRACTED: 14 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*