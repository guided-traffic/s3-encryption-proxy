# HTTP Middleware Tests

> 19 nodes · cohesion 0.20

## Key Concepts

- **http_middleware_coverage_test.go** (11 connections) — `internal/proxy/middleware/http_middleware_coverage_test.go`
- **MwechoHandler()** (8 connections) — `internal/proxy/middleware/http_middleware_coverage_test.go`
- **MwtestLogger()** (7 connections) — `internal/proxy/middleware/http_middleware_coverage_test.go`
- **TestMwCORSMiddleware()** (6 connections) — `internal/proxy/middleware/http_middleware_coverage_test.go`
- **TestMwRequestTracker()** (6 connections) — `internal/proxy/middleware/http_middleware_coverage_test.go`
- **MwFlushErrorWriter** (6 connections) — `internal/proxy/middleware/http_middleware_coverage_test.go`
- **MwHijackWriter** (6 connections) — `internal/proxy/middleware/http_middleware_coverage_test.go`
- **TestMwLoggerMiddleware()** (5 connections) — `internal/proxy/middleware/http_middleware_coverage_test.go`
- **TestMwResponseWriterForwardsToTheLiveWriter()** (5 connections) — `internal/proxy/middleware/http_middleware_coverage_test.go`
- **TestMwResponseWriterKeepsTheWriterCapabilities()** (5 connections) — `internal/proxy/middleware/http_middleware_coverage_test.go`
- **TestMwLoggerDefaultsToOKWithoutExplicitWriteHeader()** (4 connections) — `internal/proxy/middleware/http_middleware_coverage_test.go`
- **.Header()** (4 connections) — `internal/proxy/middleware/http_middleware_coverage_test.go`
- **.FlushError()** (3 connections) — `internal/proxy/middleware/http_middleware_coverage_test.go`
- **.Write()** (3 connections) — `internal/proxy/middleware/http_middleware_coverage_test.go`
- **.WriteHeader()** (3 connections) — `internal/proxy/middleware/http_middleware_coverage_test.go`
- **.Flush()** (2 connections) — `internal/proxy/middleware/http_middleware_coverage_test.go`
- **.Header()** (2 connections) — `internal/proxy/middleware/http_middleware_coverage_test.go`
- **.Write()** (1 connections) — `internal/proxy/middleware/http_middleware_coverage_test.go`
- **.WriteHeader()** (1 connections) — `internal/proxy/middleware/http_middleware_coverage_test.go`

## Relationships

- [Config Env Expansion](Config_Env_Expansion.md) (6 shared connections)
- [Response Writer Hijacking](Response_Writer_Hijacking.md) (4 shared connections)
- [CORS Middleware](CORS_Middleware.md) (2 shared connections)
- [Logging Middleware](Logging_Middleware.md) (2 shared connections)
- [Object Header Conformance](Object_Header_Conformance.md) (2 shared connections)
- [Middleware Flusher Fallback](Middleware_Flusher_Fallback.md) (1 shared connections)
- [Multipart Handler](Multipart_Handler.md) (1 shared connections)
- [License Logging](License_Logging.md) (1 shared connections)
- [Request Tracking Middleware](Request_Tracking_Middleware.md) (1 shared connections)

## Source Files

- `internal/proxy/middleware/http_middleware_coverage_test.go`

## Audit Trail

- EXTRACTED: 50 (93%)
- INFERRED: 4 (7%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*