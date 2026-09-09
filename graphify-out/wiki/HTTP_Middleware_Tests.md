# HTTP Middleware Tests

> 23 nodes · cohesion 0.15

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
- **MwNotAFlusher** (4 connections) — `internal/proxy/middleware/http_middleware_coverage_test.go`
- **.FlushError()** (3 connections) — `internal/proxy/middleware/http_middleware_coverage_test.go`
- **.Write()** (3 connections) — `internal/proxy/middleware/http_middleware_coverage_test.go`
- **.WriteHeader()** (3 connections) — `internal/proxy/middleware/http_middleware_coverage_test.go`
- **.Flush()** (2 connections) — `internal/proxy/middleware/http_middleware_coverage_test.go`
- **.Header()** (2 connections) — `internal/proxy/middleware/http_middleware_coverage_test.go`
- **.Header()** (2 connections) — `internal/proxy/middleware/http_middleware_coverage_test.go`
- **.Write()** (1 connections) — `internal/proxy/middleware/http_middleware_coverage_test.go`
- **.WriteHeader()** (1 connections) — `internal/proxy/middleware/http_middleware_coverage_test.go`
- **.Write()** (1 connections) — `internal/proxy/middleware/http_middleware_coverage_test.go`
- **.WriteHeader()** (1 connections) — `internal/proxy/middleware/http_middleware_coverage_test.go`

## Relationships

- [Config Accessor Tests](Config_Accessor_Tests.md) (6 shared connections)
- [CORS Logging Tracking Middleware](CORS_Logging_Tracking_Middleware.md) (5 shared connections)
- [Monitoring Middleware Tests](Monitoring_Middleware_Tests.md) (4 shared connections)
- [Object Header Conformance Tests](Object_Header_Conformance_Tests.md) (3 shared connections)
- [Multipart Handler Construction](Multipart_Handler_Construction.md) (1 shared connections)
- [License Logging](License_Logging.md) (1 shared connections)

## Source Files

- `internal/proxy/middleware/http_middleware_coverage_test.go`

## Audit Trail

- EXTRACTED: 54 (93%)
- INFERRED: 4 (7%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*