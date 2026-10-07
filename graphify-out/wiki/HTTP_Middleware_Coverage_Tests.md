# HTTP Middleware Coverage Tests

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

- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (6 shared connections)
- [Monitoring Hijack Middleware](Monitoring_Hijack_Middleware.md) (4 shared connections)
- [Logging Middleware](Logging_Middleware.md) (2 shared connections)
- [Integration Failing Writer Fixtures](Integration_Failing_Writer_Fixtures.md) (2 shared connections)
- [Middleware Non-Flusher Stub](Middleware_Non-Flusher_Stub.md) (1 shared connections)
- [CORS Middleware and SSE-C Stripping](CORS_Middleware_and_SSE-C_Stripping.md) (1 shared connections)
- [Multipart Handler Wiring](Multipart_Handler_Wiring.md) (1 shared connections)
- [Object GET Coverage Tests](Object_GET_Coverage_Tests.md) (1 shared connections)
- [Router](Router.md) (1 shared connections)
- [Server](Server.md) (1 shared connections)

## Source Files

- `internal/proxy/middleware/http_middleware_coverage_test.go`

## Audit Trail

- EXTRACTED: 50 (93%)
- INFERRED: 4 (7%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*