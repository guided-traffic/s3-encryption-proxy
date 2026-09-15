# HTTP Middleware Coverage Tests

> 37 nodes · cohesion 0.09

## Key Concepts

- **http_middleware_coverage_test.go** (11 connections) — `internal/proxy/middleware/http_middleware_coverage_test.go`
- **net.Conn** (8 connections)
- **MwechoHandler()** (8 connections) — `internal/proxy/middleware/http_middleware_coverage_test.go`
- **MwtestLogger()** (7 connections) — `internal/proxy/middleware/http_middleware_coverage_test.go`
- **responseWriter** (7 connections) — `internal/proxy/middleware/logging.go`
- **TestMwCORSMiddleware()** (6 connections) — `internal/proxy/middleware/http_middleware_coverage_test.go`
- **TestMwRequestTracker()** (6 connections) — `internal/proxy/middleware/http_middleware_coverage_test.go`
- **NewLogger()** (6 connections) — `internal/proxy/middleware/logging.go`
- **MwFlushErrorWriter** (6 connections) — `internal/proxy/middleware/http_middleware_coverage_test.go`
- **MwHijackWriter** (6 connections) — `internal/proxy/middleware/http_middleware_coverage_test.go`
- **TestMwLoggerMiddleware()** (5 connections) — `internal/proxy/middleware/http_middleware_coverage_test.go`
- **TestMwResponseWriterForwardsToTheLiveWriter()** (5 connections) — `internal/proxy/middleware/http_middleware_coverage_test.go`
- **TestMwResponseWriterKeepsTheWriterCapabilities()** (5 connections) — `internal/proxy/middleware/http_middleware_coverage_test.go`
- **Logger** (5 connections) — `internal/proxy/middleware/logging.go`
- **.Hijack()** (5 connections) — `internal/proxy/middleware/http_middleware_coverage_test.go`
- **bufio.ReadWriter** (4 connections)
- **TestMwLoggerDefaultsToOKWithoutExplicitWriteHeader()** (4 connections) — `internal/proxy/middleware/http_middleware_coverage_test.go`
- **.Header()** (4 connections) — `internal/proxy/middleware/http_middleware_coverage_test.go`
- **MwNotAFlusher** (4 connections) — `internal/proxy/middleware/http_middleware_coverage_test.go`
- **middleware/logging.go** (3 connections) — `internal/proxy/middleware/logging.go`
- **.Middleware()** (3 connections) — `internal/proxy/middleware/logging.go`
- **.FlushError()** (3 connections) — `internal/proxy/middleware/http_middleware_coverage_test.go`
- **.Write()** (3 connections) — `internal/proxy/middleware/http_middleware_coverage_test.go`
- **.WriteHeader()** (3 connections) — `internal/proxy/middleware/http_middleware_coverage_test.go`
- **.Hijack()** (3 connections) — `internal/proxy/middleware/logging.go`
- *... and 12 more nodes in this community*

## Relationships

- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (6 shared connections)
- [CORS Middleware and SSE-C Stripping](CORS_Middleware_and_SSE-C_Stripping.md) (5 shared connections)
- [Monitoring Middleware Tests](Monitoring_Middleware_Tests.md) (3 shared connections)
- [Multipart Handler Constructors](Multipart_Handler_Constructors.md) (3 shared connections)
- [S3 Method Error Mapping Tests](S3_Method_Error_Mapping_Tests.md) (3 shared connections)
- [Server](Server.md) (2 shared connections)
- [Bucket Website and Create/Delete](Bucket_Website_and_Create-Delete.md) (2 shared connections)
- [Monitoring HTTP Server](Monitoring_HTTP_Server.md) (1 shared connections)
- [Object GET Coverage Tests](Object_GET_Coverage_Tests.md) (1 shared connections)
- [Requestid](Requestid.md) (1 shared connections)
- [Middleware](Middleware.md) (1 shared connections)

## Source Files

- `internal/monitoring/middleware.go`
- `internal/proxy/middleware/http_middleware_coverage_test.go`
- `internal/proxy/middleware/logging.go`

## Audit Trail

- EXTRACTED: 84 (94%)
- INFERRED: 5 (6%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*