# Proxy Server and Middleware Wiring

> 172 nodes · cohesion 0.02

## Key Concepts

- **NewServer()** (50 connections) — `internal/monitoring/server.go`
- **copyWithPooledBuffer()** (21 connections) — `internal/proxy/handlers/object/helpers.go`
- **server_test.go** (15 connections) — `internal/proxy/server_test.go`
- **Server** (15 connections) — `internal/proxy/middleware_setup.go`
- **server_coverage_test.go** (14 connections) — `internal/monitoring/server_coverage_test.go`
- **server_coverage_test.go** (14 connections) — `internal/proxy/server_coverage_test.go`
- **TestRtPxMiddlewareWrappersInitialiseOnDemand()** (14 connections) — `internal/proxy/middleware_setup_coverage_test.go`
- **TestMwResponseWriterForwardsToTheLiveWriter()** (13 connections) — `internal/proxy/middleware/http_middleware_coverage_test.go`
- **router_coverage_test.go** (13 connections) — `internal/proxy/router_coverage_test.go`
- **RtPxrouter()** (13 connections) — `internal/proxy/router_coverage_test.go`
- **TestMwResponseWriterKeepsTheWriterCapabilities()** (12 connections) — `internal/proxy/middleware/http_middleware_coverage_test.go`
- **.setupMiddleware()** (12 connections) — `internal/proxy/middleware_setup.go`
- **TestMwLoggerMiddleware()** (11 connections) — `internal/proxy/middleware/http_middleware_coverage_test.go`
- **http_middleware_coverage_test.go** (11 connections) — `internal/proxy/middleware/http_middleware_coverage_test.go`
- **middleware.responseWriter (status-capturing wrapper)** (11 connections) — `internal/proxy/middleware/logging.go`
- **RtPxserver()** (11 connections) — `internal/proxy/middleware_setup_coverage_test.go`
- **.s3AuthMiddleware()** (11 connections) — `internal/proxy/middleware_setup.go`
- **RtPxconfig()** (11 connections) — `internal/proxy/server_coverage_test.go`
- **TestMwCORSMiddleware()** (10 connections) — `internal/proxy/middleware/http_middleware_coverage_test.go`
- **TestMwRequestTracker()** (10 connections) — `internal/proxy/middleware/http_middleware_coverage_test.go`
- **middleware_setup_coverage_test.go** (10 connections) — `internal/proxy/middleware_setup_coverage_test.go`
- **Server** (10 connections) — `internal/monitoring/server.go`
- **backendClientOptions()** (10 connections) — `internal/proxy/server.go`
- **TestServer_AuthErrorDoesNotReflectAttackerText()** (10 connections) — `internal/proxy/server_test.go`
- **TestRtPxS3AuthMiddlewareRejections()** (9 connections) — `internal/proxy/middleware_setup_coverage_test.go`
- *... and 147 more nodes in this community*

## Relationships

- No strong cross-community connections detected

## Source Files

- `docs/architecture/callgraph_proxy_layer.svg`
- `docs/tickets/010-baseline/README.md`
- `docs/tickets/024-coverage-round-findings.md`
- `internal/monitoring/server.go`
- `internal/monitoring/server_coverage_test.go`
- `internal/proxy/backend_client_test.go`
- `internal/proxy/handlers/multipart/copy.go`
- `internal/proxy/handlers/object/copy_bench_test.go`
- `internal/proxy/handlers/object/helpers.go`
- `internal/proxy/handlers/object/metadata_coverage_test.go`
- `internal/proxy/middleware/cors.go`
- `internal/proxy/middleware/http_middleware_coverage_test.go`
- `internal/proxy/middleware/logging.go`
- `internal/proxy/middleware/tracking.go`
- `internal/proxy/middleware_setup.go`
- `internal/proxy/middleware_setup_coverage_test.go`
- `internal/proxy/router_coverage_test.go`
- `internal/proxy/server.go`
- `internal/proxy/server_coverage_test.go`
- `internal/proxy/server_test.go`

## Audit Trail

- EXTRACTED: 608 (62%)
- INFERRED: 366 (38%)
- AMBIGUOUS: 1 (0%)

---

*Part of the graphify knowledge wiki. See [[index]] to navigate.*