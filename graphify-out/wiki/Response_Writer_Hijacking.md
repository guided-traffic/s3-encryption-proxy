# Response Writer Hijacking

> 12 nodes · cohesion 0.23

## Key Concepts

- **net.Conn** (8 connections)
- **responseWriter** (7 connections) — `internal/monitoring/middleware.go`
- **.Hijack()** (5 connections) — `internal/proxy/middleware/http_middleware_coverage_test.go`
- **.Hijack()** (5 connections) — `internal/monitoring/middleware_coverage_test.go`
- **bufio.ReadWriter** (4 connections)
- **.Hijack()** (3 connections) — `internal/proxy/middleware/logging.go`
- **.Hijack()** (3 connections) — `internal/monitoring/middleware.go`
- **middleware.go** (2 connections) — `internal/monitoring/middleware.go`
- **.Flush()** (2 connections) — `internal/monitoring/middleware.go`
- **.FlushError()** (2 connections) — `internal/monitoring/middleware.go`
- **.Unwrap()** (2 connections) — `internal/monitoring/middleware.go`
- **.WriteHeader()** (1 connections) — `internal/monitoring/middleware.go`

## Relationships

- [Monitoring Middleware](Monitoring_Middleware.md) (5 shared connections)
- [HTTP Middleware Tests](HTTP_Middleware_Tests.md) (4 shared connections)
- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (2 shared connections)
- [Monitoring Server](Monitoring_Server.md) (1 shared connections)
- [Proxy Server Tests](Proxy_Server_Tests.md) (1 shared connections)
- [Logging Middleware](Logging_Middleware.md) (1 shared connections)

## Source Files

- `internal/monitoring/middleware.go`
- `internal/monitoring/middleware_coverage_test.go`
- `internal/proxy/middleware/http_middleware_coverage_test.go`
- `internal/proxy/middleware/logging.go`

## Audit Trail

- EXTRACTED: 29 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*