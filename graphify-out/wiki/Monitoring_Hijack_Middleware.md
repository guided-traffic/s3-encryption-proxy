# Monitoring Hijack Middleware

> 12 nodes · cohesion 0.23

## Key Concepts

- **net.Conn** (8 connections)
- **responseWriter** (7 connections) — `internal/monitoring/middleware.go`
- **.Hijack()** (5 connections) — `internal/proxy/middleware/http_middleware_coverage_test.go`
- **.Hijack()** (5 connections) — `internal/monitoring/middleware_coverage_test.go`
- **bufio.ReadWriter** (4 connections)
- **middleware.go** (3 connections) — `internal/monitoring/middleware.go`
- **.Hijack()** (3 connections) — `internal/proxy/middleware/logging.go`
- **.Hijack()** (3 connections) — `internal/monitoring/middleware.go`
- **.Flush()** (2 connections) — `internal/monitoring/middleware.go`
- **.FlushError()** (2 connections) — `internal/monitoring/middleware.go`
- **.Unwrap()** (2 connections) — `internal/monitoring/middleware.go`
- **.WriteHeader()** (1 connections) — `internal/monitoring/middleware.go`

## Relationships

- [Monitoring Middleware Tests](Monitoring_Middleware_Tests.md) (5 shared connections)
- [HTTP Middleware Coverage Tests](HTTP_Middleware_Coverage_Tests.md) (4 shared connections)
- [Bucket ACL and Accelerate Handlers](Bucket_ACL_and_Accelerate_Handlers.md) (2 shared connections)
- [Monitoring Test Imports](Monitoring_Test_Imports.md) (1 shared connections)
- [Proxy Server Lifecycle Tests](Proxy_Server_Lifecycle_Tests.md) (1 shared connections)
- [ADR Web: Auth, Checksums, Config](ADR_Web-_Auth,_Checksums,_Config.md) (1 shared connections)
- [Logging Middleware](Logging_Middleware.md) (1 shared connections)

## Source Files

- `internal/monitoring/middleware.go`
- `internal/monitoring/middleware_coverage_test.go`
- `internal/proxy/middleware/http_middleware_coverage_test.go`
- `internal/proxy/middleware/logging.go`

## Audit Trail

- EXTRACTED: 30 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*