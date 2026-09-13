# Logging Middleware

> 9 nodes · cohesion 0.28

## Key Concepts

- **responseWriter** (7 connections) — `internal/proxy/middleware/logging.go`
- **NewLogger()** (6 connections) — `internal/proxy/middleware/logging.go`
- **Logger** (5 connections) — `internal/proxy/middleware/logging.go`
- **middleware/logging.go** (3 connections) — `internal/proxy/middleware/logging.go`
- **.Middleware()** (2 connections) — `internal/proxy/middleware/logging.go`
- **.Flush()** (2 connections) — `internal/proxy/middleware/logging.go`
- **.FlushError()** (2 connections) — `internal/proxy/middleware/logging.go`
- **.Unwrap()** (2 connections) — `internal/proxy/middleware/logging.go`
- **.WriteHeader()** (1 connections) — `internal/proxy/middleware/logging.go`

## Relationships

- [Multipart Handler](Multipart_Handler.md) (2 shared connections)
- [CORS Middleware](CORS_Middleware.md) (2 shared connections)
- [HTTP Middleware Tests](HTTP_Middleware_Tests.md) (2 shared connections)
- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (2 shared connections)
- [Request Tracking Middleware](Request_Tracking_Middleware.md) (1 shared connections)
- [Response Writer Hijacking](Response_Writer_Hijacking.md) (1 shared connections)

## Source Files

- `internal/proxy/middleware/logging.go`

## Audit Trail

- EXTRACTED: 18 (90%)
- INFERRED: 2 (10%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*