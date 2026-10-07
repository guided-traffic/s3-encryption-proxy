# Logging Middleware

> 8 nodes · cohesion 0.32

## Key Concepts

- **responseWriter** (7 connections) — `internal/proxy/middleware/logging.go`
- **NewLogger()** (6 connections) — `internal/proxy/middleware/logging.go`
- **Logger** (5 connections) — `internal/proxy/middleware/logging.go`
- **middleware/logging.go** (3 connections) — `internal/proxy/middleware/logging.go`
- **.Flush()** (2 connections) — `internal/proxy/middleware/logging.go`
- **.FlushError()** (2 connections) — `internal/proxy/middleware/logging.go`
- **.Unwrap()** (2 connections) — `internal/proxy/middleware/logging.go`
- **.WriteHeader()** (1 connections) — `internal/proxy/middleware/logging.go`

## Relationships

- [Multipart Handler Wiring](Multipart_Handler_Wiring.md) (2 shared connections)
- [HTTP Middleware Coverage Tests](HTTP_Middleware_Coverage_Tests.md) (2 shared connections)
- [Bucket ACL and Accelerate Handlers](Bucket_ACL_and_Accelerate_Handlers.md) (2 shared connections)
- [Server](Server.md) (1 shared connections)
- [Requestid](Requestid.md) (1 shared connections)
- [CORS Middleware and SSE-C Stripping](CORS_Middleware_and_SSE-C_Stripping.md) (1 shared connections)
- [Monitoring Hijack Middleware](Monitoring_Hijack_Middleware.md) (1 shared connections)

## Source Files

- `internal/proxy/middleware/logging.go`

## Audit Trail

- EXTRACTED: 17 (89%)
- INFERRED: 2 (11%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*