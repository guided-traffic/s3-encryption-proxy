# CORS Middleware

> 13 nodes · cohesion 0.29

## Key Concepts

- **net/http.Handler** (10 connections)
- **.setupMiddleware()** (9 connections) — `internal/proxy/middleware_setup.go`
- **Server** (7 connections) — `internal/proxy/middleware_setup.go`
- **.s3AuthMiddleware()** (6 connections) — `internal/proxy/middleware_setup.go`
- **CORS** (5 connections) — `internal/proxy/middleware/cors.go`
- **NewCORS()** (5 connections) — `internal/proxy/middleware/cors.go`
- **.writeS3Error()** (4 connections) — `internal/proxy/middleware_setup.go`
- **.corsMiddleware()** (3 connections) — `internal/proxy/middleware_setup.go`
- **.loggingMiddleware()** (3 connections) — `internal/proxy/middleware_setup.go`
- **.requestTrackingMiddleware()** (3 connections) — `internal/proxy/middleware_setup.go`
- **middleware/cors.go** (2 connections) — `internal/proxy/middleware/cors.go`
- **.Middleware()** (2 connections) — `internal/proxy/middleware/cors.go`
- **.determineErrorCode()** (2 connections) — `internal/proxy/middleware_setup.go`

## Relationships

- [Request Tracking Middleware](Request_Tracking_Middleware.md) (3 shared connections)
- [HTTP Middleware Tests](HTTP_Middleware_Tests.md) (2 shared connections)
- [Logging Middleware](Logging_Middleware.md) (2 shared connections)
- [Multipart Handler](Multipart_Handler.md) (2 shared connections)
- [Proxy Server Tests](Proxy_Server_Tests.md) (1 shared connections)
- [Monitoring Middleware](Monitoring_Middleware.md) (1 shared connections)
- [ListBuckets Handler Tests](ListBuckets_Handler_Tests.md) (1 shared connections)
- [SigV4 Header Authentication](SigV4_Header_Authentication.md) (1 shared connections)
- [Error Response Tests](Error_Response_Tests.md) (1 shared connections)
- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (1 shared connections)

## Source Files

- `internal/proxy/middleware/cors.go`
- `internal/proxy/middleware_setup.go`

## Audit Trail

- EXTRACTED: 37 (97%)
- INFERRED: 1 (3%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*