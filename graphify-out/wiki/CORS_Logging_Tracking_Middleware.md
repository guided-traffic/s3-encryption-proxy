# CORS Logging Tracking Middleware

> 28 nodes · cohesion 0.12

## Key Concepts

- **Server** (20 connections) — `internal/proxy/server.go`
- **net/http.Handler** (11 connections)
- **.setupMiddleware()** (9 connections) — `internal/proxy/middleware_setup.go`
- **Server** (7 connections) — `internal/proxy/middleware_setup.go`
- **NewLogger()** (6 connections) — `internal/proxy/middleware/logging.go`
- **RequestTracker** (6 connections) — `internal/proxy/middleware/tracking.go`
- **CORS** (5 connections) — `internal/proxy/middleware/cors.go`
- **NewCORS()** (5 connections) — `internal/proxy/middleware/cors.go`
- **Logger** (5 connections) — `internal/proxy/middleware/logging.go`
- **NewRequestTracker()** (5 connections) — `internal/proxy/middleware/tracking.go`
- **.s3AuthMiddleware()** (5 connections) — `internal/proxy/middleware_setup.go`
- **.writeS3Error()** (4 connections) — `internal/proxy/middleware_setup.go`
- **middleware/logging.go** (3 connections) — `internal/proxy/middleware/logging.go`
- **.corsMiddleware()** (3 connections) — `internal/proxy/middleware_setup.go`
- **.loggingMiddleware()** (3 connections) — `internal/proxy/middleware_setup.go`
- **.requestTrackingMiddleware()** (3 connections) — `internal/proxy/middleware_setup.go`
- **middleware/cors.go** (2 connections) — `internal/proxy/middleware/cors.go`
- **tracking.go** (2 connections) — `internal/proxy/middleware/tracking.go`
- **.Middleware()** (2 connections) — `internal/proxy/middleware/cors.go`
- **.Middleware()** (2 connections) — `internal/proxy/middleware/logging.go`
- **.Middleware()** (2 connections) — `internal/proxy/middleware/tracking.go`
- **.determineErrorCode()** (2 connections) — `internal/proxy/middleware_setup.go`
- **.GetHandler()** (2 connections) — `internal/proxy/server.go`
- **.SetShutdownStateHandler()** (2 connections) — `internal/proxy/server.go`
- **.Start()** (2 connections) — `internal/proxy/server.go`
- *... and 3 more nodes in this community*

## Relationships

- [Multipart Handler Construction](Multipart_Handler_Construction.md) (8 shared connections)
- [HTTP Middleware Tests](HTTP_Middleware_Tests.md) (5 shared connections)
- [AES and RSA Provider Tests](AES_and_RSA_Provider_Tests.md) (2 shared connections)
- [SigV4 Test Signer](SigV4_Test_Signer.md) (2 shared connections)
- [SigV4 Pre-Signed URL Auth](SigV4_Pre-Signed_URL_Auth.md) (2 shared connections)
- [Proxy Server Construction Tests](Proxy_Server_Construction_Tests.md) (2 shared connections)
- [Proxy Server Auth Error Tests](Proxy_Server_Auth_Error_Tests.md) (1 shared connections)
- [Monitoring Middleware Tests](Monitoring_Middleware_Tests.md) (1 shared connections)
- [Logging Response Writer](Logging_Response_Writer.md) (1 shared connections)
- [None Provider Integration Tests](None_Provider_Integration_Tests.md) (1 shared connections)
- [pprof Profiling Server](pprof_Profiling_Server.md) (1 shared connections)
- [HMAC and DEK Cache Tests](HMAC_and_DEK_Cache_Tests.md) (1 shared connections)

## Source Files

- `internal/proxy/middleware/cors.go`
- `internal/proxy/middleware/logging.go`
- `internal/proxy/middleware/tracking.go`
- `internal/proxy/middleware_setup.go`
- `internal/proxy/server.go`

## Audit Trail

- EXTRACTED: 72 (95%)
- INFERRED: 4 (5%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*