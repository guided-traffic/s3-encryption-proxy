# CORS Middleware and SSE-C Stripping

> 26 nodes · cohesion 0.13

## Key Concepts

- **net/http.Handler** (15 connections)
- **Server** (10 connections) — `internal/proxy/middleware_setup.go`
- **.setupMiddleware()** (9 connections) — `internal/proxy/middleware_setup.go`
- **.s3AuthMiddleware()** (7 connections) — `internal/proxy/middleware_setup.go`
- **NewCORS()** (6 connections) — `internal/proxy/middleware/cors.go`
- **RequestTracker** (6 connections) — `internal/proxy/middleware/tracking.go`
- **CORS** (5 connections) — `internal/proxy/middleware/cors.go`
- **NewRequestTracker()** (5 connections) — `internal/proxy/middleware/tracking.go`
- **.sseCustomerGuardMiddleware()** (4 connections) — `internal/proxy/middleware_setup.go`
- **.writeS3Error()** (4 connections) — `internal/proxy/middleware_setup.go`
- **What Never Reaches a Client** (3 connections) — `docs/developer/errors.md`
- **SSECustomerHeader()** (3 connections) — `internal/proxy/handlers/object/storage_headers.go`
- **authErrorStatus()** (3 connections) — `internal/proxy/middleware_setup.go`
- **.corsMiddleware()** (3 connections) — `internal/proxy/middleware_setup.go`
- **.drainGuardMiddleware()** (3 connections) — `internal/proxy/middleware_setup.go`
- **.loggingMiddleware()** (3 connections) — `internal/proxy/middleware_setup.go`
- **.rawQueryGuardMiddleware()** (3 connections) — `internal/proxy/middleware_setup.go`
- **.requestTrackingMiddleware()** (3 connections) — `internal/proxy/middleware_setup.go`
- **middleware/cors.go** (2 connections) — `internal/proxy/middleware/cors.go`
- **tracking.go** (2 connections) — `internal/proxy/middleware/tracking.go`
- **.Middleware()** (2 connections) — `internal/proxy/middleware/cors.go`
- **.Middleware()** (2 connections) — `internal/proxy/middleware/tracking.go`
- **.determineErrorCode()** (2 connections) — `internal/proxy/middleware_setup.go`
- **middleware_setup.go** (1 connections) — `internal/proxy/middleware_setup.go`
- **authErrorMessage** (1 connections) — `docs/developer/errors.md`
- *... and 1 more nodes in this community*

## Relationships

- [HTTP Middleware Coverage Tests](HTTP_Middleware_Coverage_Tests.md) (5 shared connections)
- [Multipart Handler Constructors](Multipart_Handler_Constructors.md) (4 shared connections)
- [Copy and Delete Object Handlers](Copy_and_Delete_Object_Handlers.md) (4 shared connections)
- [Router](Router.md) (2 shared connections)
- [Server](Server.md) (2 shared connections)
- [Configuration Loading and Upload Sweeper](Configuration_Loading_and_Upload_Sweeper.md) (1 shared connections)
- [Proxy Server Lifecycle Tests](Proxy_Server_Lifecycle_Tests.md) (1 shared connections)
- [Monitoring Middleware Tests](Monitoring_Middleware_Tests.md) (1 shared connections)
- [Requestid](Requestid.md) (1 shared connections)
- [S3 Method Error Mapping Tests](S3_Method_Error_Mapping_Tests.md) (1 shared connections)
- [Response Header Helpers](Response_Header_Helpers.md) (1 shared connections)
- [ListBuckets Root Handler](ListBuckets_Root_Handler.md) (1 shared connections)

## Source Files

- `docs/developer/errors.md`
- `internal/proxy/handlers/object/storage_headers.go`
- `internal/proxy/middleware/cors.go`
- `internal/proxy/middleware/tracking.go`
- `internal/proxy/middleware_setup.go`

## Audit Trail

- EXTRACTED: 65 (97%)
- INFERRED: 2 (3%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*