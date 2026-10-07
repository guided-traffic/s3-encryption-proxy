# CORS Middleware and SSE-C Stripping

> 13 nodes · cohesion 0.31

## Key Concepts

- **net/http.Handler** (15 connections)
- **Server** (10 connections) — `internal/proxy/middleware_setup.go`
- **.setupMiddleware()** (9 connections) — `internal/proxy/middleware_setup.go`
- **.s3AuthMiddleware()** (7 connections) — `internal/proxy/middleware_setup.go`
- **.sseCustomerGuardMiddleware()** (4 connections) — `internal/proxy/middleware_setup.go`
- **.writeS3Error()** (4 connections) — `internal/proxy/middleware_setup.go`
- **SSECustomerHeader()** (3 connections) — `internal/proxy/handlers/object/storage_headers.go`
- **.corsMiddleware()** (3 connections) — `internal/proxy/middleware_setup.go`
- **.drainGuardMiddleware()** (3 connections) — `internal/proxy/middleware_setup.go`
- **.loggingMiddleware()** (3 connections) — `internal/proxy/middleware_setup.go`
- **.rawQueryGuardMiddleware()** (3 connections) — `internal/proxy/middleware_setup.go`
- **.requestTrackingMiddleware()** (3 connections) — `internal/proxy/middleware_setup.go`
- **.determineErrorCode()** (2 connections) — `internal/proxy/middleware_setup.go`

## Relationships

- [Copy and Delete Object Handlers](Copy_and_Delete_Object_Handlers.md) (4 shared connections)
- [Router](Router.md) (3 shared connections)
- [Requestid](Requestid.md) (2 shared connections)
- [Server](Server.md) (2 shared connections)
- [Proxy Server Lifecycle Tests](Proxy_Server_Lifecycle_Tests.md) (1 shared connections)
- [Monitoring Middleware Tests](Monitoring_Middleware_Tests.md) (1 shared connections)
- [HTTP Middleware Coverage Tests](HTTP_Middleware_Coverage_Tests.md) (1 shared connections)
- [Integration Failing Writer Fixtures](Integration_Failing_Writer_Fixtures.md) (1 shared connections)
- [Health Probes and Request Tracker](Health_Probes_and_Request_Tracker.md) (1 shared connections)
- [Authentication Error Messages](Authentication_Error_Messages.md) (1 shared connections)
- [ListBuckets Coverage Tests](ListBuckets_Coverage_Tests.md) (1 shared connections)
- [Logging Middleware](Logging_Middleware.md) (1 shared connections)

## Source Files

- `internal/proxy/handlers/object/storage_headers.go`
- `internal/proxy/middleware_setup.go`

## Audit Trail

- EXTRACTED: 45 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*