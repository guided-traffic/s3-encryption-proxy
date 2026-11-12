# CORS and Middleware

> 16 nodes · cohesion 0.12

## Key Concepts

- **net/http.Handler** (15 connections)
- **WithClientIdentity()** (6 connections) — `internal/proxy/middleware/identity.go`
- **RequestTracker** (6 connections) — `internal/proxy/middleware/tracking.go`
- **CORS** (5 connections) — `internal/proxy/middleware/cors.go`
- **SSECustomerHeader()** (3 connections) — `internal/proxy/handlers/object/storage_headers.go`
- **.s3AuthMiddleware()** (3 connections) — `internal/proxy/middleware_setup.go`
- **.sseCustomerGuardMiddleware()** (3 connections) — `internal/proxy/middleware_setup.go`
- **authErrorStatus()** (2 connections) — `internal/proxy/middleware_setup.go`
- **.Middleware()** (2 connections) — `internal/proxy/middleware/cors.go`
- **.Middleware()** (2 connections) — `internal/proxy/middleware/tracking.go`
- **.drainGuardMiddleware()** (2 connections) — `internal/proxy/middleware_setup.go`
- **.rawQueryGuardMiddleware()** (2 connections) — `internal/proxy/middleware_setup.go`
- **.SetHandlers()** (1 connections) — `internal/proxy/middleware/tracking.go`
- **.corsMiddleware()** (1 connections) — `internal/proxy/middleware_setup.go`
- **.loggingMiddleware()** (1 connections) — `internal/proxy/middleware_setup.go`
- **.requestTrackingMiddleware()** (1 connections) — `internal/proxy/middleware_setup.go`

## Relationships

- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (5 shared connections)
- [Shutdown and Test Contexts](Shutdown_and_Test_Contexts.md) (3 shared connections)
- [Dataencryption: Segmented Gcm Io (2)](Dataencryption-_Segmented_Gcm_Io_2.md) (3 shared connections)
- [Sub-Resource Handler Tests](Sub-Resource_Handler_Tests.md) (3 shared connections)
- [Adr: 0027 Conformance Is Asserted Against A Backend That Is Not Minio](Adr-_0027_Conformance_Is_Asserted_Against_A_Backend_That_Is_Not_Minio.md) (2 shared connections)
- [Multipart Handlers and Manager](Multipart_Handlers_and_Manager.md) (2 shared connections)
- [Server and Listings](Server_and_Listings.md) (2 shared connections)
- [Monitoring: Metrics Coverage Test](Monitoring-_Metrics_Coverage_Test.md) (1 shared connections)
- [Method Not Allowed Handler](Method_Not_Allowed_Handler.md) (1 shared connections)
- [Request Middleware Plumbing](Request_Middleware_Plumbing.md) (1 shared connections)
- [Bucket Handler Tests](Bucket_Handler_Tests.md) (1 shared connections)
- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (1 shared connections)

## Source Files

- `internal/proxy/handlers/object/storage_headers.go`
- `internal/proxy/middleware/cors.go`
- `internal/proxy/middleware/identity.go`
- `internal/proxy/middleware/tracking.go`
- `internal/proxy/middleware_setup.go`

## Audit Trail

- EXTRACTED: 40 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*