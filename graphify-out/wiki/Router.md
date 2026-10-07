# Router

> 10 nodes · cohesion 0.31

## Key Concepts

- **.setupRoutes()** (9 connections) — `internal/proxy/router.go`
- **github.com/gorilla/mux.Router** (8 connections)
- **.methodNotAllowedHandler()** (8 connections) — `internal/proxy/router.go`
- **NewCORS()** (6 connections) — `internal/proxy/middleware/cors.go`
- **CORS** (5 connections) — `internal/proxy/middleware/cors.go`
- **allowedMethods()** (4 connections) — `internal/proxy/router.go`
- **bucketRoute()** (4 connections) — `internal/proxy/router.go`
- **middleware/cors.go** (2 connections) — `internal/proxy/middleware/cors.go`
- **Server** (2 connections) — `internal/proxy/router.go`
- **.Middleware()** (2 connections) — `internal/proxy/middleware/cors.go`

## Relationships

- [Multipart Handler Wiring](Multipart_Handler_Wiring.md) (4 shared connections)
- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (3 shared connections)
- [CORS Middleware and SSE-C Stripping](CORS_Middleware_and_SSE-C_Stripping.md) (3 shared connections)
- [Transfer Bounds and Shutdown](Transfer_Bounds_and_Shutdown.md) (2 shared connections)
- [Bucket Handler Error Fixtures](Bucket_Handler_Error_Fixtures.md) (1 shared connections)
- [Server](Server.md) (1 shared connections)
- [HTTP Middleware Coverage Tests](HTTP_Middleware_Coverage_Tests.md) (1 shared connections)
- [Bucket ACL and Accelerate Handlers](Bucket_ACL_and_Accelerate_Handlers.md) (1 shared connections)
- [Subresource Chunked Body](Subresource_Chunked_Body.md) (1 shared connections)
- [Requestid](Requestid.md) (1 shared connections)
- [Copy and Delete Object Handlers](Copy_and_Delete_Object_Handlers.md) (1 shared connections)
- [Health Probe Handler](Health_Probe_Handler.md) (1 shared connections)

## Source Files

- `internal/proxy/middleware/cors.go`
- `internal/proxy/router.go`

## Audit Trail

- EXTRACTED: 35 (97%)
- INFERRED: 1 (3%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*