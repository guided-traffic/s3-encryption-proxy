# Router

> 10 nodes · cohesion 0.31

## Key Concepts

- **.setupRoutes()** (9 connections) — `internal/proxy/router.go`
- **github.com/gorilla/mux.Router** (8 connections)
- **.methodNotAllowedHandler()** (8 connections) — `internal/proxy/router.go`
- **net/http.HandlerFunc** (4 connections)
- **allowedMethods()** (4 connections) — `internal/proxy/router.go`
- **bucketRoute()** (4 connections) — `internal/proxy/router.go`
- **router.go** (3 connections) — `internal/proxy/router.go`
- **isProbeRequest()** (3 connections) — `internal/proxy/router.go`
- **github.com/gorilla/mux.RouteMatch** (2 connections)
- **Server** (2 connections) — `internal/proxy/router.go`

## Relationships

- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (4 shared connections)
- [Bucket Handler Error Fixtures](Bucket_Handler_Error_Fixtures.md) (2 shared connections)
- [Replication and ACL Handlers](Replication_and_ACL_Handlers.md) (2 shared connections)
- [CORS Middleware and SSE-C Stripping](CORS_Middleware_and_SSE-C_Stripping.md) (2 shared connections)
- [Multipart Handler Constructors](Multipart_Handler_Constructors.md) (2 shared connections)
- [Subresource Chunked Body](Subresource_Chunked_Body.md) (1 shared connections)
- [DeleteObjects Handler Tests](DeleteObjects_Handler_Tests.md) (1 shared connections)
- [Requestid](Requestid.md) (1 shared connections)
- [Copy and Delete Object Handlers](Copy_and_Delete_Object_Handlers.md) (1 shared connections)
- [Health Probe Handler](Health_Probe_Handler.md) (1 shared connections)
- [ListBuckets Root Handler](ListBuckets_Root_Handler.md) (1 shared connections)
- [Bucket Crud](Bucket_Crud.md) (1 shared connections)

## Source Files

- `internal/proxy/router.go`

## Audit Trail

- EXTRACTED: 33 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*