# Bucket Crud

> 14 nodes · cohesion 0.20

## Key Concepts

- **NewHandler()** (40 connections) — `internal/proxy/handlers/bucket/handler.go`
- **TestLifecycleHandler_ComplexRules()** (7 connections) — `internal/proxy/handlers/bucket/lifecycle_test.go`
- **TestLifecycleHandler_Handle()** (7 connections) — `internal/proxy/handlers/bucket/lifecycle_test.go`
- **NewLifecycleHandler()** (6 connections) — `internal/proxy/handlers/bucket/lifecycle.go`
- **bucket_crud_test.go** (5 connections) — `internal/proxy/handlers/bucket/bucket_crud_test.go`
- **TestBucketHandle_BaseOperationsStillReachTheBackend()** (3 connections) — `internal/proxy/handlers/bucket/bucket_crud_test.go`
- **TestBucketHandle_KnownSubResourceKeepsMethodNotAllowed()** (3 connections) — `internal/proxy/handlers/bucket/bucket_crud_test.go`
- **TestBucketHandle_UnroutedSubResourceIsNotABaseOperation()** (3 connections) — `internal/proxy/handlers/bucket/bucket_crud_test.go`
- **TestHandleCreateBucket()** (3 connections) — `internal/proxy/handlers/bucket/bucket_crud_test.go`
- **TestHandleDeleteBucket()** (3 connections) — `internal/proxy/handlers/bucket/bucket_crud_test.go`
- **TestMainBucketHandler_NewHandlers()** (3 connections) — `internal/proxy/handlers/bucket/handlers_test.go`
- **bucket/handler.go** (2 connections) — `internal/proxy/handlers/bucket/handler.go`
- **lifecycle_test.go** (2 connections) — `internal/proxy/handlers/bucket/lifecycle_test.go`
- **handlers_test.go** (1 connections) — `internal/proxy/handlers/bucket/handlers_test.go`

## Relationships

- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (17 shared connections)
- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (8 shared connections)
- [ACL, CORS and Lifecycle Handlers](ACL,_CORS_and_Lifecycle_Handlers.md) (5 shared connections)
- [Bucket Handler Error Fixtures](Bucket_Handler_Error_Fixtures.md) (5 shared connections)
- [Bucket Location and Logging Tests](Bucket_Location_and_Logging_Tests.md) (4 shared connections)
- [Bucket Handler Dispatch](Bucket_Handler_Dispatch.md) (3 shared connections)
- [Copy and Delete Object Handlers](Copy_and_Delete_Object_Handlers.md) (3 shared connections)
- [Multipart Handler Constructors](Multipart_Handler_Constructors.md) (3 shared connections)
- [Router](Router.md) (1 shared connections)
- [Configuration Struct and Accessors](Configuration_Struct_and_Accessors.md) (1 shared connections)
- [Logging](Logging.md) (1 shared connections)
- [Subresource Chunked Body](Subresource_Chunked_Body.md) (1 shared connections)

## Source Files

- `internal/proxy/handlers/bucket/bucket_crud_test.go`
- `internal/proxy/handlers/bucket/handler.go`
- `internal/proxy/handlers/bucket/handlers_test.go`
- `internal/proxy/handlers/bucket/lifecycle.go`
- `internal/proxy/handlers/bucket/lifecycle_test.go`

## Audit Trail

- EXTRACTED: 36 (51%)
- INFERRED: 34 (49%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*