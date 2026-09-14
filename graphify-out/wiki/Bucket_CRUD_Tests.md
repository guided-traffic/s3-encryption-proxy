# Bucket CRUD Tests

> 15 nodes · cohesion 0.18

## Key Concepts

- **NewHandler()** (41 connections) — `internal/proxy/handlers/bucket/handler.go`
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
- **lifecycle.go** (2 connections) — `internal/proxy/handlers/bucket/lifecycle.go`
- **lifecycle_test.go** (2 connections) — `internal/proxy/handlers/bucket/lifecycle_test.go`
- **handlers_test.go** (1 connections) — `internal/proxy/handlers/bucket/handlers_test.go`

## Relationships

- [Bucket NotImplemented Tests](Bucket_NotImplemented_Tests.md) (9 shared connections)
- [Config Env Expansion](Config_Env_Expansion.md) (8 shared connections)
- [Bucket Handler Routing](Bucket_Handler_Routing.md) (5 shared connections)
- [Bucket Sub-Resource Tests](Bucket_Sub-Resource_Tests.md) (5 shared connections)
- [Bucket Handler Tests](Bucket_Handler_Tests.md) (5 shared connections)
- [Multipart Handler](Multipart_Handler.md) (4 shared connections)
- [XML Response Helpers](XML_Response_Helpers.md) (3 shared connections)
- [Error Response Tests](Error_Response_Tests.md) (3 shared connections)
- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (2 shared connections)
- [Config Structure](Config_Structure.md) (1 shared connections)
- [Bucket ACL Tests](Bucket_ACL_Tests.md) (1 shared connections)
- [Bucket ACL Handler](Bucket_ACL_Handler.md) (1 shared connections)

## Source Files

- `internal/proxy/handlers/bucket/bucket_crud_test.go`
- `internal/proxy/handlers/bucket/handler.go`
- `internal/proxy/handlers/bucket/handlers_test.go`
- `internal/proxy/handlers/bucket/lifecycle.go`
- `internal/proxy/handlers/bucket/lifecycle_test.go`

## Audit Trail

- EXTRACTED: 37 (51%)
- INFERRED: 35 (49%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*