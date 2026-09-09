# Bucket Lifecycle Handler

> 17 nodes · cohesion 0.18

## Key Concepts

- **NewHandler()** (38 connections) — `internal/proxy/handlers/bucket/handler.go`
- **LifecycleHandler** (9 connections) — `internal/proxy/handlers/bucket/lifecycle.go`
- **.Handle()** (6 connections) — `internal/proxy/handlers/bucket/lifecycle.go`
- **NewLifecycleHandler()** (6 connections) — `internal/proxy/handlers/bucket/lifecycle.go`
- **bucket_crud_test.go** (5 connections) — `internal/proxy/handlers/bucket/bucket_crud_test.go`
- **.handleDeleteBucketLifecycle()** (4 connections) — `internal/proxy/handlers/bucket/lifecycle.go`
- **.handleGetBucketLifecycleConfiguration()** (4 connections) — `internal/proxy/handlers/bucket/lifecycle.go`
- **.handlePutBucketLifecycleConfiguration()** (4 connections) — `internal/proxy/handlers/bucket/lifecycle.go`
- **TestBucketHandle_BaseOperationsStillReachTheBackend()** (3 connections) — `internal/proxy/handlers/bucket/bucket_crud_test.go`
- **TestBucketHandle_KnownSubResourceKeepsMethodNotAllowed()** (3 connections) — `internal/proxy/handlers/bucket/bucket_crud_test.go`
- **TestBucketHandle_UnroutedSubResourceIsNotABaseOperation()** (3 connections) — `internal/proxy/handlers/bucket/bucket_crud_test.go`
- **TestHandleCreateBucket()** (3 connections) — `internal/proxy/handlers/bucket/bucket_crud_test.go`
- **TestHandleDeleteBucket()** (3 connections) — `internal/proxy/handlers/bucket/bucket_crud_test.go`
- **TestMainBucketHandler_NewHandlers()** (3 connections) — `internal/proxy/handlers/bucket/handlers_test.go`
- **.GetLifecycleHandler()** (2 connections) — `internal/proxy/handlers/bucket/handler.go`
- **lifecycle.go** (2 connections) — `internal/proxy/handlers/bucket/lifecycle.go`
- **bucket/handlers_test.go** (1 connections) — `internal/proxy/handlers/bucket/handlers_test.go`

## Relationships

- [Bucket Sub-Resource Tests](Bucket_Sub-Resource_Tests.md) (13 shared connections)
- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (10 shared connections)
- [Bucket Sub-Resource Registry](Bucket_Sub-Resource_Registry.md) (9 shared connections)
- [Config Accessor Tests](Config_Accessor_Tests.md) (6 shared connections)
- [Bucket Location and Logging Tests](Bucket_Location_and_Logging_Tests.md) (5 shared connections)
- [Multipart Handler Construction](Multipart_Handler_Construction.md) (3 shared connections)
- [Bucket Handler Test Fakes](Bucket_Handler_Test_Fakes.md) (3 shared connections)
- [Configuration Accessors](Configuration_Accessors.md) (1 shared connections)
- [Bucket ACL Tests](Bucket_ACL_Tests.md) (1 shared connections)

## Source Files

- `internal/proxy/handlers/bucket/bucket_crud_test.go`
- `internal/proxy/handlers/bucket/handler.go`
- `internal/proxy/handlers/bucket/handlers_test.go`
- `internal/proxy/handlers/bucket/lifecycle.go`

## Audit Trail

- EXTRACTED: 44 (59%)
- INFERRED: 31 (41%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*