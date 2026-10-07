# Bucket Sub-Resource Handler Registry

> 30 nodes · cohesion 0.09

## Key Concepts

- **NewHandler()** (40 connections) — `internal/proxy/handlers/bucket/handler.go`
- **BaseSubResourceHandler** (34 connections) — `internal/proxy/handlers/bucket/base.go`
- **AccelerateHandler** (8 connections) — `internal/proxy/handlers/bucket/accelerate.go`
- **NotificationHandler** (8 connections) — `internal/proxy/handlers/bucket/notification.go`
- **RequestPaymentHandler** (8 connections) — `internal/proxy/handlers/bucket/request_payment.go`
- **LocationHandler** (7 connections) — `internal/proxy/handlers/bucket/location.go`
- **ACLHandler** (6 connections) — `internal/proxy/handlers/bucket/acl.go`
- **bucket_crud_test.go** (5 connections) — `internal/proxy/handlers/bucket/bucket_crud_test.go`
- **NewACLHandler()** (4 connections) — `internal/proxy/handlers/bucket/acl.go`
- **NewCORSHandler()** (4 connections) — `internal/proxy/handlers/bucket/cors.go`
- **NewLocationHandler()** (4 connections) — `internal/proxy/handlers/bucket/location.go`
- **NewLoggingHandler()** (4 connections) — `internal/proxy/handlers/bucket/logging.go`
- **NewPolicyHandler()** (4 connections) — `internal/proxy/handlers/bucket/policy.go`
- **TestBucketHandle_BaseOperationsStillReachTheBackend()** (3 connections) — `internal/proxy/handlers/bucket/bucket_crud_test.go`
- **TestBucketHandle_KnownSubResourceKeepsMethodNotAllowed()** (3 connections) — `internal/proxy/handlers/bucket/bucket_crud_test.go`
- **TestBucketHandle_UnroutedSubResourceIsNotABaseOperation()** (3 connections) — `internal/proxy/handlers/bucket/bucket_crud_test.go`
- **TestHandleCreateBucket()** (3 connections) — `internal/proxy/handlers/bucket/bucket_crud_test.go`
- **TestHandleDeleteBucket()** (3 connections) — `internal/proxy/handlers/bucket/bucket_crud_test.go`
- **TestMainBucketHandler_NewHandlers()** (3 connections) — `internal/proxy/handlers/bucket/handlers_test.go`
- **.GetLocationHandler()** (2 connections) — `internal/proxy/handlers/bucket/handler.go`
- **accelerate.go** (2 connections) — `internal/proxy/handlers/bucket/accelerate.go`
- **bucket/acl.go** (2 connections) — `internal/proxy/handlers/bucket/acl.go`
- **base.go** (2 connections) — `internal/proxy/handlers/bucket/base.go`
- **bucket/cors.go** (2 connections) — `internal/proxy/handlers/bucket/cors.go`
- **location.go** (2 connections) — `internal/proxy/handlers/bucket/location.go`
- *... and 5 more nodes in this community*

## Relationships

- [Bucket ACL and Accelerate Handlers](Bucket_ACL_and_Accelerate_Handlers.md) (22 shared connections)
- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (21 shared connections)
- [Bucket CORS Handler](Bucket_CORS_Handler.md) (16 shared connections)
- [Multipart Handler Wiring](Multipart_Handler_Wiring.md) (7 shared connections)
- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (6 shared connections)
- [Bucket Handler Error Fixtures](Bucket_Handler_Error_Fixtures.md) (5 shared connections)
- [Bucket Location and Logging Tests](Bucket_Location_and_Logging_Tests.md) (4 shared connections)
- [Bucket Versioning Handler](Bucket_Versioning_Handler.md) (3 shared connections)
- [Bucket Lifecycle Handler](Bucket_Lifecycle_Handler.md) (2 shared connections)
- [Bucket Replication Handler](Bucket_Replication_Handler.md) (2 shared connections)
- [Copy and Delete Object Handlers](Copy_and_Delete_Object_Handlers.md) (1 shared connections)
- [Router](Router.md) (1 shared connections)

## Source Files

- `internal/proxy/handlers/bucket/accelerate.go`
- `internal/proxy/handlers/bucket/acl.go`
- `internal/proxy/handlers/bucket/base.go`
- `internal/proxy/handlers/bucket/bucket_crud_test.go`
- `internal/proxy/handlers/bucket/cors.go`
- `internal/proxy/handlers/bucket/handler.go`
- `internal/proxy/handlers/bucket/handlers_test.go`
- `internal/proxy/handlers/bucket/location.go`
- `internal/proxy/handlers/bucket/logging.go`
- `internal/proxy/handlers/bucket/notification.go`
- `internal/proxy/handlers/bucket/policy.go`
- `internal/proxy/handlers/bucket/request_payment.go`

## Audit Trail

- EXTRACTED: 104 (78%)
- INFERRED: 30 (22%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*