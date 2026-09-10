# Bucket Handler Routing

> 40 nodes · cohesion 0.08

## Key Concepts

- **Handler** (37 connections) — `internal/proxy/handlers/bucket/handler.go`
- **BaseSubResourceHandler** (33 connections) — `internal/proxy/handlers/bucket/base.go`
- **PolicyHandler** (9 connections) — `internal/proxy/handlers/bucket/policy.go`
- **AccelerateHandler** (8 connections) — `internal/proxy/handlers/bucket/accelerate.go`
- **RequestPaymentHandler** (8 connections) — `internal/proxy/handlers/bucket/request_payment.go`
- **VersioningHandler** (8 connections) — `internal/proxy/handlers/bucket/versioning.go`
- **LocationHandler** (7 connections) — `internal/proxy/handlers/bucket/location.go`
- **.Handle()** (6 connections) — `internal/proxy/handlers/bucket/policy.go`
- **.Handle()** (5 connections) — `internal/proxy/handlers/bucket/accelerate.go`
- **.Handle()** (5 connections) — `internal/proxy/handlers/bucket/handler.go`
- **.Handle()** (5 connections) — `internal/proxy/handlers/bucket/request_payment.go`
- **.Handle()** (5 connections) — `internal/proxy/handlers/bucket/versioning.go`
- **.handleGetBucketAccelerateConfiguration()** (4 connections) — `internal/proxy/handlers/bucket/accelerate.go`
- **.handlePutBucketAccelerateConfiguration()** (4 connections) — `internal/proxy/handlers/bucket/accelerate.go`
- **.handleBaseBucketOperations()** (4 connections) — `internal/proxy/handlers/bucket/handler.go`
- **.Handle()** (4 connections) — `internal/proxy/handlers/bucket/location.go`
- **.handleGetLocation()** (4 connections) — `internal/proxy/handlers/bucket/location.go`
- **.handleDeletePolicy()** (4 connections) — `internal/proxy/handlers/bucket/policy.go`
- **.handleGetPolicy()** (4 connections) — `internal/proxy/handlers/bucket/policy.go`
- **.handlePutPolicy()** (4 connections) — `internal/proxy/handlers/bucket/policy.go`
- **.handleGetBucketRequestPayment()** (4 connections) — `internal/proxy/handlers/bucket/request_payment.go`
- **.handlePutBucketRequestPayment()** (4 connections) — `internal/proxy/handlers/bucket/request_payment.go`
- **.handleGetBucketVersioning()** (4 connections) — `internal/proxy/handlers/bucket/versioning.go`
- **.handlePutBucketVersioning()** (4 connections) — `internal/proxy/handlers/bucket/versioning.go`
- **NewLocationHandler()** (4 connections) — `internal/proxy/handlers/bucket/location.go`
- *... and 15 more nodes in this community*

## Relationships

- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (50 shared connections)
- [Multipart Handler](Multipart_Handler.md) (11 shared connections)
- [Bucket NotImplemented Tests](Bucket_NotImplemented_Tests.md) (9 shared connections)
- [Bucket CRUD Tests](Bucket_CRUD_Tests.md) (5 shared connections)
- [Bucket CORS Handler](Bucket_CORS_Handler.md) (4 shared connections)
- [Bucket Versioning Handler](Bucket_Versioning_Handler.md) (3 shared connections)
- [Bucket ACL Handler](Bucket_ACL_Handler.md) (2 shared connections)
- [Bucket Logging Handler](Bucket_Logging_Handler.md) (1 shared connections)
- [Bucket Notification Handler](Bucket_Notification_Handler.md) (1 shared connections)
- [Bucket Replication Handler](Bucket_Replication_Handler.md) (1 shared connections)
- [Bucket Website Handler](Bucket_Website_Handler.md) (1 shared connections)
- [Object Handler Dispatch](Object_Handler_Dispatch.md) (1 shared connections)

## Source Files

- `internal/proxy/handlers/bucket/accelerate.go`
- `internal/proxy/handlers/bucket/base.go`
- `internal/proxy/handlers/bucket/handler.go`
- `internal/proxy/handlers/bucket/location.go`
- `internal/proxy/handlers/bucket/policy.go`
- `internal/proxy/handlers/bucket/request_payment.go`
- `internal/proxy/handlers/bucket/versioning.go`

## Audit Trail

- EXTRACTED: 153 (99%)
- INFERRED: 2 (1%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*