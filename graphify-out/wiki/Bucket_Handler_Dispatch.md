# Bucket Handler Dispatch

> 42 nodes · cohesion 0.07

## Key Concepts

- **Handler** (37 connections) — `internal/proxy/handlers/bucket/handler.go`
- **AccelerateHandler** (8 connections) — `internal/proxy/handlers/bucket/accelerate.go`
- **NotificationHandler** (8 connections) — `internal/proxy/handlers/bucket/notification.go`
- **RequestPaymentHandler** (8 connections) — `internal/proxy/handlers/bucket/request_payment.go`
- **VersioningHandler** (8 connections) — `internal/proxy/handlers/bucket/versioning.go`
- **LocationHandler** (7 connections) — `internal/proxy/handlers/bucket/location.go`
- **.handleGetBucketNotificationConfiguration()** (6 connections) — `internal/proxy/handlers/bucket/notification.go`
- **.Handle()** (5 connections) — `internal/proxy/handlers/bucket/accelerate.go`
- **.handleGetBucketAccelerateConfiguration()** (5 connections) — `internal/proxy/handlers/bucket/accelerate.go`
- **.Handle()** (5 connections) — `internal/proxy/handlers/bucket/handler.go`
- **.handleGetLocation()** (5 connections) — `internal/proxy/handlers/bucket/location.go`
- **.Handle()** (5 connections) — `internal/proxy/handlers/bucket/notification.go`
- **.handlePutBucketNotificationConfiguration()** (5 connections) — `internal/proxy/handlers/bucket/notification.go`
- **.Handle()** (5 connections) — `internal/proxy/handlers/bucket/request_payment.go`
- **.handleGetBucketRequestPayment()** (5 connections) — `internal/proxy/handlers/bucket/request_payment.go`
- **.Handle()** (5 connections) — `internal/proxy/handlers/bucket/versioning.go`
- **.handleGetBucketVersioning()** (5 connections) — `internal/proxy/handlers/bucket/versioning.go`
- **.handlePutBucketVersioning()** (5 connections) — `internal/proxy/handlers/bucket/versioning.go`
- **.handlePutBucketAccelerateConfiguration()** (4 connections) — `internal/proxy/handlers/bucket/accelerate.go`
- **.handleBaseBucketOperations()** (4 connections) — `internal/proxy/handlers/bucket/handler.go`
- **.Handle()** (4 connections) — `internal/proxy/handlers/bucket/location.go`
- **.handlePutBucketRequestPayment()** (4 connections) — `internal/proxy/handlers/bucket/request_payment.go`
- **NewLocationHandler()** (4 connections) — `internal/proxy/handlers/bucket/location.go`
- **IsAWSProtocolQueryParam()** (4 connections) — `internal/proxy/request/queryparams.go`
- **TestReqIsAWSProtocolQueryParam()** (3 connections) — `internal/proxy/request/queryparams_test.go`
- *... and 17 more nodes in this community*

## Relationships

- [Replication and ACL Handlers](Replication_and_ACL_Handlers.md) (20 shared connections)
- [Bucket Website and Create/Delete](Bucket_Website_and_Create-Delete.md) (18 shared connections)
- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (14 shared connections)
- [ACL, CORS and Lifecycle Handlers](ACL,_CORS_and_Lifecycle_Handlers.md) (13 shared connections)
- [Multipart Handler Constructors](Multipart_Handler_Constructors.md) (5 shared connections)
- [Bucket Crud](Bucket_Crud.md) (3 shared connections)
- [Logging](Logging.md) (2 shared connections)
- [Subresource Documents](Subresource_Documents.md) (1 shared connections)
- [Configuration Struct and Accessors](Configuration_Struct_and_Accessors.md) (1 shared connections)
- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (1 shared connections)

## Source Files

- `internal/proxy/handlers/bucket/accelerate.go`
- `internal/proxy/handlers/bucket/handler.go`
- `internal/proxy/handlers/bucket/location.go`
- `internal/proxy/handlers/bucket/notification.go`
- `internal/proxy/handlers/bucket/request_payment.go`
- `internal/proxy/handlers/bucket/versioning.go`
- `internal/proxy/request/queryparams.go`
- `internal/proxy/request/queryparams_test.go`

## Audit Trail

- EXTRACTED: 134 (98%)
- INFERRED: 3 (2%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*