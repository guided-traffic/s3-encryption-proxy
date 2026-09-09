# Bucket Sub-Resource Registry

> 56 nodes · cohesion 0.06

## Key Concepts

- **Handler** (35 connections) — `internal/proxy/handlers/bucket/handler.go`
- **BaseSubResourceHandler** (33 connections) — `internal/proxy/handlers/bucket/base.go`
- **CORSHandler** (10 connections) — `internal/proxy/handlers/bucket/cors.go`
- **LoggingHandler** (9 connections) — `internal/proxy/handlers/bucket/logging.go`
- **AccelerateHandler** (8 connections) — `internal/proxy/handlers/bucket/accelerate.go`
- **NotificationHandler** (8 connections) — `internal/proxy/handlers/bucket/notification.go`
- **RequestPaymentHandler** (8 connections) — `internal/proxy/handlers/bucket/request_payment.go`
- **VersioningHandler** (8 connections) — `internal/proxy/handlers/bucket/versioning.go`
- **.Handle()** (7 connections) — `internal/proxy/handlers/bucket/cors.go`
- **LocationHandler** (7 connections) — `internal/proxy/handlers/bucket/location.go`
- **.Handle()** (6 connections) — `internal/proxy/handlers/bucket/logging.go`
- **.Handle()** (5 connections) — `internal/proxy/handlers/bucket/accelerate.go`
- **.Handle()** (5 connections) — `internal/proxy/handlers/bucket/handler.go`
- **.Handle()** (5 connections) — `internal/proxy/handlers/bucket/notification.go`
- **.Handle()** (5 connections) — `internal/proxy/handlers/bucket/request_payment.go`
- **.Handle()** (5 connections) — `internal/proxy/handlers/bucket/versioning.go`
- **.handleGetBucketAccelerateConfiguration()** (4 connections) — `internal/proxy/handlers/bucket/accelerate.go`
- **.handlePutBucketAccelerateConfiguration()** (4 connections) — `internal/proxy/handlers/bucket/accelerate.go`
- **.handleDeleteCORS()** (4 connections) — `internal/proxy/handlers/bucket/cors.go`
- **.handleGetCORS()** (4 connections) — `internal/proxy/handlers/bucket/cors.go`
- **.handleMockCORS()** (4 connections) — `internal/proxy/handlers/bucket/cors.go`
- **.handlePutCORS()** (4 connections) — `internal/proxy/handlers/bucket/cors.go`
- **.handleBaseBucketOperations()** (4 connections) — `internal/proxy/handlers/bucket/handler.go`
- **.Handle()** (4 connections) — `internal/proxy/handlers/bucket/location.go`
- **.handleGetLocation()** (4 connections) — `internal/proxy/handlers/bucket/location.go`
- *... and 31 more nodes in this community*

## Relationships

- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (63 shared connections)
- [Bucket Sub-Resource Tests](Bucket_Sub-Resource_Tests.md) (17 shared connections)
- [Multipart Handler Construction](Multipart_Handler_Construction.md) (10 shared connections)
- [Bucket Lifecycle Handler](Bucket_Lifecycle_Handler.md) (9 shared connections)
- [Multipart Handler Tests](Multipart_Handler_Tests.md) (2 shared connections)
- [Object Handler Sub-Resources](Object_Handler_Sub-Resources.md) (1 shared connections)

## Source Files

- `internal/proxy/handlers/bucket/accelerate.go`
- `internal/proxy/handlers/bucket/base.go`
- `internal/proxy/handlers/bucket/cors.go`
- `internal/proxy/handlers/bucket/handler.go`
- `internal/proxy/handlers/bucket/location.go`
- `internal/proxy/handlers/bucket/logging.go`
- `internal/proxy/handlers/bucket/notification.go`
- `internal/proxy/handlers/bucket/request_payment.go`
- `internal/proxy/handlers/bucket/versioning.go`

## Audit Trail

- EXTRACTED: 191 (98%)
- INFERRED: 3 (2%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*