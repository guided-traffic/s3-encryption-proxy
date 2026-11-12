# Object: Metadata Coverage Test

> 33 nodes · cohesion 0.09

## Key Concepts

- **Handler** (45 connections) — `internal/proxy/handlers/bucket/handler.go`
- **LoggingHandler** (9 connections) — `internal/proxy/handlers/bucket/logging.go`
- **AccelerateHandler** (8 connections) — `internal/proxy/handlers/bucket/accelerate.go`
- **NotificationHandler** (8 connections) — `internal/proxy/handlers/bucket/notification.go`
- **RequestPaymentHandler** (8 connections) — `internal/proxy/handlers/bucket/request_payment.go`
- **VersioningHandler** (8 connections) — `internal/proxy/handlers/bucket/versioning.go`
- **LocationHandler** (7 connections) — `internal/proxy/handlers/bucket/location.go`
- **.handleGetBucketNotificationConfiguration()** (6 connections) — `internal/proxy/handlers/bucket/notification.go`
- **.Handle()** (5 connections) — `internal/proxy/handlers/bucket/accelerate.go`
- **.handleGetBucketAccelerateConfiguration()** (5 connections) — `internal/proxy/handlers/bucket/accelerate.go`
- **.Handle()** (5 connections) — `internal/proxy/handlers/bucket/notification.go`
- **.handlePutBucketNotificationConfiguration()** (5 connections) — `internal/proxy/handlers/bucket/notification.go`
- **.Handle()** (5 connections) — `internal/proxy/handlers/bucket/versioning.go`
- **.handleGetBucketVersioning()** (5 connections) — `internal/proxy/handlers/bucket/versioning.go`
- **.handlePutBucketVersioning()** (5 connections) — `internal/proxy/handlers/bucket/versioning.go`
- **IsAWSProtocolQueryParam()** (5 connections) — `internal/proxy/request/queryparams.go`
- **.handlePutBucketAccelerateConfiguration()** (4 connections) — `internal/proxy/handlers/bucket/accelerate.go`
- **.Handle()** (4 connections) — `internal/proxy/handlers/bucket/handler.go`
- **NewLocationHandler()** (4 connections) — `internal/proxy/handlers/bucket/location.go`
- **NewLoggingHandler()** (4 connections) — `internal/proxy/handlers/bucket/logging.go`
- **TestReqIsAWSProtocolQueryParam()** (3 connections) — `internal/proxy/request/queryparams_test.go`
- **.GetAccelerateHandler()** (2 connections) — `internal/proxy/handlers/bucket/handler.go`
- **.GetACLHandler()** (2 connections) — `internal/proxy/handlers/bucket/handler.go`
- **.GetCORSHandler()** (2 connections) — `internal/proxy/handlers/bucket/handler.go`
- **.GetLocationHandler()** (2 connections) — `internal/proxy/handlers/bucket/handler.go`
- *... and 8 more nodes in this community*

## Relationships

- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (50 shared connections)
- [Sub-Resource Handler Tests](Sub-Resource_Handler_Tests.md) (15 shared connections)
- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (11 shared connections)
- [Multipart Handlers and Manager](Multipart_Handlers_and_Manager.md) (5 shared connections)
- [Misc (24)](Misc_24.md) (2 shared connections)
- [Request Documents and Owner Guard](Request_Documents_and_Owner_Guard.md) (1 shared connections)
- [ADR Corpus and Release History](ADR_Corpus_and_Release_History.md) (1 shared connections)
- [Etag: Etag](Etag-_Etag.md) (1 shared connections)
- [Bucket: Subresource Documents (3)](Bucket-_Subresource_Documents_3.md) (1 shared connections)
- [S3 API Behaviour](S3_API_Behaviour.md) (1 shared connections)
- [Shutdown and Test Contexts](Shutdown_and_Test_Contexts.md) (1 shared connections)

## Source Files

- `internal/proxy/handlers/bucket/accelerate.go`
- `internal/proxy/handlers/bucket/handler.go`
- `internal/proxy/handlers/bucket/listing.go`
- `internal/proxy/handlers/bucket/location.go`
- `internal/proxy/handlers/bucket/logging.go`
- `internal/proxy/handlers/bucket/notification.go`
- `internal/proxy/handlers/bucket/request_payment.go`
- `internal/proxy/handlers/bucket/versioning.go`
- `internal/proxy/request/queryparams.go`
- `internal/proxy/request/queryparams_test.go`

## Audit Trail

- EXTRACTED: 125 (93%)
- INFERRED: 10 (7%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*