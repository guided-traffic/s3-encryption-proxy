# Bucket Sub-Resource Tests

> 71 nodes · cohesion 0.10

## Key Concepts

- **NewErrorWriter()** (76 connections) — `internal/proxy/response/errors.go`
- **NewXMLWriter()** (61 connections) — `internal/proxy/response/xml.go`
- **NewParser()** (52 connections) — `internal/proxy/request/parser.go`
- **NewBaseSubResourceHandler()** (49 connections) — `internal/proxy/handlers/bucket/base.go`
- **NewAccelerateHandler()** (11 connections) — `internal/proxy/handlers/bucket/accelerate.go`
- **NewRequestPaymentHandler()** (11 connections) — `internal/proxy/handlers/bucket/request_payment.go`
- **NewWebsiteHandler()** (10 connections) — `internal/proxy/handlers/bucket/website.go`
- **NewNotificationHandler()** (9 connections) — `internal/proxy/handlers/bucket/notification.go`
- **NewReplicationHandler()** (9 connections) — `internal/proxy/handlers/bucket/replication.go`
- **NewTaggingHandler()** (9 connections) — `internal/proxy/handlers/bucket/tagging.go`
- **NewVersioningHandler()** (8 connections) — `internal/proxy/handlers/bucket/versioning.go`
- **accelerate_test.go** (7 connections) — `internal/proxy/handlers/bucket/accelerate_test.go`
- **TestAccelerateHandler_AccelerateStatuses()** (7 connections) — `internal/proxy/handlers/bucket/accelerate_test.go`
- **TestAccelerateHandler_AccelerationBenefits()** (7 connections) — `internal/proxy/handlers/bucket/accelerate_test.go`
- **TestAccelerateHandler_BucketNamingRequirements()** (7 connections) — `internal/proxy/handlers/bucket/accelerate_test.go`
- **TestAccelerateHandler_ContentTypeHandling()** (7 connections) — `internal/proxy/handlers/bucket/accelerate_test.go`
- **TestAccelerateHandler_Handle()** (7 connections) — `internal/proxy/handlers/bucket/accelerate_test.go`
- **TestAccelerateHandler_HandleErrors()** (7 connections) — `internal/proxy/handlers/bucket/accelerate_test.go`
- **TestAccelerateHandler_XMLValidation()** (7 connections) — `internal/proxy/handlers/bucket/accelerate_test.go`
- **TestLifecycleHandler_ComplexRules()** (7 connections) — `internal/proxy/handlers/bucket/lifecycle_test.go`
- **TestLifecycleHandler_Handle()** (7 connections) — `internal/proxy/handlers/bucket/lifecycle_test.go`
- **TestNotificationHandler_ComplexConfigurations()** (7 connections) — `internal/proxy/handlers/bucket/notification_test.go`
- **TestNotificationHandler_EventTypes()** (7 connections) — `internal/proxy/handlers/bucket/notification_test.go`
- **TestNotificationHandler_Handle()** (7 connections) — `internal/proxy/handlers/bucket/notification_test.go`
- **TestNotificationHandler_HandleErrors()** (7 connections) — `internal/proxy/handlers/bucket/notification_test.go`
- *... and 46 more nodes in this community*

## Relationships

- [Config Accessor Tests](Config_Accessor_Tests.md) (49 shared connections)
- [S3 Error Mapping](S3_Error_Mapping.md) (27 shared connections)
- [Multipart Handler Construction](Multipart_Handler_Construction.md) (20 shared connections)
- [Bucket Sub-Resource Registry](Bucket_Sub-Resource_Registry.md) (17 shared connections)
- [Bucket Lifecycle Handler](Bucket_Lifecycle_Handler.md) (13 shared connections)
- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (7 shared connections)
- [Multipart Handler Tests](Multipart_Handler_Tests.md) (3 shared connections)
- [Multipart Create Handler Tests](Multipart_Create_Handler_Tests.md) (3 shared connections)
- [Request Body Parser Tests](Request_Body_Parser_Tests.md) (2 shared connections)
- [Configuration Accessors](Configuration_Accessors.md) (1 shared connections)
- [Object GET Handler Tests](Object_GET_Handler_Tests.md) (1 shared connections)
- [ListBuckets Root Handler](ListBuckets_Root_Handler.md) (1 shared connections)

## Source Files

- `internal/proxy/handlers/bucket/accelerate.go`
- `internal/proxy/handlers/bucket/accelerate_test.go`
- `internal/proxy/handlers/bucket/base.go`
- `internal/proxy/handlers/bucket/lifecycle_test.go`
- `internal/proxy/handlers/bucket/notification.go`
- `internal/proxy/handlers/bucket/notification_test.go`
- `internal/proxy/handlers/bucket/replication.go`
- `internal/proxy/handlers/bucket/replication_test.go`
- `internal/proxy/handlers/bucket/request_payment.go`
- `internal/proxy/handlers/bucket/request_payment_test.go`
- `internal/proxy/handlers/bucket/tagging.go`
- `internal/proxy/handlers/bucket/tagging_test.go`
- `internal/proxy/handlers/bucket/versioning.go`
- `internal/proxy/handlers/bucket/versioning_test.go`
- `internal/proxy/handlers/bucket/website.go`
- `internal/proxy/handlers/bucket/website_test.go`
- `internal/proxy/handlers/multipart/copy_test.go`
- `internal/proxy/handlers/object/copy_test.go`
- `internal/proxy/handlers/object/delete_object_test.go`
- `internal/proxy/request/parser.go`

## Audit Trail

- EXTRACTED: 286 (71%)
- INFERRED: 119 (29%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*