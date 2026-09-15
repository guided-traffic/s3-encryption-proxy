# Bucket Sub-Resource Handlers

> 58 nodes · cohesion 0.12

## Key Concepts

- **NewParser()** (57 connections) — `internal/proxy/request/parser.go`
- **NewXMLWriter()** (52 connections) — `internal/proxy/response/xml.go`
- **NewBaseSubResourceHandler()** (49 connections) — `internal/proxy/handlers/bucket/base.go`
- **BaseSubResourceHandler** (34 connections) — `internal/proxy/handlers/bucket/base.go`
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
- **TestNotificationHandler_ComplexConfigurations()** (7 connections) — `internal/proxy/handlers/bucket/notification_test.go`
- **TestNotificationHandler_EventTypes()** (7 connections) — `internal/proxy/handlers/bucket/notification_test.go`
- **TestNotificationHandler_Handle()** (7 connections) — `internal/proxy/handlers/bucket/notification_test.go`
- **TestNotificationHandler_HandleErrors()** (7 connections) — `internal/proxy/handlers/bucket/notification_test.go`
- **TestNotificationHandler_XMLValidation()** (7 connections) — `internal/proxy/handlers/bucket/notification_test.go`
- **TestReplicationHandler_ComplexConfigurations()** (7 connections) — `internal/proxy/handlers/bucket/replication_test.go`
- *... and 33 more nodes in this community*

## Relationships

- [Copy and Delete Object Handlers](Copy_and_Delete_Object_Handlers.md) (39 shared connections)
- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (39 shared connections)
- [Multipart Handler Constructors](Multipart_Handler_Constructors.md) (17 shared connections)
- [Bucket Crud](Bucket_Crud.md) (17 shared connections)
- [Bucket Handler Dispatch](Bucket_Handler_Dispatch.md) (14 shared connections)
- [ACL, CORS and Lifecycle Handlers](ACL,_CORS_and_Lifecycle_Handlers.md) (10 shared connections)
- [Replication and ACL Handlers](Replication_and_ACL_Handlers.md) (7 shared connections)
- [Bucket Website and Create/Delete](Bucket_Website_and_Create-Delete.md) (3 shared connections)
- [Request Parser and Framing Tests](Request_Parser_and_Framing_Tests.md) (3 shared connections)
- [Checksum Verifier Tests](Checksum_Verifier_Tests.md) (3 shared connections)
- [Logging](Logging.md) (2 shared connections)
- [Multipart Handler Coverage Tests](Multipart_Handler_Coverage_Tests.md) (2 shared connections)

## Source Files

- `internal/proxy/handlers/bucket/accelerate.go`
- `internal/proxy/handlers/bucket/accelerate_test.go`
- `internal/proxy/handlers/bucket/base.go`
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
- `internal/proxy/request/parser.go`
- `internal/proxy/response/xml.go`

## Audit Trail

- EXTRACTED: 272 (74%)
- INFERRED: 96 (26%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*