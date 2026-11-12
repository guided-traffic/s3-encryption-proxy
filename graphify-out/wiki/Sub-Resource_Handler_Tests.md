# Sub-Resource Handler Tests

> 80 nodes · cohesion 0.08

## Key Concepts

- **NewErrorWriter()** (91 connections) — `internal/proxy/response/errors.go`
- **NewParser()** (56 connections) — `internal/proxy/request/parser.go`
- **NewXMLWriter()** (52 connections) — `internal/proxy/response/xml.go`
- **NewBaseSubResourceHandler()** (49 connections) — `internal/proxy/handlers/bucket/base.go`
- **NewHandler()** (39 connections) — `internal/proxy/handlers/bucket/handler.go`
- **BaseSubResourceHandler** (34 connections) — `internal/proxy/handlers/bucket/base.go`
- **NewAccelerateHandler()** (11 connections) — `internal/proxy/handlers/bucket/accelerate.go`
- **NewRequestPaymentHandler()** (11 connections) — `internal/proxy/handlers/bucket/request_payment.go`
- **NewWebsiteHandler()** (10 connections) — `internal/proxy/handlers/bucket/website.go`
- **NewNotificationHandler()** (9 connections) — `internal/proxy/handlers/bucket/notification.go`
- **NewReplicationHandler()** (9 connections) — `internal/proxy/handlers/bucket/replication.go`
- **NewTaggingHandler()** (9 connections) — `internal/proxy/handlers/bucket/tagging.go`
- **NewVersioningHandler()** (8 connections) — `internal/proxy/handlers/bucket/versioning.go`
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
- *... and 55 more nodes in this community*

## Relationships

- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (79 shared connections)
- [Shutdown and Test Contexts](Shutdown_and_Test_Contexts.md) (64 shared connections)
- [Multipart Handlers and Manager](Multipart_Handlers_and_Manager.md) (31 shared connections)
- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (16 shared connections)
- [Object: Metadata Coverage Test](Object-_Metadata_Coverage_Test.md) (15 shared connections)
- [Keyencryption: Aes Test](Keyencryption-_Aes_Test.md) (8 shared connections)
- [Error Mapping](Error_Mapping.md) (7 shared connections)
- [Bucket Handler Tests](Bucket_Handler_Tests.md) (6 shared connections)
- [Response: Error Mapping Coverage Test](Response-_Error_Mapping_Coverage_Test.md) (6 shared connections)
- [Request Documents and Owner Guard](Request_Documents_and_Owner_Guard.md) (4 shared connections)
- [Checksum Verifier](Checksum_Verifier.md) (4 shared connections)
- [Multipart Checksum Answers](Multipart_Checksum_Answers.md) (3 shared connections)

## Source Files

- `internal/proxy/handlers/bucket/accelerate.go`
- `internal/proxy/handlers/bucket/accelerate_test.go`
- `internal/proxy/handlers/bucket/acl.go`
- `internal/proxy/handlers/bucket/base.go`
- `internal/proxy/handlers/bucket/bucket_crud_test.go`
- `internal/proxy/handlers/bucket/cors.go`
- `internal/proxy/handlers/bucket/handler.go`
- `internal/proxy/handlers/bucket/handlers_test.go`
- `internal/proxy/handlers/bucket/lifecycle.go`
- `internal/proxy/handlers/bucket/lifecycle_test.go`
- `internal/proxy/handlers/bucket/location_test.go`
- `internal/proxy/handlers/bucket/logging_test.go`
- `internal/proxy/handlers/bucket/notification.go`
- `internal/proxy/handlers/bucket/notification_test.go`
- `internal/proxy/handlers/bucket/policy_test.go`
- `internal/proxy/handlers/bucket/replication.go`
- `internal/proxy/handlers/bucket/replication_test.go`
- `internal/proxy/handlers/bucket/request_payment.go`
- `internal/proxy/handlers/bucket/request_payment_test.go`
- `internal/proxy/handlers/bucket/tagging.go`

## Audit Trail

- EXTRACTED: 362 (71%)
- INFERRED: 146 (29%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*