# Bucket Sub-Resource Handlers

> 45 nodes · cohesion 0.15

## Key Concepts

- **NewParser()** (57 connections) — `internal/proxy/request/parser.go`
- **NewXMLWriter()** (52 connections) — `internal/proxy/response/xml.go`
- **NewBaseSubResourceHandler()** (49 connections) — `internal/proxy/handlers/bucket/base.go`
- **NewAccelerateHandler()** (11 connections) — `internal/proxy/handlers/bucket/accelerate.go`
- **NewRequestPaymentHandler()** (11 connections) — `internal/proxy/handlers/bucket/request_payment.go`
- **NewWebsiteHandler()** (10 connections) — `internal/proxy/handlers/bucket/website.go`
- **NewNotificationHandler()** (9 connections) — `internal/proxy/handlers/bucket/notification.go`
- **NewTaggingHandler()** (9 connections) — `internal/proxy/handlers/bucket/tagging.go`
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
- **request_payment_test.go** (7 connections) — `internal/proxy/handlers/bucket/request_payment_test.go`
- **TestRequestPaymentHandler_BillingImplications()** (7 connections) — `internal/proxy/handlers/bucket/request_payment_test.go`
- **TestRequestPaymentHandler_Handle()** (7 connections) — `internal/proxy/handlers/bucket/request_payment_test.go`
- **TestRequestPaymentHandler_HandleErrors()** (7 connections) — `internal/proxy/handlers/bucket/request_payment_test.go`
- *... and 20 more nodes in this community*

## Relationships

- [Copy and Delete Object Handlers](Copy_and_Delete_Object_Handlers.md) (30 shared connections)
- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (30 shared connections)
- [Bucket Sub-Resource Handler Registry](Bucket_Sub-Resource_Handler_Registry.md) (21 shared connections)
- [Bucket Replication Handler](Bucket_Replication_Handler.md) (15 shared connections)
- [Bucket Versioning Handler](Bucket_Versioning_Handler.md) (12 shared connections)
- [Multipart Handler Wiring](Multipart_Handler_Wiring.md) (11 shared connections)
- [Bucket ACL and Accelerate Handlers](Bucket_ACL_and_Accelerate_Handlers.md) (6 shared connections)
- [Bucket Lifecycle Handler](Bucket_Lifecycle_Handler.md) (6 shared connections)
- [Checksum Verifier Tests](Checksum_Verifier_Tests.md) (3 shared connections)
- [Multipart Handler Coverage Tests](Multipart_Handler_Coverage_Tests.md) (2 shared connections)
- [Multipart Handler Constructors](Multipart_Handler_Constructors.md) (2 shared connections)
- [Request Parser and Framing Tests](Request_Parser_and_Framing_Tests.md) (2 shared connections)

## Source Files

- `internal/proxy/handlers/bucket/accelerate.go`
- `internal/proxy/handlers/bucket/accelerate_test.go`
- `internal/proxy/handlers/bucket/base.go`
- `internal/proxy/handlers/bucket/notification.go`
- `internal/proxy/handlers/bucket/notification_test.go`
- `internal/proxy/handlers/bucket/request_payment.go`
- `internal/proxy/handlers/bucket/request_payment_test.go`
- `internal/proxy/handlers/bucket/tagging.go`
- `internal/proxy/handlers/bucket/tagging_test.go`
- `internal/proxy/handlers/bucket/website.go`
- `internal/proxy/handlers/bucket/website_test.go`
- `internal/proxy/request/parser.go`
- `internal/proxy/response/xml.go`

## Audit Trail

- EXTRACTED: 215 (72%)
- INFERRED: 85 (28%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*