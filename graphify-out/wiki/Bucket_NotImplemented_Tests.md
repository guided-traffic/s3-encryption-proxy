# Bucket NotImplemented Tests

> 28 nodes · cohesion 0.20

## Key Concepts

- **NewParser()** (51 connections) — `internal/proxy/request/parser.go`
- **NewBaseSubResourceHandler()** (49 connections) — `internal/proxy/handlers/bucket/base.go`
- **NewAccelerateHandler()** (11 connections) — `internal/proxy/handlers/bucket/accelerate.go`
- **NewRequestPaymentHandler()** (11 connections) — `internal/proxy/handlers/bucket/request_payment.go`
- **NewTaggingHandler()** (9 connections) — `internal/proxy/handlers/bucket/tagging.go`
- **accelerate_test.go** (7 connections) — `internal/proxy/handlers/bucket/accelerate_test.go`
- **TestAccelerateHandler_AccelerateStatuses()** (7 connections) — `internal/proxy/handlers/bucket/accelerate_test.go`
- **TestAccelerateHandler_AccelerationBenefits()** (7 connections) — `internal/proxy/handlers/bucket/accelerate_test.go`
- **TestAccelerateHandler_BucketNamingRequirements()** (7 connections) — `internal/proxy/handlers/bucket/accelerate_test.go`
- **TestAccelerateHandler_ContentTypeHandling()** (7 connections) — `internal/proxy/handlers/bucket/accelerate_test.go`
- **TestAccelerateHandler_Handle()** (7 connections) — `internal/proxy/handlers/bucket/accelerate_test.go`
- **TestAccelerateHandler_HandleErrors()** (7 connections) — `internal/proxy/handlers/bucket/accelerate_test.go`
- **TestAccelerateHandler_XMLValidation()** (7 connections) — `internal/proxy/handlers/bucket/accelerate_test.go`
- **request_payment_test.go** (7 connections) — `internal/proxy/handlers/bucket/request_payment_test.go`
- **TestRequestPaymentHandler_BillingImplications()** (7 connections) — `internal/proxy/handlers/bucket/request_payment_test.go`
- **TestRequestPaymentHandler_Handle()** (7 connections) — `internal/proxy/handlers/bucket/request_payment_test.go`
- **TestRequestPaymentHandler_HandleErrors()** (7 connections) — `internal/proxy/handlers/bucket/request_payment_test.go`
- **TestRequestPaymentHandler_PayerTypes()** (7 connections) — `internal/proxy/handlers/bucket/request_payment_test.go`
- **TestRequestPaymentHandler_RequesterPaysHeaders()** (7 connections) — `internal/proxy/handlers/bucket/request_payment_test.go`
- **TestRequestPaymentHandler_RequesterPaysImplications()** (7 connections) — `internal/proxy/handlers/bucket/request_payment_test.go`
- **TestRequestPaymentHandler_XMLValidation()** (7 connections) — `internal/proxy/handlers/bucket/request_payment_test.go`
- **TestTaggingHandler_Handle()** (7 connections) — `internal/proxy/handlers/bucket/tagging_test.go`
- **TestTaggingHandler_HandleErrors()** (7 connections) — `internal/proxy/handlers/bucket/tagging_test.go`
- **TestTaggingHandler_MaxTagLimits()** (7 connections) — `internal/proxy/handlers/bucket/tagging_test.go`
- **TestTaggingHandler_SpecialCharacterHandling()** (7 connections) — `internal/proxy/handlers/bucket/tagging_test.go`
- *... and 3 more nodes in this community*

## Relationships

- [XML Response Helpers](XML_Response_Helpers.md) (19 shared connections)
- [Error Response Tests](Error_Response_Tests.md) (19 shared connections)
- [Config Env Expansion](Config_Env_Expansion.md) (19 shared connections)
- [Bucket Website Handler](Bucket_Website_Handler.md) (12 shared connections)
- [Bucket Notification Handler](Bucket_Notification_Handler.md) (10 shared connections)
- [Bucket Replication Handler](Bucket_Replication_Handler.md) (10 shared connections)
- [Bucket Handler Routing](Bucket_Handler_Routing.md) (9 shared connections)
- [Bucket CRUD Tests](Bucket_CRUD_Tests.md) (9 shared connections)
- [Multipart Handler](Multipart_Handler.md) (9 shared connections)
- [Bucket Versioning Handler](Bucket_Versioning_Handler.md) (8 shared connections)
- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (2 shared connections)
- [Request Parser Tests](Request_Parser_Tests.md) (2 shared connections)

## Source Files

- `internal/proxy/handlers/bucket/accelerate.go`
- `internal/proxy/handlers/bucket/accelerate_test.go`
- `internal/proxy/handlers/bucket/base.go`
- `internal/proxy/handlers/bucket/request_payment.go`
- `internal/proxy/handlers/bucket/request_payment_test.go`
- `internal/proxy/handlers/bucket/tagging.go`
- `internal/proxy/handlers/bucket/tagging_test.go`
- `internal/proxy/request/parser.go`

## Audit Trail

- EXTRACTED: 143 (69%)
- INFERRED: 65 (31%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*