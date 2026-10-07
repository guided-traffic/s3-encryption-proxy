# Bucket ACL and Accelerate Handlers

> 90 nodes · cohesion 0.05

## Key Concepts

- **net/http.Request** (187 connections)
- **net/http.ResponseWriter** (135 connections)
- **Parser** (38 connections) — `internal/proxy/request/parser.go`
- **.readBody()** (12 connections) — `internal/proxy/request/parser.go`
- **LifecycleHandler** (9 connections) — `internal/proxy/handlers/bucket/lifecycle.go`
- **LoggingHandler** (9 connections) — `internal/proxy/handlers/bucket/logging.go`
- **WebsiteHandler** (9 connections) — `internal/proxy/handlers/bucket/website.go`
- **.writeErrorDocument()** (8 connections) — `internal/proxy/response/errors.go`
- **TaggingHandler** (7 connections) — `internal/proxy/handlers/bucket/tagging.go`
- **verifying()** (7 connections) — `internal/proxy/request/checksum.go`
- **isAWSChunkedRequest()** (7 connections) — `internal/proxy/request/streaming_aws_decoder.go`
- **.Handle()** (7 connections) — `internal/proxy/handlers/multipart/create.go`
- **.StreamingReader()** (7 connections) — `internal/proxy/request/parser.go`
- **.handleGetACL()** (6 connections) — `internal/proxy/handlers/bucket/acl.go`
- **.Handle()** (6 connections) — `internal/proxy/handlers/bucket/lifecycle.go`
- **.handleGetBucketLifecycleConfiguration()** (6 connections) — `internal/proxy/handlers/bucket/lifecycle.go`
- **.Handle()** (6 connections) — `internal/proxy/handlers/bucket/logging.go`
- **.handleGetLogging()** (6 connections) — `internal/proxy/handlers/bucket/logging.go`
- **.handleGetBucketNotificationConfiguration()** (6 connections) — `internal/proxy/handlers/bucket/notification.go`
- **.Handle()** (6 connections) — `internal/proxy/handlers/bucket/tagging.go`
- **.handleGetBucketTagging()** (6 connections) — `internal/proxy/handlers/bucket/tagging.go`
- **.Handle()** (6 connections) — `internal/proxy/handlers/bucket/website.go`
- **.handleGetBucketWebsite()** (6 connections) — `internal/proxy/handlers/bucket/website.go`
- **readDocument()** (6 connections) — `internal/proxy/handlers/object/helpers.go`
- **.Handle()** (5 connections) — `internal/proxy/handlers/bucket/accelerate.go`
- *... and 65 more nodes in this community*

## Relationships

- [Object Response Header Helpers](Object_Response_Header_Helpers.md) (74 shared connections)
- [Bucket CORS Handler](Bucket_CORS_Handler.md) (35 shared connections)
- [Multipart ListParts Handler](Multipart_ListParts_Handler.md) (27 shared connections)
- [Multipart Handler Wiring](Multipart_Handler_Wiring.md) (27 shared connections)
- [Bucket Sub-Resource Handler Registry](Bucket_Sub-Resource_Handler_Registry.md) (22 shared connections)
- [Object Sub-Resource Dispatch](Object_Sub-Resource_Dispatch.md) (15 shared connections)
- [SigV4 Header and Presign Tests](SigV4_Header_and_Presign_Tests.md) (14 shared connections)
- [Health Probes and Request Tracker](Health_Probes_and_Request_Tracker.md) (13 shared connections)
- [Object Listing Handler](Object_Listing_Handler.md) (9 shared connections)
- [Object Handler Dependencies](Object_Handler_Dependencies.md) (8 shared connections)
- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (6 shared connections)
- [Checksum](Checksum.md) (6 shared connections)

## Source Files

- `internal/proxy/handlers/bucket/accelerate.go`
- `internal/proxy/handlers/bucket/acl.go`
- `internal/proxy/handlers/bucket/base.go`
- `internal/proxy/handlers/bucket/handler.go`
- `internal/proxy/handlers/bucket/lifecycle.go`
- `internal/proxy/handlers/bucket/location.go`
- `internal/proxy/handlers/bucket/logging.go`
- `internal/proxy/handlers/bucket/notification.go`
- `internal/proxy/handlers/bucket/operations.go`
- `internal/proxy/handlers/bucket/request_payment.go`
- `internal/proxy/handlers/bucket/tagging.go`
- `internal/proxy/handlers/bucket/versioning.go`
- `internal/proxy/handlers/bucket/website.go`
- `internal/proxy/handlers/health/handler_coverage_test.go`
- `internal/proxy/handlers/multipart/copy.go`
- `internal/proxy/handlers/multipart/create.go`
- `internal/proxy/handlers/object/acl.go`
- `internal/proxy/handlers/object/copy_bench_test.go`
- `internal/proxy/handlers/object/helpers.go`
- `internal/proxy/handlers/object/objectlock.go`

## Audit Trail

- EXTRACTED: 526 (97%)
- INFERRED: 18 (3%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*