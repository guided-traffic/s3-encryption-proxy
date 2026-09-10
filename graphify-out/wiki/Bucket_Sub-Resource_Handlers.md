# Bucket Sub-Resource Handlers

> 69 nodes · cohesion 0.06

## Key Concepts

- **net/http.Request** (147 connections)
- **net/http.ResponseWriter** (121 connections)
- **LifecycleHandler** (9 connections) — `internal/proxy/handlers/bucket/lifecycle.go`
- **LoggingHandler** (9 connections) — `internal/proxy/handlers/bucket/logging.go`
- **ReplicationHandler** (9 connections) — `internal/proxy/handlers/bucket/replication.go`
- **WebsiteHandler** (9 connections) — `internal/proxy/handlers/bucket/website.go`
- **NotificationHandler** (8 connections) — `internal/proxy/handlers/bucket/notification.go`
- **TaggingHandler** (7 connections) — `internal/proxy/handlers/bucket/tagging.go`
- **.ReadBody()** (7 connections) — `internal/proxy/request/parser.go`
- **.writeErrorDocument()** (7 connections) — `internal/proxy/response/errors.go`
- **.Handle()** (6 connections) — `internal/proxy/handlers/bucket/lifecycle.go`
- **.Handle()** (6 connections) — `internal/proxy/handlers/bucket/logging.go`
- **.Handle()** (6 connections) — `internal/proxy/handlers/bucket/replication.go`
- **.Handle()** (6 connections) — `internal/proxy/handlers/bucket/tagging.go`
- **.Handle()** (6 connections) — `internal/proxy/handlers/bucket/website.go`
- **isAWSChunkedRequest()** (6 connections) — `internal/proxy/request/streaming_aws_decoder.go`
- **.Handle()** (5 connections) — `internal/proxy/handlers/bucket/notification.go`
- **.Handle()** (5 connections) — `internal/proxy/handlers/multipart/upload.go`
- **.uploadSegmentedPart()** (5 connections) — `internal/proxy/handlers/multipart/upload.go`
- **.Handle()** (5 connections) — `internal/proxy/handlers/object/acl.go`
- **.StreamingReader()** (5 connections) — `internal/proxy/request/parser.go`
- **.handleDeleteBucketLifecycle()** (4 connections) — `internal/proxy/handlers/bucket/lifecycle.go`
- **.handleGetBucketLifecycleConfiguration()** (4 connections) — `internal/proxy/handlers/bucket/lifecycle.go`
- **.handlePutBucketLifecycleConfiguration()** (4 connections) — `internal/proxy/handlers/bucket/lifecycle.go`
- **.handleDeleteLogging()** (4 connections) — `internal/proxy/handlers/bucket/logging.go`
- *... and 44 more nodes in this community*

## Relationships

- [Bucket Handler Routing](Bucket_Handler_Routing.md) (50 shared connections)
- [Object Operations Handler](Object_Operations_Handler.md) (35 shared connections)
- [Multipart Handler](Multipart_Handler.md) (26 shared connections)
- [Object Handler Dispatch](Object_Handler_Dispatch.md) (14 shared connections)
- [Object Helper Functions](Object_Helper_Functions.md) (13 shared connections)
- [Bucket CORS Handler](Bucket_CORS_Handler.md) (10 shared connections)
- [Request Parser Tests](Request_Parser_Tests.md) (10 shared connections)
- [Bucket ACL Handler](Bucket_ACL_Handler.md) (8 shared connections)
- [Object Tagging Handler](Object_Tagging_Handler.md) (8 shared connections)
- [Object Listing](Object_Listing.md) (7 shared connections)
- [SigV4 Signing Helper](SigV4_Signing_Helper.md) (6 shared connections)
- [SigV4 Header Authentication](SigV4_Header_Authentication.md) (6 shared connections)

## Source Files

- `internal/proxy/handlers/bucket/handler.go`
- `internal/proxy/handlers/bucket/lifecycle.go`
- `internal/proxy/handlers/bucket/logging.go`
- `internal/proxy/handlers/bucket/notification.go`
- `internal/proxy/handlers/bucket/operations.go`
- `internal/proxy/handlers/bucket/replication.go`
- `internal/proxy/handlers/bucket/tagging.go`
- `internal/proxy/handlers/bucket/website.go`
- `internal/proxy/handlers/health/handler.go`
- `internal/proxy/handlers/multipart/copy.go`
- `internal/proxy/handlers/multipart/upload.go`
- `internal/proxy/handlers/object/acl.go`
- `internal/proxy/handlers/root/handler.go`
- `internal/proxy/request/parser.go`
- `internal/proxy/request/streaming_aws_decoder.go`
- `internal/proxy/response/errors.go`
- `internal/proxy/response/xml.go`

## Audit Trail

- EXTRACTED: 390 (98%)
- INFERRED: 8 (2%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*