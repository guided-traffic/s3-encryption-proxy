# Multipart Handler

> 44 nodes · cohesion 0.15

## Key Concepts

- **github.com/sirupsen/logrus.Entry** (62 connections)
- **Manager** (35 connections) — `internal/orchestration/manager.go`
- **Parser** (31 connections) — `internal/proxy/request/parser.go`
- **ErrorWriter** (31 connections) — `internal/proxy/response/errors.go`
- **S3BackendInterface** (30 connections) — `internal/proxy/interfaces/s3_backend.go`
- **XMLWriter** (28 connections) — `internal/proxy/response/xml.go`
- **Handler** (20 connections) — `internal/proxy/handlers/multipart/handler.go`
- **NewHandler()** (17 connections) — `internal/proxy/handlers/multipart/handler.go`
- **NewHandler()** (17 connections) — `internal/proxy/handlers/object/handler.go`
- **NewCompleteHandler()** (16 connections) — `internal/proxy/handlers/multipart/complete.go`
- **UploadHandler** (14 connections) — `internal/proxy/handlers/multipart/upload.go`
- **AbortHandler** (13 connections) — `internal/proxy/handlers/multipart/abort.go`
- **CompleteHandler** (13 connections) — `internal/proxy/handlers/multipart/complete.go`
- **CreateHandler** (13 connections) — `internal/proxy/handlers/multipart/create.go`
- **NewAbortHandler()** (12 connections) — `internal/proxy/handlers/multipart/abort.go`
- **ListHandler** (12 connections) — `internal/proxy/handlers/multipart/list.go`
- **NewListHandler()** (10 connections) — `internal/proxy/handlers/multipart/list.go`
- **ACLHandler** (10 connections) — `internal/proxy/handlers/object/acl.go`
- **CopyHandler** (9 connections) — `internal/proxy/handlers/multipart/copy.go`
- **NewCopyHandler()** (8 connections) — `internal/proxy/handlers/multipart/copy.go`
- **NewACLHandler()** (8 connections) — `internal/proxy/handlers/object/acl.go`
- **NewTaggingHandler()** (8 connections) — `internal/proxy/handlers/object/tagging.go`
- **.setupRoutes()** (7 connections) — `internal/proxy/router.go`
- **Handler** (7 connections) — `internal/proxy/handlers/root/handler.go`
- **.HandleListParts()** (4 connections) — `internal/proxy/handlers/multipart/list.go`
- *... and 19 more nodes in this community*

## Relationships

- [Multipart Handler Unit Tests](Multipart_Handler_Unit_Tests.md) (32 shared connections)
- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (26 shared connections)
- [Multipart Handler Tests](Multipart_Handler_Tests.md) (16 shared connections)
- [Bucket Handler Routing](Bucket_Handler_Routing.md) (11 shared connections)
- [Bucket NotImplemented Tests](Bucket_NotImplemented_Tests.md) (9 shared connections)
- [Object Helper Functions](Object_Helper_Functions.md) (9 shared connections)
- [Object Handler Dispatch](Object_Handler_Dispatch.md) (8 shared connections)
- [Object Tagging Handler](Object_Tagging_Handler.md) (7 shared connections)
- [Request Parser Tests](Request_Parser_Tests.md) (7 shared connections)
- [XML Response Helpers](XML_Response_Helpers.md) (7 shared connections)
- [Error Response Tests](Error_Response_Tests.md) (5 shared connections)
- [Request Tracking Middleware](Request_Tracking_Middleware.md) (4 shared connections)

## Source Files

- `internal/orchestration/manager.go`
- `internal/proxy/handlers/multipart/abort.go`
- `internal/proxy/handlers/multipart/complete.go`
- `internal/proxy/handlers/multipart/copy.go`
- `internal/proxy/handlers/multipart/create.go`
- `internal/proxy/handlers/multipart/handler.go`
- `internal/proxy/handlers/multipart/list.go`
- `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- `internal/proxy/handlers/multipart/upload.go`
- `internal/proxy/handlers/object/acl.go`
- `internal/proxy/handlers/object/handler.go`
- `internal/proxy/handlers/object/tagging.go`
- `internal/proxy/handlers/root/handler.go`
- `internal/proxy/interfaces/s3_backend.go`
- `internal/proxy/request/parser.go`
- `internal/proxy/response/errors.go`
- `internal/proxy/response/xml.go`
- `internal/proxy/router.go`

## Audit Trail

- EXTRACTED: 303 (92%)
- INFERRED: 28 (8%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*