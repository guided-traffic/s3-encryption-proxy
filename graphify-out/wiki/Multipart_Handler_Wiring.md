# Multipart Handler Wiring

> 40 nodes · cohesion 0.15

## Key Concepts

- **github.com/sirupsen/logrus.Entry** (61 connections)
- **Manager** (41 connections) — `internal/orchestration/manager.go`
- **ErrorWriter** (31 connections) — `internal/proxy/response/errors.go`
- **S3BackendInterface** (29 connections) — `internal/proxy/interfaces/s3_backend.go`
- **XMLWriter** (24 connections) — `internal/proxy/response/xml.go`
- **Handler** (20 connections) — `internal/proxy/handlers/multipart/handler.go`
- **NewHandler()** (17 connections) — `internal/proxy/handlers/multipart/handler.go`
- **NewHandler()** (17 connections) — `internal/proxy/handlers/object/handler.go`
- **NewCompleteHandler()** (16 connections) — `internal/proxy/handlers/multipart/complete.go`
- **ListHandler** (14 connections) — `internal/proxy/handlers/multipart/list.go`
- **AbortHandler** (13 connections) — `internal/proxy/handlers/multipart/abort.go`
- **CompleteHandler** (13 connections) — `internal/proxy/handlers/multipart/complete.go`
- **NewAbortHandler()** (12 connections) — `internal/proxy/handlers/multipart/abort.go`
- **CreateHandler** (12 connections) — `internal/proxy/handlers/multipart/create.go`
- **NewListHandler()** (11 connections) — `internal/proxy/handlers/multipart/list.go`
- **ACLHandler** (10 connections) — `internal/proxy/handlers/object/acl.go`
- **CopyHandler** (9 connections) — `internal/proxy/handlers/multipart/copy.go`
- **NewCopyHandler()** (8 connections) — `internal/proxy/handlers/multipart/copy.go`
- **NewACLHandler()** (8 connections) — `internal/proxy/handlers/object/acl.go`
- **Handler** (7 connections) — `internal/proxy/handlers/root/handler.go`
- **manager.go** (6 connections) — `internal/orchestration/manager.go`
- **.Handle()** (6 connections) — `internal/proxy/handlers/multipart/abort.go`
- **copy.go** (3 connections) — `internal/proxy/handlers/multipart/copy.go`
- **multipart/handler.go** (3 connections) — `internal/proxy/handlers/multipart/handler.go`
- **.list()** (3 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- *... and 15 more nodes in this community*

## Relationships

- [Bucket ACL and Accelerate Handlers](Bucket_ACL_and_Accelerate_Handlers.md) (27 shared connections)
- [Multipart Handler Constructors](Multipart_Handler_Constructors.md) (26 shared connections)
- [Multipart ListParts Handler](Multipart_ListParts_Handler.md) (14 shared connections)
- [Multipart Handler Coverage Tests](Multipart_Handler_Coverage_Tests.md) (13 shared connections)
- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (11 shared connections)
- [Bucket Sub-Resource Handler Registry](Bucket_Sub-Resource_Handler_Registry.md) (7 shared connections)
- [Object Sub-Resource Dispatch](Object_Sub-Resource_Dispatch.md) (7 shared connections)
- [Bucket CORS Handler](Bucket_CORS_Handler.md) (5 shared connections)
- [Copy and Delete Object Handlers](Copy_and_Delete_Object_Handlers.md) (5 shared connections)
- [Object Response Header Helpers](Object_Response_Header_Helpers.md) (5 shared connections)
- [Object GET Coverage Tests](Object_GET_Coverage_Tests.md) (5 shared connections)
- [Router](Router.md) (4 shared connections)

## Source Files

- `internal/orchestration/manager.go`
- `internal/proxy/handlers/multipart/abort.go`
- `internal/proxy/handlers/multipart/complete.go`
- `internal/proxy/handlers/multipart/copy.go`
- `internal/proxy/handlers/multipart/create.go`
- `internal/proxy/handlers/multipart/handler.go`
- `internal/proxy/handlers/multipart/list.go`
- `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- `internal/proxy/handlers/object/acl.go`
- `internal/proxy/handlers/object/handler.go`
- `internal/proxy/handlers/root/handler.go`
- `internal/proxy/interfaces/s3_backend.go`
- `internal/proxy/response/errors.go`
- `internal/proxy/response/xml.go`

## Audit Trail

- EXTRACTED: 278 (91%)
- INFERRED: 27 (9%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*