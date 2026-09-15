# Multipart Handler Constructors

> 68 nodes · cohesion 0.10

## Key Concepts

- **github.com/sirupsen/logrus.Entry** (61 connections)
- **Manager** (41 connections) — `internal/orchestration/manager.go`
- **ErrorWriter** (33 connections) — `internal/proxy/response/errors.go`
- **S3BackendInterface** (31 connections) — `internal/proxy/interfaces/s3_backend.go`
- **setupMultipartTestEnv()** (29 connections) — `internal/proxy/handlers/multipart/multipart_test.go`
- **multipart_test.go** (26 connections) — `internal/proxy/handlers/multipart/multipart_test.go`
- **XMLWriter** (26 connections) — `internal/proxy/response/xml.go`
- **NewCreateHandler()** (24 connections) — `internal/proxy/handlers/multipart/create.go`
- **NewUploadHandler()** (21 connections) — `internal/proxy/handlers/multipart/upload.go`
- **Handler** (20 connections) — `internal/proxy/handlers/multipart/handler.go`
- **NewHandler()** (17 connections) — `internal/proxy/handlers/multipart/handler.go`
- **NewHandler()** (17 connections) — `internal/proxy/handlers/object/handler.go`
- **NewCompleteHandler()** (16 connections) — `internal/proxy/handlers/multipart/complete.go`
- **AbortHandler** (13 connections) — `internal/proxy/handlers/multipart/abort.go`
- **CompleteHandler** (13 connections) — `internal/proxy/handlers/multipart/complete.go`
- **NewAbortHandler()** (12 connections) — `internal/proxy/handlers/multipart/abort.go`
- **CreateHandler** (12 connections) — `internal/proxy/handlers/multipart/create.go`
- **NewListHandler()** (11 connections) — `internal/proxy/handlers/multipart/list.go`
- **TaggingHandler** (11 connections) — `internal/proxy/handlers/object/tagging.go`
- **alignedPlaintext()** (9 connections) — `internal/proxy/handlers/multipart/multipart_test.go`
- **CopyHandler** (9 connections) — `internal/proxy/handlers/multipart/copy.go`
- **NewCopyHandler()** (8 connections) — `internal/proxy/handlers/multipart/copy.go`
- **TestCompleteHandler_AbortSurvivesClientDisconnect()** (8 connections) — `internal/proxy/handlers/multipart/multipart_test.go`
- **TestMultipartHandlers_Integration()** (8 connections) — `internal/proxy/handlers/multipart/multipart_test.go`
- **NewACLHandler()** (8 connections) — `internal/proxy/handlers/object/acl.go`
- *... and 43 more nodes in this community*

## Relationships

- [Replication and ACL Handlers](Replication_and_ACL_Handlers.md) (29 shared connections)
- [Bucket Website and Create/Delete](Bucket_Website_and_Create-Delete.md) (19 shared connections)
- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (19 shared connections)
- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (17 shared connections)
- [Multipart Handler Coverage Tests](Multipart_Handler_Coverage_Tests.md) (14 shared connections)
- [List](List.md) (10 shared connections)
- [Complete](Complete.md) (7 shared connections)
- [Response Header Helpers](Response_Header_Helpers.md) (6 shared connections)
- [Copy and Delete Object Handlers](Copy_and_Delete_Object_Handlers.md) (6 shared connections)
- [Bucket Handler Dispatch](Bucket_Handler_Dispatch.md) (5 shared connections)
- [Object GET Coverage Tests](Object_GET_Coverage_Tests.md) (5 shared connections)
- [CORS Middleware and SSE-C Stripping](CORS_Middleware_and_SSE-C_Stripping.md) (4 shared connections)

## Source Files

- `internal/orchestration/manager.go`
- `internal/proxy/handlers/multipart/abort.go`
- `internal/proxy/handlers/multipart/complete.go`
- `internal/proxy/handlers/multipart/copy.go`
- `internal/proxy/handlers/multipart/create.go`
- `internal/proxy/handlers/multipart/handler.go`
- `internal/proxy/handlers/multipart/list.go`
- `internal/proxy/handlers/multipart/multipart_test.go`
- `internal/proxy/handlers/multipart/upload.go`
- `internal/proxy/handlers/object/acl.go`
- `internal/proxy/handlers/object/handler.go`
- `internal/proxy/handlers/object/tagging.go`
- `internal/proxy/handlers/root/handler.go`
- `internal/proxy/interfaces/s3_backend.go`
- `internal/proxy/response/errors.go`
- `internal/proxy/response/xml.go`

## Audit Trail

- EXTRACTED: 366 (87%)
- INFERRED: 54 (13%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*