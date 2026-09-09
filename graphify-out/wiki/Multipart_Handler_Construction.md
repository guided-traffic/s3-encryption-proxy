# Multipart Handler Construction

> 73 nodes · cohesion 0.07

## Key Concepts

- **github.com/sirupsen/logrus.Entry** (70 connections)
- **Manager** (60 connections) — `internal/orchestration/manager.go`
- **Parser** (34 connections) — `internal/proxy/request/parser.go`
- **ErrorWriter** (33 connections) — `internal/proxy/response/errors.go`
- **S3BackendInterface** (30 connections) — `internal/proxy/interfaces/s3_backend.go`
- **XMLWriter** (29 connections) — `internal/proxy/response/xml.go`
- **Handler** (26 connections) — `internal/proxy/handlers/multipart/handler.go`
- **NewHandler()** (17 connections) — `internal/proxy/handlers/multipart/handler.go`
- **NewHandler()** (17 connections) — `internal/proxy/handlers/object/handler.go`
- **NewCompleteHandler()** (16 connections) — `internal/proxy/handlers/multipart/complete.go`
- **NewUploadHandler()** (13 connections) — `internal/proxy/handlers/multipart/upload.go`
- **CompleteHandler** (13 connections) — `internal/proxy/handlers/multipart/complete.go`
- **CreateHandler** (13 connections) — `internal/proxy/handlers/multipart/create.go`
- **UploadHandler** (13 connections) — `internal/proxy/handlers/multipart/upload.go`
- **NewAbortHandler()** (12 connections) — `internal/proxy/handlers/multipart/abort.go`
- **AbortHandler** (12 connections) — `internal/proxy/handlers/multipart/abort.go`
- **ListHandler** (12 connections) — `internal/proxy/handlers/multipart/list.go`
- **NewListHandler()** (10 connections) — `internal/proxy/handlers/multipart/list.go`
- **ACLHandler** (10 connections) — `internal/proxy/handlers/object/acl.go`
- **MetadataHandler** (10 connections) — `internal/proxy/handlers/object/metadata.go`
- **CopyHandler** (9 connections) — `internal/proxy/handlers/multipart/copy.go`
- **NewCopyHandler()** (8 connections) — `internal/proxy/handlers/multipart/copy.go`
- **NewACLHandler()** (8 connections) — `internal/proxy/handlers/object/acl.go`
- **NewMetadataHandler()** (8 connections) — `internal/proxy/handlers/object/metadata.go`
- **NewTaggingHandler()** (8 connections) — `internal/proxy/handlers/object/tagging.go`
- *... and 48 more nodes in this community*

## Relationships

- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (50 shared connections)
- [Multipart Create Handler Tests](Multipart_Create_Handler_Tests.md) (26 shared connections)
- [Bucket Sub-Resource Tests](Bucket_Sub-Resource_Tests.md) (20 shared connections)
- [Multipart Handler Tests](Multipart_Handler_Tests.md) (19 shared connections)
- [Manager Envelope Encryption](Manager_Envelope_Encryption.md) (15 shared connections)
- [Bucket Sub-Resource Registry](Bucket_Sub-Resource_Registry.md) (10 shared connections)
- [Object Handler Sub-Resources](Object_Handler_Sub-Resources.md) (10 shared connections)
- [CORS Logging Tracking Middleware](CORS_Logging_Tracking_Middleware.md) (8 shared connections)
- [S3 Backend Interface Types](S3_Backend_Interface_Types.md) (6 shared connections)
- [Manager Construction Tests](Manager_Construction_Tests.md) (5 shared connections)
- [Configuration Accessors](Configuration_Accessors.md) (4 shared connections)
- [ListBuckets Root Handler](ListBuckets_Root_Handler.md) (4 shared connections)

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
- `internal/proxy/handlers/object/metadata.go`
- `internal/proxy/handlers/object/tagging.go`
- `internal/proxy/handlers/root/handler.go`
- `internal/proxy/interfaces/s3_backend.go`
- `internal/proxy/request/parser.go`
- `internal/proxy/response/errors.go`
- `internal/proxy/response/xml.go`
- `internal/proxy/router.go`

## Audit Trail

- EXTRACTED: 390 (92%)
- INFERRED: 33 (8%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*