# Bucket Website and Create/Delete

> 37 nodes · cohesion 0.11

## Key Concepts

- **net/http.ResponseWriter** (135 connections)
- **UploadHandler** (21 connections) — `internal/proxy/handlers/multipart/upload.go`
- **WebsiteHandler** (9 connections) — `internal/proxy/handlers/bucket/website.go`
- **clientETag()** (9 connections) — `internal/proxy/handlers/multipart/handler.go`
- **.Handle()** (9 connections) — `internal/proxy/handlers/multipart/upload.go`
- **.storePassThroughPart()** (8 connections) — `internal/proxy/handlers/multipart/upload.go`
- **.writeErrorDocument()** (8 connections) — `internal/proxy/response/errors.go`
- **.uploadPassThroughPart()** (7 connections) — `internal/proxy/handlers/multipart/upload.go`
- **.uploadSegmentedPart()** (7 connections) — `internal/proxy/handlers/multipart/upload.go`
- **.uploadStreamedPart()** (7 connections) — `internal/proxy/handlers/multipart/upload.go`
- **.Handle()** (6 connections) — `internal/proxy/handlers/bucket/website.go`
- **.handleGetBucketWebsite()** (6 connections) — `internal/proxy/handlers/bucket/website.go`
- **.readHeldPart()** (6 connections) — `internal/proxy/handlers/multipart/upload.go`
- **.handleDeleteBucketWebsite()** (5 connections) — `internal/proxy/handlers/bucket/website.go`
- **.forwardPassThroughPart()** (5 connections) — `internal/proxy/handlers/multipart/upload.go`
- **.readPart()** (5 connections) — `internal/proxy/handlers/multipart/upload.go`
- **.readUndeclaredPart()** (5 connections) — `internal/proxy/handlers/multipart/upload.go`
- **.handleDeleteBucket()** (4 connections) — `internal/proxy/handlers/bucket/operations.go`
- **.handleHeadBucket()** (4 connections) — `internal/proxy/handlers/bucket/operations.go`
- **.handlePutBucketWebsite()** (4 connections) — `internal/proxy/handlers/bucket/website.go`
- **Hlthprobe** (4 connections) — `internal/proxy/handlers/health/handler_coverage_test.go`
- **forwardingWriter** (4 connections) — `internal/proxy/handlers/object/copy_bench_test.go`
- **.WriteS3Error()** (4 connections) — `internal/proxy/response/errors.go`
- **.handleCreateBucket()** (3 connections) — `internal/proxy/handlers/bucket/operations.go`
- **Handler** (3 connections) — `internal/proxy/handlers/bucket/operations.go`
- *... and 12 more nodes in this community*

## Relationships

- [Replication and ACL Handlers](Replication_and_ACL_Handlers.md) (35 shared connections)
- [ACL, CORS and Lifecycle Handlers](ACL,_CORS_and_Lifecycle_Handlers.md) (26 shared connections)
- [Response Header Helpers](Response_Header_Helpers.md) (26 shared connections)
- [Multipart Handler Constructors](Multipart_Handler_Constructors.md) (19 shared connections)
- [Bucket Handler Dispatch](Bucket_Handler_Dispatch.md) (18 shared connections)
- [List](List.md) (5 shared connections)
- [Object Listing Handler](Object_Listing_Handler.md) (4 shared connections)
- [Logging](Logging.md) (4 shared connections)
- [Health Probe Handler](Health_Probe_Handler.md) (4 shared connections)
- [Ranged GET Path and Window](Ranged_GET_Path_and_Window.md) (4 shared connections)
- [Segmented Session Lifecycle](Segmented_Session_Lifecycle.md) (4 shared connections)
- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (3 shared connections)

## Source Files

- `internal/proxy/handlers/bucket/handler.go`
- `internal/proxy/handlers/bucket/operations.go`
- `internal/proxy/handlers/bucket/website.go`
- `internal/proxy/handlers/health/handler_coverage_test.go`
- `internal/proxy/handlers/multipart/copy.go`
- `internal/proxy/handlers/multipart/handler.go`
- `internal/proxy/handlers/multipart/upload.go`
- `internal/proxy/handlers/object/copy_bench_test.go`
- `internal/proxy/response/errors.go`
- `internal/proxy/response/xml.go`

## Audit Trail

- EXTRACTED: 237 (97%)
- INFERRED: 8 (3%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*