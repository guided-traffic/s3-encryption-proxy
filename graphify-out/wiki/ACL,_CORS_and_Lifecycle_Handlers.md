# ACL, CORS and Lifecycle Handlers

> 38 nodes · cohesion 0.09

## Key Concepts

- **ExpectedBucketOwner()** (60 connections) — `internal/proxy/request/bucketowner.go`
- **CORSHandler** (9 connections) — `internal/proxy/handlers/bucket/cors.go`
- **LifecycleHandler** (9 connections) — `internal/proxy/handlers/bucket/lifecycle.go`
- **PolicyHandler** (9 connections) — `internal/proxy/handlers/bucket/policy.go`
- **TaggingHandler** (7 connections) — `internal/proxy/handlers/bucket/tagging.go`
- **ACLHandler** (6 connections) — `internal/proxy/handlers/bucket/acl.go`
- **.handleGetACL()** (6 connections) — `internal/proxy/handlers/bucket/acl.go`
- **.Handle()** (6 connections) — `internal/proxy/handlers/bucket/cors.go`
- **.handleGetCORS()** (6 connections) — `internal/proxy/handlers/bucket/cors.go`
- **.Handle()** (6 connections) — `internal/proxy/handlers/bucket/lifecycle.go`
- **.handleGetBucketLifecycleConfiguration()** (6 connections) — `internal/proxy/handlers/bucket/lifecycle.go`
- **.Handle()** (6 connections) — `internal/proxy/handlers/bucket/policy.go`
- **.Handle()** (6 connections) — `internal/proxy/handlers/bucket/tagging.go`
- **.handleGetBucketTagging()** (6 connections) — `internal/proxy/handlers/bucket/tagging.go`
- **.Handle()** (5 connections) — `internal/proxy/handlers/bucket/acl.go`
- **.handlePutACL()** (5 connections) — `internal/proxy/handlers/bucket/acl.go`
- **.handleDeleteCORS()** (5 connections) — `internal/proxy/handlers/bucket/cors.go`
- **.handlePutCORS()** (5 connections) — `internal/proxy/handlers/bucket/cors.go`
- **.handleDeleteBucketLifecycle()** (5 connections) — `internal/proxy/handlers/bucket/lifecycle.go`
- **.handlePutBucketLifecycleConfiguration()** (5 connections) — `internal/proxy/handlers/bucket/lifecycle.go`
- **.handleDeletePolicy()** (5 connections) — `internal/proxy/handlers/bucket/policy.go`
- **.handleGetPolicy()** (5 connections) — `internal/proxy/handlers/bucket/policy.go`
- **.handlePutPolicy()** (5 connections) — `internal/proxy/handlers/bucket/policy.go`
- **.handleDeleteBucketTagging()** (5 connections) — `internal/proxy/handlers/bucket/tagging.go`
- **.handlePutBucketTagging()** (5 connections) — `internal/proxy/handlers/bucket/tagging.go`
- *... and 13 more nodes in this community*

## Relationships

- [Bucket Website and Create/Delete](Bucket_Website_and_Create-Delete.md) (26 shared connections)
- [Replication and ACL Handlers](Replication_and_ACL_Handlers.md) (23 shared connections)
- [Bucket Handler Dispatch](Bucket_Handler_Dispatch.md) (13 shared connections)
- [Response Header Helpers](Response_Header_Helpers.md) (13 shared connections)
- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (10 shared connections)
- [Bucket Crud](Bucket_Crud.md) (5 shared connections)
- [Subresource Documents](Subresource_Documents.md) (4 shared connections)
- [Logging](Logging.md) (3 shared connections)
- [Ranged GET Path and Window](Ranged_GET_Path_and_Window.md) (3 shared connections)
- [Object Listing Handler](Object_Listing_Handler.md) (2 shared connections)
- [Complete](Complete.md) (2 shared connections)
- [List](List.md) (2 shared connections)

## Source Files

- `internal/proxy/handlers/bucket/acl.go`
- `internal/proxy/handlers/bucket/cors.go`
- `internal/proxy/handlers/bucket/handler.go`
- `internal/proxy/handlers/bucket/lifecycle.go`
- `internal/proxy/handlers/bucket/policy.go`
- `internal/proxy/handlers/bucket/subresource_documents.go`
- `internal/proxy/handlers/bucket/tagging.go`
- `internal/proxy/request/bucketowner.go`

## Audit Trail

- EXTRACTED: 165 (96%)
- INFERRED: 7 (4%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*