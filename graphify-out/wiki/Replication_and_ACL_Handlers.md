# Replication and ACL Handlers

> 44 nodes · cohesion 0.09

## Key Concepts

- **net/http.Request** (187 connections)
- **Parser** (40 connections) — `internal/proxy/request/parser.go`
- **Handler** (20 connections) — `internal/proxy/handlers/object/handler.go`
- **.readBody()** (12 connections) — `internal/proxy/request/parser.go`
- **ACLHandler** (10 connections) — `internal/proxy/handlers/object/acl.go`
- **ReplicationHandler** (9 connections) — `internal/proxy/handlers/bucket/replication.go`
- **verifying()** (7 connections) — `internal/proxy/request/checksum.go`
- **isAWSChunkedRequest()** (7 connections) — `internal/proxy/request/streaming_aws_decoder.go`
- **.Handle()** (7 connections) — `internal/proxy/handlers/multipart/create.go`
- **.StreamingReader()** (7 connections) — `internal/proxy/request/parser.go`
- **.Handle()** (6 connections) — `internal/proxy/handlers/bucket/replication.go`
- **.handleGetBucketReplication()** (6 connections) — `internal/proxy/handlers/bucket/replication.go`
- **.handleDeleteBucketReplication()** (5 connections) — `internal/proxy/handlers/bucket/replication.go`
- **.Handle()** (5 connections) — `internal/proxy/handlers/object/acl.go`
- **.Handle()** (5 connections) — `internal/proxy/handlers/object/handler.go`
- **.handlePutBucketReplication()** (4 connections) — `internal/proxy/handlers/bucket/replication.go`
- **UserMetadata()** (4 connections) — `internal/proxy/handlers/object/helpers.go`
- **.handleGetACL()** (4 connections) — `internal/proxy/handlers/object/acl.go`
- **.handlePutACL()** (4 connections) — `internal/proxy/handlers/object/acl.go`
- **.handleBaseObjectOperations()** (4 connections) — `internal/proxy/handlers/object/handler.go`
- **.ReadDocument()** (4 connections) — `internal/proxy/request/parser.go`
- **.readDocument()** (3 connections) — `internal/proxy/handlers/bucket/base.go`
- **.HandleDeleteObjects()** (3 connections) — `internal/proxy/handlers/object/handler.go`
- **.HandleObjectLegalHold()** (3 connections) — `internal/proxy/handlers/object/handler.go`
- **.HandleObjectRetention()** (3 connections) — `internal/proxy/handlers/object/handler.go`
- *... and 19 more nodes in this community*

## Relationships

- [Bucket Website and Create/Delete](Bucket_Website_and_Create-Delete.md) (35 shared connections)
- [Response Header Helpers](Response_Header_Helpers.md) (31 shared connections)
- [Multipart Handler Constructors](Multipart_Handler_Constructors.md) (29 shared connections)
- [ACL, CORS and Lifecycle Handlers](ACL,_CORS_and_Lifecycle_Handlers.md) (23 shared connections)
- [Bucket Handler Dispatch](Bucket_Handler_Dispatch.md) (20 shared connections)
- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (7 shared connections)
- [Checksum](Checksum.md) (7 shared connections)
- [S3auth Robust](S3auth_Robust.md) (6 shared connections)
- [Request Parser and Framing Tests](Request_Parser_and_Framing_Tests.md) (6 shared connections)
- [Object Listing Handler](Object_Listing_Handler.md) (5 shared connections)
- [List](List.md) (5 shared connections)
- [Ranged GET Path and Window](Ranged_GET_Path_and_Window.md) (5 shared connections)

## Source Files

- `internal/proxy/handlers/bucket/base.go`
- `internal/proxy/handlers/bucket/handler.go`
- `internal/proxy/handlers/bucket/replication.go`
- `internal/proxy/handlers/multipart/create.go`
- `internal/proxy/handlers/object/acl.go`
- `internal/proxy/handlers/object/handler.go`
- `internal/proxy/handlers/object/helpers.go`
- `internal/proxy/request/checksum.go`
- `internal/proxy/request/parser.go`
- `internal/proxy/request/streaming_aws_decoder.go`

## Audit Trail

- EXTRACTED: 317 (96%)
- INFERRED: 12 (4%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*