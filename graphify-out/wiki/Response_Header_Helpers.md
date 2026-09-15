# Response Header Helpers

> 57 nodes · cohesion 0.07

## Key Concepts

- **objectVersionID()** (16 connections) — `internal/proxy/handlers/object/helpers.go`
- **Handler** (14 connections) — `internal/proxy/handlers/object/operations.go`
- **writeVersionHeaders()** (12 connections) — `internal/proxy/handlers/object/helpers.go`
- **helpers.go** (11 connections) — `internal/proxy/handlers/object/helpers.go`
- **ReadConditionalHeaders()** (11 connections) — `internal/proxy/handlers/object/storage_headers.go`
- **.putObjectAutoMultipart()** (11 connections) — `internal/proxy/handlers/object/operations.go`
- **.writeGetObjectResponse()** (11 connections) — `internal/proxy/handlers/object/operations.go`
- **.writeHeadResponse()** (11 connections) — `internal/proxy/handlers/object/operations.go`
- **ReadUploadHeaders()** (10 connections) — `internal/proxy/handlers/object/storage_headers.go`
- **.handleHeadObject()** (10 connections) — `internal/proxy/handlers/object/operations.go`
- **.putObjectSegmented()** (10 connections) — `internal/proxy/handlers/object/operations.go`
- **.servePerObject()** (10 connections) — `internal/proxy/handlers/object/operations.go`
- **readDocument()** (9 connections) — `internal/proxy/handlers/object/helpers.go`
- **storage_headers.go** (9 connections) — `internal/proxy/handlers/object/storage_headers.go`
- **.fetchObjectTail()** (9 connections) — `internal/proxy/handlers/object/tail.go`
- **.serveWholeObject()** (9 connections) — `internal/proxy/handlers/object/operations.go`
- **WriteSSEHeaders()** (8 connections) — `internal/proxy/handlers/object/helpers.go`
- **EntityHeaders** (8 connections) — `internal/proxy/handlers/object/storage_headers.go`
- **StorageAttributes** (8 connections) — `internal/proxy/handlers/object/storage_headers.go`
- **.handleGetTagging()** (8 connections) — `internal/proxy/handlers/object/tagging.go`
- **.handlePutTagging()** (8 connections) — `internal/proxy/handlers/object/tagging.go`
- **writeEntityHeaders()** (7 connections) — `internal/proxy/handlers/object/helpers.go`
- **.handleObjectLegalHold()** (7 connections) — `internal/proxy/handlers/object/objectlock.go`
- **.handleObjectRetention()** (7 connections) — `internal/proxy/handlers/object/objectlock.go`
- **.handleDeleteTagging()** (7 connections) — `internal/proxy/handlers/object/tagging.go`
- *... and 32 more nodes in this community*

## Relationships

- [Replication and ACL Handlers](Replication_and_ACL_Handlers.md) (31 shared connections)
- [Bucket Website and Create/Delete](Bucket_Website_and_Create-Delete.md) (26 shared connections)
- [ACL, CORS and Lifecycle Handlers](ACL,_CORS_and_Lifecycle_Handlers.md) (13 shared connections)
- [Ranged GET Path and Window](Ranged_GET_Path_and_Window.md) (9 shared connections)
- [MockS3Backend Multipart Operations](MockS3Backend_Multipart_Operations.md) (7 shared connections)
- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (6 shared connections)
- [DeleteObjects Handler Tests](DeleteObjects_Handler_Tests.md) (6 shared connections)
- [Multipart Handler Constructors](Multipart_Handler_Constructors.md) (6 shared connections)
- [Complete](Complete.md) (4 shared connections)
- [Segmented Manager Streaming IO](Segmented_Manager_Streaming_IO.md) (4 shared connections)
- [Subresource Documents](Subresource_Documents.md) (3 shared connections)
- [S3 Signing Helper](S3_Signing_Helper.md) (3 shared connections)

## Source Files

- `internal/monitoring/metrics.go`
- `internal/proxy/handlers/object/content_encoding.go`
- `internal/proxy/handlers/object/content_encoding_test.go`
- `internal/proxy/handlers/object/helpers.go`
- `internal/proxy/handlers/object/metadata_coverage_test.go`
- `internal/proxy/handlers/object/objectlock.go`
- `internal/proxy/handlers/object/operations.go`
- `internal/proxy/handlers/object/storage_headers.go`
- `internal/proxy/handlers/object/tagging.go`
- `internal/proxy/handlers/object/tail.go`

## Audit Trail

- EXTRACTED: 182 (76%)
- INFERRED: 59 (24%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*