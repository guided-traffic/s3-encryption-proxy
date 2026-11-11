# Bucket: Subresource Documents

> 14 nodes · cohesion 0.16

## Key Concepts

- **replicationRuleDocument** (6 connections) — `internal/proxy/handlers/bucket/subresource_documents.go`
- **newTagDocuments()** (6 connections) — `internal/proxy/handlers/bucket/subresource_documents.go`
- **newReplicationConfigurationDocument()** (5 connections) — `internal/proxy/handlers/bucket/subresource_documents.go`
- **taggingDocument** (5 connections) — `internal/proxy/handlers/object/subresource_documents.go`
- **replicationConfigurationDocument** (4 connections) — `internal/proxy/handlers/bucket/subresource_documents.go`
- **github.com/aws/aws-sdk-go-v2/service/s3/types.Tag** (4 connections)
- **newTaggingDocument()** (4 connections) — `internal/proxy/handlers/object/subresource_documents.go`
- **sourceSelectionPD** (3 connections) — `internal/proxy/handlers/bucket/subresource_documents.go`
- **statusOnlyPD** (3 connections) — `internal/proxy/handlers/bucket/subresource_documents.go`
- **tagSetHolder** (3 connections) — `internal/proxy/handlers/object/subresource_documents.go`
- **subpassTagPairs()** (3 connections) — `test/integration/s3-methods/object_subresource_passthrough_test.go`
- **.tagSet()** (2 connections) — `internal/proxy/handlers/object/subresource_documents.go`
- **github.com/aws/aws-sdk-go-v2/service/s3/types.ReplicationConfiguration** (1 connections)
- **tagDocument** (1 connections)

## Relationships

- [Bucket Sub-Resource Documents](Bucket_Sub-Resource_Documents.md) (8 shared connections)
- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (4 shared connections)
- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (3 shared connections)
- [Bucket XML Documents](Bucket_XML_Documents.md) (2 shared connections)
- [Bucket: Subresource Documents (6)](Bucket-_Subresource_Documents_6.md) (2 shared connections)
- [Chunked Encoding Tests](Chunked_Encoding_Tests.md) (1 shared connections)

## Source Files

- `internal/proxy/handlers/bucket/subresource_documents.go`
- `internal/proxy/handlers/object/subresource_documents.go`
- `test/integration/s3-methods/object_subresource_passthrough_test.go`

## Audit Trail

- EXTRACTED: 32 (91%)
- INFERRED: 3 (9%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*