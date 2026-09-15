# Subresource Documents

> 9 nodes · cohesion 0.22

## Key Concepts

- **newLifecycleConfigurationDocument()** (6 connections) — `internal/proxy/handlers/bucket/subresource_documents.go`
- **newTagDocuments()** (6 connections) — `internal/proxy/handlers/bucket/subresource_documents.go`
- **newReplicationConfigurationDocument()** (5 connections) — `internal/proxy/handlers/bucket/subresource_documents.go`
- **replicationConfigurationDocument** (4 connections) — `internal/proxy/handlers/bucket/subresource_documents.go`
- **github.com/aws/aws-sdk-go-v2/service/s3/types.Tag** (4 connections)
- **formatDate()** (3 connections) — `internal/proxy/handlers/bucket/subresource_documents.go`
- **.tagSet()** (2 connections) — `internal/proxy/handlers/object/subresource_documents.go`
- **github.com/aws/aws-sdk-go-v2/service/s3/types.LifecycleRule** (1 connections)
- **github.com/aws/aws-sdk-go-v2/service/s3/types.ReplicationConfiguration** (1 connections)

## Relationships

- [Bucket XML Document Types](Bucket_XML_Document_Types.md) (8 shared connections)
- [Subresource Documents](Subresource_Documents.md) (2 shared connections)
- [ACL, CORS and Lifecycle Handlers](ACL,_CORS_and_Lifecycle_Handlers.md) (2 shared connections)
- [XML Document Marshalling](XML_Document_Marshalling.md) (1 shared connections)
- [Authentication Integration Tests](Authentication_Integration_Tests.md) (1 shared connections)
- [S3 Signing Helper](S3_Signing_Helper.md) (1 shared connections)
- [Replication and ACL Handlers](Replication_and_ACL_Handlers.md) (1 shared connections)

## Source Files

- `internal/proxy/handlers/bucket/subresource_documents.go`
- `internal/proxy/handlers/object/subresource_documents.go`

## Audit Trail

- EXTRACTED: 21 (88%)
- INFERRED: 3 (12%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*