# Replication Configuration Document

> 6 nodes · cohesion 0.40

## Key Concepts

- **replicationRuleDocument** (6 connections) — `internal/proxy/handlers/bucket/subresource_documents.go`
- **newReplicationConfigurationDocument()** (5 connections) — `internal/proxy/handlers/bucket/subresource_documents.go`
- **replicationConfigurationDocument** (4 connections) — `internal/proxy/handlers/bucket/subresource_documents.go`
- **sourceSelectionPD** (3 connections) — `internal/proxy/handlers/bucket/subresource_documents.go`
- **statusOnlyPD** (3 connections) — `internal/proxy/handlers/bucket/subresource_documents.go`
- **github.com/aws/aws-sdk-go-v2/service/s3/types.ReplicationConfiguration** (1 connections)

## Relationships

- [Bucket Sub-Resource Documents](Bucket_Sub-Resource_Documents.md) (6 shared connections)
- [Bucket XML Documents](Bucket_XML_Documents.md) (1 shared connections)
- [Bucket: Subresource Documents (6)](Bucket-_Subresource_Documents_6.md) (1 shared connections)
- [Bucket: Subresource Documents](Bucket-_Subresource_Documents.md) (1 shared connections)
- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (1 shared connections)

## Source Files

- `internal/proxy/handlers/bucket/subresource_documents.go`

## Audit Trail

- EXTRACTED: 15 (94%)
- INFERRED: 1 (6%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*