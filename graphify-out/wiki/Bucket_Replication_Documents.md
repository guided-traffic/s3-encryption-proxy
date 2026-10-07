# Bucket Replication Documents

> 6 nodes · cohesion 0.40

## Key Concepts

- **replicationRuleDocument** (6 connections) — `internal/proxy/handlers/bucket/subresource_documents.go`
- **newReplicationConfigurationDocument()** (5 connections) — `internal/proxy/handlers/bucket/subresource_documents.go`
- **replicationConfigurationDocument** (4 connections) — `internal/proxy/handlers/bucket/subresource_documents.go`
- **sourceSelectionPD** (3 connections) — `internal/proxy/handlers/bucket/subresource_documents.go`
- **statusOnlyPD** (3 connections) — `internal/proxy/handlers/bucket/subresource_documents.go`
- **github.com/aws/aws-sdk-go-v2/service/s3/types.ReplicationConfiguration** (1 connections)

## Relationships

- [Bucket XML Document Types](Bucket_XML_Document_Types.md) (7 shared connections)
- [XML Document Marshalling](XML_Document_Marshalling.md) (1 shared connections)
- [Object Sub-Resource Documents](Object_Sub-Resource_Documents.md) (1 shared connections)
- [Bucket CORS Handler](Bucket_CORS_Handler.md) (1 shared connections)

## Source Files

- `internal/proxy/handlers/bucket/subresource_documents.go`

## Audit Trail

- EXTRACTED: 15 (94%)
- INFERRED: 1 (6%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*