# Object Listing Handler

> 20 nodes · cohesion 0.19

## Key Concepts

- **.listObjectsV1()** (14 connections) — `internal/proxy/handlers/bucket/listing.go`
- **.listObjectsV2()** (14 connections) — `internal/proxy/handlers/bucket/listing.go`
- **callerOwner()** (6 connections) — `internal/proxy/handlers/bucket/listing.go`
- **Handler** (6 connections) — `internal/proxy/handlers/bucket/listing.go`
- **.handleListObjects()** (5 connections) — `internal/proxy/handlers/bucket/listing.go`
- **formatLastModified()** (5 connections) — `internal/proxy/handlers/bucket/listing_document.go`
- **ClientIdentity()** (5 connections) — `internal/proxy/middleware/identity.go`
- **.HandleListBuckets()** (5 connections) — `internal/proxy/handlers/root/handler.go`
- **.listingETag()** (4 connections) — `internal/proxy/handlers/bucket/listing.go`
- **.reportedSize()** (4 connections) — `internal/proxy/handlers/bucket/listing.go`
- **listing_params.go** (4 connections) — `internal/proxy/handlers/bucket/listing_params.go`
- **S3Timestamp()** (4 connections) — `internal/proxy/response/xml.go`
- **.activeProviderEncrypts()** (3 connections) — `internal/proxy/handlers/bucket/listing.go`
- **clientWantsURLEncoding()** (3 connections) — `internal/proxy/handlers/bucket/listing_params.go`
- **decodeBackendValue()** (3 connections) — `internal/proxy/handlers/bucket/listing_params.go`
- **encodeForClient()** (3 connections) — `internal/proxy/handlers/bucket/listing_params.go`
- **parseMaxKeys()** (3 connections) — `internal/proxy/handlers/bucket/listing_params.go`
- **response/xml.go** (3 connections) — `internal/proxy/response/xml.go`
- **listing.go** (1 connections) — `internal/proxy/handlers/bucket/listing.go`
- **ownerEntry** (1 connections)

## Relationships

- [Replication and ACL Handlers](Replication_and_ACL_Handlers.md) (5 shared connections)
- [Bucket Website and Create/Delete](Bucket_Website_and_Create-Delete.md) (4 shared connections)
- [ACL, CORS and Lifecycle Handlers](ACL,_CORS_and_Lifecycle_Handlers.md) (2 shared connections)
- [S3 Signing Helper](S3_Signing_Helper.md) (2 shared connections)
- [Multipart Handler Constructors](Multipart_Handler_Constructors.md) (2 shared connections)
- [ETag Marker Codec](ETag_Marker_Codec.md) (1 shared connections)
- [Segmented GCM](Segmented_GCM.md) (1 shared connections)
- [Listing Document](Listing_Document.md) (1 shared connections)
- [List](List.md) (1 shared connections)
- [MockS3Backend Bucket Operations](MockS3Backend_Bucket_Operations.md) (1 shared connections)
- [ListBuckets Root Handler](ListBuckets_Root_Handler.md) (1 shared connections)
- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (1 shared connections)

## Source Files

- `internal/proxy/handlers/bucket/listing.go`
- `internal/proxy/handlers/bucket/listing_document.go`
- `internal/proxy/handlers/bucket/listing_params.go`
- `internal/proxy/handlers/root/handler.go`
- `internal/proxy/middleware/identity.go`
- `internal/proxy/response/xml.go`

## Audit Trail

- EXTRACTED: 49 (83%)
- INFERRED: 10 (17%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*