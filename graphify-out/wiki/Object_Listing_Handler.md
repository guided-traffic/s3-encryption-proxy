# Object Listing Handler

> 23 nodes · cohesion 0.16

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
- **identity.go** (3 connections) — `internal/proxy/middleware/identity.go`
- **response/xml.go** (3 connections) — `internal/proxy/response/xml.go`
- **Listings report plaintext size** (2 connections) — `docs/developer/request-paths.md`
- **listing.go** (2 connections) — `internal/proxy/handlers/bucket/listing.go`
- **ownerEntry** (1 connections)
- **clientIdentityKey** (1 connections) — `internal/proxy/middleware/identity.go`

## Relationships

- [Bucket ACL and Accelerate Handlers](Bucket_ACL_and_Accelerate_Handlers.md) (9 shared connections)
- [Object Response Header Helpers](Object_Response_Header_Helpers.md) (2 shared connections)
- [Health Probes and Request Tracker](Health_Probes_and_Request_Tracker.md) (2 shared connections)
- [Multipart Handler Wiring](Multipart_Handler_Wiring.md) (2 shared connections)
- [ETag Marker Codec](ETag_Marker_Codec.md) (1 shared connections)
- [Segmented GCM](Segmented_GCM.md) (1 shared connections)
- [Storage Format Integrity Guarantees](Storage_Format_Integrity_Guarantees.md) (1 shared connections)
- [Listing Document](Listing_Document.md) (1 shared connections)
- [ListBuckets Coverage Tests](ListBuckets_Coverage_Tests.md) (1 shared connections)
- [Multipart ListParts Handler](Multipart_ListParts_Handler.md) (1 shared connections)
- [MockS3Backend Tagging and Policy](MockS3Backend_Tagging_and_Policy.md) (1 shared connections)
- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (1 shared connections)

## Source Files

- `docs/developer/request-paths.md`
- `internal/proxy/handlers/bucket/listing.go`
- `internal/proxy/handlers/bucket/listing_document.go`
- `internal/proxy/handlers/bucket/listing_params.go`
- `internal/proxy/handlers/root/handler.go`
- `internal/proxy/middleware/identity.go`
- `internal/proxy/response/xml.go`

## Audit Trail

- EXTRACTED: 53 (84%)
- INFERRED: 10 (16%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*