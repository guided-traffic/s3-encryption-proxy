# Misc (24)

> 13 nodes · cohesion 0.27

## Key Concepts

- **.listObjectsV1()** (10 connections) — `internal/proxy/handlers/bucket/listing.go`
- **.listObjectsV2()** (10 connections) — `internal/proxy/handlers/bucket/listing.go`
- **listing_params.go** (8 connections) — `internal/proxy/handlers/bucket/listing_params.go`
- **callerOwner()** (6 connections) — `internal/proxy/handlers/bucket/listing.go`
- **formatLastModified()** (5 connections) — `internal/proxy/handlers/bucket/listing_document.go`
- **ClientIdentity()** (5 connections) — `internal/proxy/middleware/identity.go`
- **.HandleListBuckets()** (5 connections) — `internal/proxy/handlers/root/handler.go`
- **S3Timestamp()** (4 connections) — `internal/proxy/response/xml.go`
- **clientWantsURLEncoding()** (3 connections) — `internal/proxy/handlers/bucket/listing_params.go`
- **decodeBackendValue()** (3 connections) — `internal/proxy/handlers/bucket/listing_params.go`
- **encodeForClient()** (3 connections) — `internal/proxy/handlers/bucket/listing_params.go`
- **parseMaxKeys()** (3 connections) — `internal/proxy/handlers/bucket/listing_params.go`
- **ownerEntry** (1 connections)

## Relationships

- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (9 shared connections)
- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (8 shared connections)
- [Object: Metadata Coverage Test](Object-_Metadata_Coverage_Test.md) (2 shared connections)
- [Server and Listings](Server_and_Listings.md) (2 shared connections)
- [Request Documents and Owner Guard](Request_Documents_and_Owner_Guard.md) (1 shared connections)
- [Misc (15)](Misc_15.md) (1 shared connections)
- [Multipart Handlers and Manager](Multipart_Handlers_and_Manager.md) (1 shared connections)

## Source Files

- `internal/proxy/handlers/bucket/listing.go`
- `internal/proxy/handlers/bucket/listing_document.go`
- `internal/proxy/handlers/bucket/listing_params.go`
- `internal/proxy/handlers/root/handler.go`
- `internal/proxy/middleware/identity.go`
- `internal/proxy/response/xml.go`

## Audit Trail

- EXTRACTED: 35 (78%)
- INFERRED: 10 (22%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*