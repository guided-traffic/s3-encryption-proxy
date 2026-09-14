# Object Listing

> 14 nodes · cohesion 0.31

## Key Concepts

- **.listObjectsV1()** (12 connections) — `internal/proxy/handlers/bucket/listing.go`
- **.listObjectsV2()** (12 connections) — `internal/proxy/handlers/bucket/listing.go`
- **callerOwner()** (6 connections) — `internal/proxy/handlers/bucket/listing.go`
- **.handleListObjects()** (5 connections) — `internal/proxy/handlers/bucket/listing.go`
- **Handler** (5 connections) — `internal/proxy/handlers/bucket/listing.go`
- **.reportedSize()** (4 connections) — `internal/proxy/handlers/bucket/listing.go`
- **formatLastModified()** (4 connections) — `internal/proxy/handlers/bucket/listing_document.go`
- **listing_params.go** (4 connections) — `internal/proxy/handlers/bucket/listing_params.go`
- **.activeProviderEncrypts()** (3 connections) — `internal/proxy/handlers/bucket/listing.go`
- **clientWantsURLEncoding()** (3 connections) — `internal/proxy/handlers/bucket/listing_params.go`
- **decodeBackendValue()** (3 connections) — `internal/proxy/handlers/bucket/listing_params.go`
- **encodeForClient()** (3 connections) — `internal/proxy/handlers/bucket/listing_params.go`
- **parseMaxKeys()** (3 connections) — `internal/proxy/handlers/bucket/listing_params.go`
- **listing.go** (1 connections) — `internal/proxy/handlers/bucket/listing.go`

## Relationships

- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (7 shared connections)
- [Listing XML Documents](Listing_XML_Documents.md) (2 shared connections)
- [Segment Codec Tests](Segment_Codec_Tests.md) (1 shared connections)
- [Client Identity Context](Client_Identity_Context.md) (1 shared connections)
- [SigV4 Signing Helper](SigV4_Signing_Helper.md) (1 shared connections)

## Source Files

- `internal/proxy/handlers/bucket/listing.go`
- `internal/proxy/handlers/bucket/listing_document.go`
- `internal/proxy/handlers/bucket/listing_params.go`

## Audit Trail

- EXTRACTED: 30 (75%)
- INFERRED: 10 (25%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*