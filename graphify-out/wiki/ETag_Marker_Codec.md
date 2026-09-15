# ETag Marker Codec

> 20 nodes · cohesion 0.18

## Key Concepts

- **Mark()** (10 connections) — `internal/proxy/etag/etag.go`
- **Unmark()** (9 connections) — `internal/proxy/etag/etag.go`
- **etag.go** (7 connections) — `internal/proxy/etag/etag.go`
- **Handler** (7 connections) — `internal/proxy/handlers/object/helpers.go`
- **etag_test.go** (5 connections) — `internal/proxy/etag/etag_test.go`
- **UnmarkList()** (5 connections) — `internal/proxy/etag/etag.go`
- **TestEtagRoundTripsForEveryShapeTheProxyAnswers()** (4 connections) — `internal/proxy/etag/etag_test.go`
- **TestEtagTheMarkerIsNotAShapeS3Produces()** (4 connections) — `internal/proxy/etag/etag_test.go`
- **isHexDigest()** (3 connections) — `internal/proxy/etag/etag.go`
- **requote()** (3 connections) — `internal/proxy/etag/etag.go`
- **TestEtagMarkOnlyTouchesTheDigestShape()** (3 connections) — `internal/proxy/etag/etag_test.go`
- **TestEtagUnmarkIsShapeDrivenNotATrim()** (3 connections) — `internal/proxy/etag/etag_test.go`
- **TestEtagUnmarkListHandlesEveryHeaderForm()** (3 connections) — `internal/proxy/etag/etag_test.go`
- **unquote()** (3 connections) — `internal/proxy/etag/etag.go`
- **leadingSpace()** (2 connections) — `internal/proxy/etag/etag.go`
- **.cleanMetadata()** (2 connections) — `internal/proxy/handlers/object/helpers.go`
- **.clientETag()** (2 connections) — `internal/proxy/handlers/object/helpers.go`
- **.isEncryptionMetadata()** (2 connections) — `internal/proxy/handlers/object/helpers.go`
- **.getMultipartPartSize()** (1 connections) — `internal/proxy/handlers/object/helpers.go`
- **.getMultipartUploadConcurrency()** (1 connections) — `internal/proxy/handlers/object/helpers.go`

## Relationships

- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (5 shared connections)
- [Response Header Helpers](Response_Header_Helpers.md) (2 shared connections)
- [Object Listing Handler](Object_Listing_Handler.md) (1 shared connections)
- [Bucket Website and Create/Delete](Bucket_Website_and_Create-Delete.md) (1 shared connections)
- [Complete](Complete.md) (1 shared connections)
- [Replication and ACL Handlers](Replication_and_ACL_Handlers.md) (1 shared connections)

## Source Files

- `internal/proxy/etag/etag.go`
- `internal/proxy/etag/etag_test.go`
- `internal/proxy/handlers/object/helpers.go`

## Audit Trail

- EXTRACTED: 38 (84%)
- INFERRED: 7 (16%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*