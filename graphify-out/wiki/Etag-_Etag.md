# Etag: Etag

> 17 nodes · cohesion 0.21

## Key Concepts

- **etag.go** (14 connections) — `internal/proxy/etag/etag.go`
- **Entity tag -0 marker gates** (11 connections) — `docs/developer/request-paths.md`
- **Mark()** (10 connections) — `internal/proxy/etag/etag.go`
- **Unmark()** (9 connections) — `internal/proxy/etag/etag.go`
- **UnmarkList()** (6 connections) — `internal/proxy/etag/etag.go`
- **TestEtagRoundTripsForEveryShapeTheProxyAnswers()** (4 connections) — `internal/proxy/etag/etag_test.go`
- **TestEtagTheMarkerIsNotAShapeS3Produces()** (4 connections) — `internal/proxy/etag/etag_test.go`
- **.listingETag()** (3 connections) — `internal/proxy/handlers/bucket/listing.go`
- **isHexDigest()** (3 connections) — `internal/proxy/etag/etag.go`
- **requote()** (3 connections) — `internal/proxy/etag/etag.go`
- **TestEtagMarkOnlyTouchesTheDigestShape()** (3 connections) — `internal/proxy/etag/etag_test.go`
- **TestEtagUnmarkIsShapeDrivenNotATrim()** (3 connections) — `internal/proxy/etag/etag_test.go`
- **TestEtagUnmarkListHandlesEveryHeaderForm()** (3 connections) — `internal/proxy/etag/etag_test.go`
- **unquote()** (3 connections) — `internal/proxy/etag/etag.go`
- **.clientETag()** (3 connections) — `internal/proxy/handlers/object/helpers.go`
- **leadingSpace()** (2 connections) — `internal/proxy/etag/etag.go`
- **.VerifyClientParts()** (2 connections) — `internal/orchestration/segmented_session.go`

## Relationships

- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (11 shared connections)
- [Shutdown and Test Contexts](Shutdown_and_Test_Contexts.md) (5 shared connections)
- [Request Documents and Owner Guard](Request_Documents_and_Owner_Guard.md) (3 shared connections)
- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (3 shared connections)
- [S3 API Behaviour](S3_API_Behaviour.md) (2 shared connections)
- [Orchestration: Segmented Session](Orchestration-_Segmented_Session.md) (2 shared connections)
- [Object: Metadata Coverage Test](Object-_Metadata_Coverage_Test.md) (1 shared connections)
- [Middleware: S3Auth Robust](Middleware-_S3Auth_Robust.md) (1 shared connections)

## Source Files

- `docs/developer/request-paths.md`
- `internal/orchestration/segmented_session.go`
- `internal/proxy/etag/etag.go`
- `internal/proxy/etag/etag_test.go`
- `internal/proxy/handlers/bucket/listing.go`
- `internal/proxy/handlers/object/helpers.go`

## Audit Trail

- EXTRACTED: 49 (86%)
- INFERRED: 8 (14%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*