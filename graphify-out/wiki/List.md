# List

> 10 nodes · cohesion 0.40

## Key Concepts

- **ListHandler** (14 connections) — `internal/proxy/handlers/multipart/list.go`
- **.HandleListParts()** (8 connections) — `internal/proxy/handlers/multipart/list.go`
- **.listPassThroughParts()** (8 connections) — `internal/proxy/handlers/multipart/list.go`
- **callerOwner()** (7 connections) — `internal/proxy/handlers/multipart/list.go`
- **.HandleListMultipartUploads()** (7 connections) — `internal/proxy/handlers/multipart/list.go`
- **list.go** (5 connections) — `internal/proxy/handlers/multipart/list.go`
- **formatListTime()** (5 connections) — `internal/proxy/handlers/multipart/list.go`
- **parseListingCount()** (3 connections) — `internal/proxy/handlers/multipart/list.go`
- **.list()** (3 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **ownerEntry** (1 connections)

## Relationships

- [Multipart Handler Constructors](Multipart_Handler_Constructors.md) (10 shared connections)
- [Replication and ACL Handlers](Replication_and_ACL_Handlers.md) (5 shared connections)
- [Bucket Website and Create/Delete](Bucket_Website_and_Create-Delete.md) (5 shared connections)
- [ACL, CORS and Lifecycle Handlers](ACL,_CORS_and_Lifecycle_Handlers.md) (2 shared connections)
- [Object Listing Handler](Object_Listing_Handler.md) (1 shared connections)
- [S3 Signing Helper](S3_Signing_Helper.md) (1 shared connections)
- [Multipart Handler Coverage Tests](Multipart_Handler_Coverage_Tests.md) (1 shared connections)

## Source Files

- `internal/proxy/handlers/multipart/list.go`
- `internal/proxy/handlers/multipart/multipart_coverage_test.go`

## Audit Trail

- EXTRACTED: 40 (93%)
- INFERRED: 3 (7%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*