# Multipart ListParts Handler

> 23 nodes · cohesion 0.17

## Key Concepts

- **UploadHandler** (21 connections) — `internal/proxy/handlers/multipart/upload.go`
- **clientETag()** (9 connections) — `internal/proxy/handlers/multipart/handler.go`
- **.Handle()** (9 connections) — `internal/proxy/handlers/multipart/upload.go`
- **.HandleListParts()** (8 connections) — `internal/proxy/handlers/multipart/list.go`
- **.listPassThroughParts()** (8 connections) — `internal/proxy/handlers/multipart/list.go`
- **.storePassThroughPart()** (8 connections) — `internal/proxy/handlers/multipart/upload.go`
- **callerOwner()** (7 connections) — `internal/proxy/handlers/multipart/list.go`
- **.HandleListMultipartUploads()** (7 connections) — `internal/proxy/handlers/multipart/list.go`
- **.uploadPassThroughPart()** (7 connections) — `internal/proxy/handlers/multipart/upload.go`
- **.uploadSegmentedPart()** (7 connections) — `internal/proxy/handlers/multipart/upload.go`
- **.uploadStreamedPart()** (7 connections) — `internal/proxy/handlers/multipart/upload.go`
- **list.go** (6 connections) — `internal/proxy/handlers/multipart/list.go`
- **.readHeldPart()** (6 connections) — `internal/proxy/handlers/multipart/upload.go`
- **formatListTime()** (5 connections) — `internal/proxy/handlers/multipart/list.go`
- **.forwardPassThroughPart()** (5 connections) — `internal/proxy/handlers/multipart/upload.go`
- **.readPart()** (5 connections) — `internal/proxy/handlers/multipart/upload.go`
- **.readUndeclaredPart()** (5 connections) — `internal/proxy/handlers/multipart/upload.go`
- **parseListingCount()** (3 connections) — `internal/proxy/handlers/multipart/list.go`
- **.noSuchUpload()** (3 connections) — `internal/proxy/handlers/multipart/upload.go`
- **ListParts answered from the session part table** (2 connections) — `docs/security/refusals.md`
- **upload.go** (2 connections) — `internal/proxy/handlers/multipart/upload.go`
- **.GetUploadHandler()** (2 connections) — `internal/proxy/handlers/multipart/handler.go`
- **ownerEntry** (1 connections)

## Relationships

- [Bucket ACL and Accelerate Handlers](Bucket_ACL_and_Accelerate_Handlers.md) (27 shared connections)
- [Multipart Handler Wiring](Multipart_Handler_Wiring.md) (14 shared connections)
- [Object Response Header Helpers](Object_Response_Header_Helpers.md) (6 shared connections)
- [Segmented Session Lifecycle](Segmented_Session_Lifecycle.md) (5 shared connections)
- [Multipart Handler Constructors](Multipart_Handler_Constructors.md) (2 shared connections)
- [ETag Marker Codec](ETag_Marker_Codec.md) (1 shared connections)
- [Object Listing Handler](Object_Listing_Handler.md) (1 shared connections)
- [Health Probes and Request Tracker](Health_Probes_and_Request_Tracker.md) (1 shared connections)
- [Multipart Handler Coverage Tests](Multipart_Handler_Coverage_Tests.md) (1 shared connections)
- [Segmented Manager Streaming IO](Segmented_Manager_Streaming_IO.md) (1 shared connections)

## Source Files

- `docs/security/refusals.md`
- `internal/proxy/handlers/multipart/handler.go`
- `internal/proxy/handlers/multipart/list.go`
- `internal/proxy/handlers/multipart/upload.go`

## Audit Trail

- EXTRACTED: 95 (94%)
- INFERRED: 6 (6%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*