# Request Documents and Owner Guard

> 56 nodes · cohesion 0.08

## Key Concepts

- **Parser** (39 connections) — `internal/proxy/request/parser.go`
- **UploadHandler** (21 connections) — `internal/proxy/handlers/multipart/upload.go`
- **.WriteGenericError()** (19 connections) — `internal/proxy/response/errors.go`
- **.Handle()** (18 connections) — `internal/proxy/handlers/multipart/complete.go`
- **.uploadStreamedPart()** (18 connections) — `internal/proxy/handlers/multipart/upload.go`
- **.uploadSegmentedPart()** (14 connections) — `internal/proxy/handlers/multipart/upload.go`
- **.WriteS3Error()** (14 connections) — `internal/proxy/response/errors.go`
- **.Handle()** (12 connections) — `internal/proxy/handlers/multipart/create.go`
- **.Handle()** (12 connections) — `internal/proxy/handlers/multipart/upload.go`
- **.storePassThroughPart()** (12 connections) — `internal/proxy/handlers/multipart/upload.go`
- **.readBody()** (12 connections) — `internal/proxy/request/parser.go`
- **What One In-Flight Request Costs in Memory** (11 connections) — `docs/developer/performance.md`
- **clientETag()** (11 connections) — `internal/proxy/handlers/multipart/handler.go`
- **.HandleListMultipartUploads()** (11 connections) — `internal/proxy/handlers/multipart/list.go`
- **.HandleListParts()** (11 connections) — `internal/proxy/handlers/multipart/list.go`
- **.listPassThroughParts()** (11 connections) — `internal/proxy/handlers/multipart/list.go`
- **.readHeldPart()** (10 connections) — `internal/proxy/handlers/multipart/upload.go`
- **declaredChecksums()** (9 connections) — `internal/proxy/request/checksum.go`
- **Verdict()** (9 connections) — `internal/proxy/request/checksum.go`
- **.Handle()** (9 connections) — `internal/proxy/handlers/multipart/abort.go`
- **.forwardPassThroughPart()** (9 connections) — `internal/proxy/handlers/multipart/upload.go`
- **.uploadPassThroughPart()** (9 connections) — `internal/proxy/handlers/multipart/upload.go`
- **.StreamingReader()** (9 connections) — `internal/proxy/request/parser.go`
- **.readPart()** (8 connections) — `internal/proxy/handlers/multipart/upload.go`
- **.WriteChecksumVerdict()** (8 connections) — `internal/proxy/response/errors.go`
- *... and 31 more nodes in this community*

## Relationships

- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (72 shared connections)
- [Multipart Handlers and Manager](Multipart_Handlers_and_Manager.md) (42 shared connections)
- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (19 shared connections)
- [Orchestration: Segmented Session](Orchestration-_Segmented_Session.md) (12 shared connections)
- [Checksum Verifier](Checksum_Verifier.md) (8 shared connections)
- [Dataencryption: Segmented Gcm Range](Dataencryption-_Segmented_Gcm_Range.md) (7 shared connections)
- [Object: Storage Headers](Object-_Storage_Headers.md) (5 shared connections)
- [Sub-Resource Handler Tests](Sub-Resource_Handler_Tests.md) (4 shared connections)
- [Misc (45)](Misc_45.md) (4 shared connections)
- [Shutdown and Test Contexts](Shutdown_and_Test_Contexts.md) (3 shared connections)
- [Etag: Etag](Etag-_Etag.md) (3 shared connections)
- [Exit Provider and Session Lifecycle](Exit_Provider_and_Session_Lifecycle.md) (2 shared connections)

## Source Files

- `docs/developer/performance.md`
- `internal/orchestration/manager.go`
- `internal/orchestration/segmented_session.go`
- `internal/proxy/handlers/bucket/base.go`
- `internal/proxy/handlers/multipart/abort.go`
- `internal/proxy/handlers/multipart/complete.go`
- `internal/proxy/handlers/multipart/create.go`
- `internal/proxy/handlers/multipart/handler.go`
- `internal/proxy/handlers/multipart/list.go`
- `internal/proxy/handlers/multipart/upload.go`
- `internal/proxy/request/checksum.go`
- `internal/proxy/request/checksum_test.go`
- `internal/proxy/request/parser.go`
- `internal/proxy/request/streaming_aws_decoder.go`
- `internal/proxy/response/errors.go`
- `internal/proxy/response/xml.go`

## Audit Trail

- EXTRACTED: 210 (64%)
- INFERRED: 120 (36%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*