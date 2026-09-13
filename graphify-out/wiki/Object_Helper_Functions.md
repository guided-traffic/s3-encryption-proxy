# Object Helper Functions

> 22 nodes · cohesion 0.11

## Key Concepts

- **CleanupContext()** (8 connections) — `internal/proxy/utils/utils.go`
- **.putObjectAutoMultipart()** (8 connections) — `internal/proxy/handlers/object/operations.go`
- **.Handle()** (7 connections) — `internal/proxy/handlers/multipart/create.go`
- **Handler** (6 connections) — `internal/proxy/handlers/object/helpers.go`
- **.abortUpload()** (6 connections) — `internal/proxy/handlers/multipart/complete.go`
- **.Handle()** (6 connections) — `internal/proxy/handlers/multipart/complete.go`
- **StripAWSChunked()** (5 connections) — `internal/proxy/handlers/object/content_encoding.go`
- **.Handle()** (5 connections) — `internal/proxy/handlers/multipart/abort.go`
- **complete.go** (4 connections) — `internal/proxy/handlers/multipart/complete.go`
- **CompleteMultipartUpload** (4 connections) — `internal/proxy/handlers/multipart/complete.go`
- **.addRequestHeaders()** (4 connections) — `internal/proxy/handlers/object/helpers.go`
- **TestStripAWSChunked()** (3 connections) — `internal/proxy/handlers/object/content_encoding_test.go`
- **.userMetadata()** (3 connections) — `internal/proxy/handlers/multipart/create.go`
- **.isEncryptionMetadata()** (3 connections) — `internal/proxy/handlers/object/helpers.go`
- **.userMetadataFromRequest()** (3 connections) — `internal/proxy/handlers/object/helpers.go`
- **.cleanupSession()** (2 connections) — `internal/proxy/handlers/multipart/abort.go`
- **CompletedPart** (2 connections) — `internal/proxy/handlers/multipart/complete.go`
- **.cleanMetadata()** (2 connections) — `internal/proxy/handlers/object/helpers.go`
- **content_encoding.go** (1 connections) — `internal/proxy/handlers/object/content_encoding.go`
- **content_encoding_test.go** (1 connections) — `internal/proxy/handlers/object/content_encoding_test.go`
- **.getMultipartUploadConcurrency()** (1 connections) — `internal/proxy/handlers/object/helpers.go`
- **.getSegmentSize()** (1 connections) — `internal/proxy/handlers/object/helpers.go`

## Relationships

- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (13 shared connections)
- [Multipart Handler](Multipart_Handler.md) (9 shared connections)
- [Proxy Server Tests](Proxy_Server_Tests.md) (3 shared connections)
- [Object Operations Handler](Object_Operations_Handler.md) (3 shared connections)
- [Multipart Handler Tests](Multipart_Handler_Tests.md) (2 shared connections)
- [Config Env Expansion](Config_Env_Expansion.md) (1 shared connections)
- [Provider Mode Integration Tests](Provider_Mode_Integration_Tests.md) (1 shared connections)
- [Mock Backend Helpers](Mock_Backend_Helpers.md) (1 shared connections)
- [Multipart XML Documents](Multipart_XML_Documents.md) (1 shared connections)
- [Mock: PutObject](Mock-_PutObject.md) (1 shared connections)

## Source Files

- `internal/proxy/handlers/multipart/abort.go`
- `internal/proxy/handlers/multipart/complete.go`
- `internal/proxy/handlers/multipart/create.go`
- `internal/proxy/handlers/object/content_encoding.go`
- `internal/proxy/handlers/object/content_encoding_test.go`
- `internal/proxy/handlers/object/helpers.go`
- `internal/proxy/handlers/object/operations.go`
- `internal/proxy/utils/utils.go`

## Audit Trail

- EXTRACTED: 52 (87%)
- INFERRED: 8 (13%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*