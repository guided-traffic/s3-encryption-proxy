# Bucket Sub-Resource Handlers

> 116 nodes · cohesion 0.04

## Key Concepts

- **net/http.Request** (150 connections)
- **net/http.ResponseWriter** (125 connections)
- **Handler** (19 connections) — `internal/proxy/handlers/object/operations.go`
- **TaggingHandler** (11 connections) — `internal/proxy/handlers/object/tagging.go`
- **writeVersionHeaders()** (10 connections) — `internal/proxy/handlers/object/helpers.go`
- **.serveRangeByFullDecryption()** (10 connections) — `internal/proxy/handlers/object/range.go`
- **PolicyHandler** (9 connections) — `internal/proxy/handlers/bucket/policy.go`
- **ReplicationHandler** (9 connections) — `internal/proxy/handlers/bucket/replication.go`
- **WebsiteHandler** (9 connections) — `internal/proxy/handlers/bucket/website.go`
- **CleanupContext()** (9 connections) — `internal/proxy/utils/utils.go`
- **.writeGetObjectResponse()** (9 connections) — `internal/proxy/handlers/object/operations.go`
- **.writeRangeResponse()** (9 connections) — `internal/proxy/handlers/object/range.go`
- **objectVersionID()** (8 connections) — `internal/proxy/handlers/object/helpers.go`
- **.Handle()** (8 connections) — `internal/proxy/handlers/multipart/create.go`
- **.handleGetObjectStreamingDecryption()** (8 connections) — `internal/proxy/handlers/object/operations.go`
- **.handlePutObject()** (8 connections) — `internal/proxy/handlers/object/operations.go`
- **.putObjectAutoMultipart()** (8 connections) — `internal/proxy/handlers/object/operations.go`
- **.putObjectStreamingReader()** (8 connections) — `internal/proxy/handlers/object/operations.go`
- **ACLHandler** (7 connections) — `internal/proxy/handlers/bucket/acl.go`
- **TaggingHandler** (7 connections) — `internal/proxy/handlers/bucket/tagging.go`
- **.handleGetObject()** (7 connections) — `internal/proxy/handlers/object/operations.go`
- **.handleGetObjectRange()** (7 connections) — `internal/proxy/handlers/object/range.go`
- **.ReadBody()** (7 connections) — `internal/proxy/request/parser.go`
- **.writeErrorDocument()** (7 connections) — `internal/proxy/response/errors.go`
- **.Handle()** (6 connections) — `internal/proxy/handlers/bucket/acl.go`
- *... and 91 more nodes in this community*

## Relationships

- [Bucket Sub-Resource Registry](Bucket_Sub-Resource_Registry.md) (63 shared connections)
- [Multipart Handler Construction](Multipart_Handler_Construction.md) (50 shared connections)
- [Object Handler Sub-Resources](Object_Handler_Sub-Resources.md) (14 shared connections)
- [Bucket Lifecycle Handler](Bucket_Lifecycle_Handler.md) (10 shared connections)
- [SigV4 Pre-Signed URL Auth](SigV4_Pre-Signed_URL_Auth.md) (10 shared connections)
- [DeleteObjects Handler Tests](DeleteObjects_Handler_Tests.md) (9 shared connections)
- [Bucket Sub-Resource Tests](Bucket_Sub-Resource_Tests.md) (7 shared connections)
- [SigV4 Test Signer](SigV4_Test_Signer.md) (6 shared connections)
- [Object GET Handler Tests](Object_GET_Handler_Tests.md) (5 shared connections)
- [GetObject Backend Method](GetObject_Backend_Method.md) (5 shared connections)
- [Manager Envelope Encryption](Manager_Envelope_Encryption.md) (5 shared connections)
- [Ciphertext Size Arithmetic](Ciphertext_Size_Arithmetic.md) (5 shared connections)

## Source Files

- `internal/proxy/handlers/bucket/acl.go`
- `internal/proxy/handlers/bucket/handler.go`
- `internal/proxy/handlers/bucket/operations.go`
- `internal/proxy/handlers/bucket/policy.go`
- `internal/proxy/handlers/bucket/replication.go`
- `internal/proxy/handlers/bucket/tagging.go`
- `internal/proxy/handlers/bucket/website.go`
- `internal/proxy/handlers/health/handler.go`
- `internal/proxy/handlers/multipart/abort.go`
- `internal/proxy/handlers/multipart/copy.go`
- `internal/proxy/handlers/multipart/create.go`
- `internal/proxy/handlers/multipart/upload.go`
- `internal/proxy/handlers/object/acl.go`
- `internal/proxy/handlers/object/content_encoding.go`
- `internal/proxy/handlers/object/content_encoding_test.go`
- `internal/proxy/handlers/object/copy_bench_test.go`
- `internal/proxy/handlers/object/helpers.go`
- `internal/proxy/handlers/object/metadata_coverage_test.go`
- `internal/proxy/handlers/object/operations.go`
- `internal/proxy/handlers/object/range.go`

## Audit Trail

- EXTRACTED: 486 (93%)
- INFERRED: 37 (7%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*