# ListBuckets Root Handler

> 41 nodes · cohesion 0.08

## Key Concepts

- **listbuckets_coverage_test.go** (19 connections) — `internal/proxy/handlers/root/listbuckets_coverage_test.go`
- **NewHandler()** (13 connections) — `internal/proxy/handlers/root/handler.go`
- **RtPxlistBuckets()** (12 connections) — `internal/proxy/handlers/root/listbuckets_coverage_test.go`
- **RtPxdoListBuckets()** (8 connections) — `internal/proxy/handlers/root/listbuckets_coverage_test.go`
- **RtPxnewHandler()** (8 connections) — `internal/proxy/handlers/root/listbuckets_coverage_test.go`
- **.body()** (7 connections) — `internal/proxy/handlers/root/listbuckets_coverage_test.go`
- **root/handler.go** (6 connections) — `internal/proxy/handlers/root/handler.go`
- **WithClientIdentity()** (6 connections) — `internal/proxy/middleware/identity.go`
- **RtPxfailingWriter** (6 connections) — `internal/proxy/handlers/root/listbuckets_coverage_test.go`
- **.Header()** (6 connections) — `internal/proxy/handlers/root/listbuckets_coverage_test.go`
- **TestRtPxListBucketsClientDisconnect()** (5 connections) — `internal/proxy/handlers/root/listbuckets_coverage_test.go`
- **TestRtPxListBucketsDocumentShape()** (5 connections) — `internal/proxy/handlers/root/listbuckets_coverage_test.go`
- **TestRtPxListBucketsRejectsInvalidMaxBuckets()** (5 connections) — `internal/proxy/handlers/root/listbuckets_coverage_test.go`
- **RtPxcall** (5 connections) — `internal/proxy/handlers/root/listbuckets_coverage_test.go`
- **handler_test.go** (4 connections) — `internal/proxy/handlers/root/handler_test.go`
- **TestRtPxListBucketsBackendErrors()** (4 connections) — `internal/proxy/handlers/root/listbuckets_coverage_test.go`
- **TestRtPxListBucketsEchoesPrefixAndContinuationToken()** (4 connections) — `internal/proxy/handlers/root/listbuckets_coverage_test.go`
- **TestRtPxListBucketsOwnerIsTheCaller()** (4 connections) — `internal/proxy/handlers/root/listbuckets_coverage_test.go`
- **ListAllMyBucketsResult** (4 connections) — `internal/proxy/handlers/root/handler.go`
- **TestHandleListBuckets()** (3 connections) — `internal/proxy/handlers/root/handler_test.go`
- **TestHandleListBucketsError()** (3 connections) — `internal/proxy/handlers/root/handler_test.go`
- **TestHandleListBucketsMultipleBuckets()** (3 connections) — `internal/proxy/handlers/root/handler_test.go`
- **TestNewHandler()** (3 connections) — `internal/proxy/handlers/root/handler_test.go`
- **TestRtPxListBucketsEmptyAccount()** (3 connections) — `internal/proxy/handlers/root/listbuckets_coverage_test.go`
- **TestRtPxListBucketsForwardsQueryParameters()** (3 connections) — `internal/proxy/handlers/root/listbuckets_coverage_test.go`
- *... and 16 more nodes in this community*

## Relationships

- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (18 shared connections)
- [Multipart Handler Constructors](Multipart_Handler_Constructors.md) (4 shared connections)
- [Helpers](Helpers.md) (4 shared connections)
- [DeleteObjects Handler Tests](DeleteObjects_Handler_Tests.md) (3 shared connections)
- [XML Document Marshalling](XML_Document_Marshalling.md) (2 shared connections)
- [S3 Method Error Mapping Tests](S3_Method_Error_Mapping_Tests.md) (2 shared connections)
- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (1 shared connections)
- [Copy and Delete Object Handlers](Copy_and_Delete_Object_Handlers.md) (1 shared connections)
- [Router](Router.md) (1 shared connections)
- [Object Listing Handler](Object_Listing_Handler.md) (1 shared connections)
- [Bucket Handler Error Fixtures](Bucket_Handler_Error_Fixtures.md) (1 shared connections)
- [CORS Middleware and SSE-C Stripping](CORS_Middleware_and_SSE-C_Stripping.md) (1 shared connections)

## Source Files

- `internal/proxy/handlers/root/handler.go`
- `internal/proxy/handlers/root/handler_test.go`
- `internal/proxy/handlers/root/listbuckets_coverage_test.go`
- `internal/proxy/middleware/identity.go`

## Audit Trail

- EXTRACTED: 103 (93%)
- INFERRED: 8 (7%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*