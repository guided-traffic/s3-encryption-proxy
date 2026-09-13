# ListBuckets Handler Tests

> 24 nodes · cohesion 0.17

## Key Concepts

- **listbuckets_coverage_test.go** (19 connections) — `internal/proxy/handlers/root/listbuckets_coverage_test.go`
- **RtPxlistBuckets()** (12 connections) — `internal/proxy/handlers/root/listbuckets_coverage_test.go`
- **RtPxdoListBuckets()** (8 connections) — `internal/proxy/handlers/root/listbuckets_coverage_test.go`
- **RtPxnewHandler()** (8 connections) — `internal/proxy/handlers/root/listbuckets_coverage_test.go`
- **WithClientIdentity()** (6 connections) — `internal/proxy/middleware/identity.go`
- **RtPxfailingWriter** (6 connections) — `internal/proxy/handlers/root/listbuckets_coverage_test.go`
- **.Header()** (6 connections) — `internal/proxy/handlers/root/listbuckets_coverage_test.go`
- **TestRtPxListBucketsClientDisconnect()** (5 connections) — `internal/proxy/handlers/root/listbuckets_coverage_test.go`
- **TestRtPxListBucketsDocumentShape()** (5 connections) — `internal/proxy/handlers/root/listbuckets_coverage_test.go`
- **TestRtPxListBucketsRejectsInvalidMaxBuckets()** (5 connections) — `internal/proxy/handlers/root/listbuckets_coverage_test.go`
- **RtPxcall** (5 connections) — `internal/proxy/handlers/root/listbuckets_coverage_test.go`
- **.body()** (5 connections) — `internal/proxy/handlers/root/listbuckets_coverage_test.go`
- **TestRtPxListBucketsBackendErrors()** (4 connections) — `internal/proxy/handlers/root/listbuckets_coverage_test.go`
- **TestRtPxListBucketsEchoesPrefixAndContinuationToken()** (4 connections) — `internal/proxy/handlers/root/listbuckets_coverage_test.go`
- **TestRtPxListBucketsOwnerIsTheCaller()** (4 connections) — `internal/proxy/handlers/root/listbuckets_coverage_test.go`
- **TestRtPxListBucketsEmptyAccount()** (3 connections) — `internal/proxy/handlers/root/listbuckets_coverage_test.go`
- **TestRtPxListBucketsForwardsQueryParameters()** (3 connections) — `internal/proxy/handlers/root/listbuckets_coverage_test.go`
- **TestRtPxListBucketsPassesRequestContext()** (3 connections) — `internal/proxy/handlers/root/listbuckets_coverage_test.go`
- **TestRtPxListBucketsToleratesUnsetFields()** (3 connections) — `internal/proxy/handlers/root/listbuckets_coverage_test.go`
- **RtPxrequest** (3 connections) — `internal/proxy/handlers/root/listbuckets_coverage_test.go`
- **Handler** (1 connections)
- **MockS3Backend** (1 connections)
- **.Write()** (1 connections) — `internal/proxy/handlers/root/listbuckets_coverage_test.go`
- **.WriteHeader()** (1 connections) — `internal/proxy/handlers/root/listbuckets_coverage_test.go`

## Relationships

- [Config Env Expansion](Config_Env_Expansion.md) (13 shared connections)
- [Mock: ListBuckets](Mock-_ListBuckets.md) (3 shared connections)
- [ListBuckets Root Handler Tests](ListBuckets_Root_Handler_Tests.md) (2 shared connections)
- [Object Dispatch and Metadata Tests](Object_Dispatch_and_Metadata_Tests.md) (2 shared connections)
- [Object Header Conformance](Object_Header_Conformance.md) (2 shared connections)
- [Multipart XML Documents](Multipart_XML_Documents.md) (1 shared connections)
- [Discard Response Writer](Discard_Response_Writer.md) (1 shared connections)
- [Bucket Handler Tests](Bucket_Handler_Tests.md) (1 shared connections)
- [CORS Middleware](CORS_Middleware.md) (1 shared connections)
- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (1 shared connections)
- [Client Identity Context](Client_Identity_Context.md) (1 shared connections)
- [Proxy Server Tests](Proxy_Server_Tests.md) (1 shared connections)

## Source Files

- `internal/proxy/handlers/root/listbuckets_coverage_test.go`
- `internal/proxy/middleware/identity.go`

## Audit Trail

- EXTRACTED: 74 (99%)
- INFERRED: 1 (1%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*