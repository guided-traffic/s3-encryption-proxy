# ListBuckets Coverage Tests

> 26 nodes · cohesion 0.15

## Key Concepts

- **listbuckets_coverage_test.go** (19 connections) — `internal/proxy/handlers/root/listbuckets_coverage_test.go`
- **RtPxlistBuckets()** (12 connections) — `internal/proxy/handlers/root/listbuckets_coverage_test.go`
- **RtPxdoListBuckets()** (8 connections) — `internal/proxy/handlers/root/listbuckets_coverage_test.go`
- **RtPxnewHandler()** (8 connections) — `internal/proxy/handlers/root/listbuckets_coverage_test.go`
- **.body()** (7 connections) — `internal/proxy/handlers/root/listbuckets_coverage_test.go`
- **WithClientIdentity()** (6 connections) — `internal/proxy/middleware/identity.go`
- **RtPxfailingWriter** (6 connections) — `internal/proxy/handlers/root/listbuckets_coverage_test.go`
- **.Header()** (6 connections) — `internal/proxy/handlers/root/listbuckets_coverage_test.go`
- **TestRtPxListBucketsClientDisconnect()** (5 connections) — `internal/proxy/handlers/root/listbuckets_coverage_test.go`
- **TestRtPxListBucketsDocumentShape()** (5 connections) — `internal/proxy/handlers/root/listbuckets_coverage_test.go`
- **TestRtPxListBucketsRejectsInvalidMaxBuckets()** (5 connections) — `internal/proxy/handlers/root/listbuckets_coverage_test.go`
- **RtPxcall** (5 connections) — `internal/proxy/handlers/root/listbuckets_coverage_test.go`
- **TestRtPxListBucketsBackendErrors()** (4 connections) — `internal/proxy/handlers/root/listbuckets_coverage_test.go`
- **TestRtPxListBucketsEchoesPrefixAndContinuationToken()** (4 connections) — `internal/proxy/handlers/root/listbuckets_coverage_test.go`
- **TestRtPxListBucketsOwnerIsTheCaller()** (4 connections) — `internal/proxy/handlers/root/listbuckets_coverage_test.go`
- **TestRtPxListBucketsEmptyAccount()** (3 connections) — `internal/proxy/handlers/root/listbuckets_coverage_test.go`
- **TestRtPxListBucketsForwardsQueryParameters()** (3 connections) — `internal/proxy/handlers/root/listbuckets_coverage_test.go`
- **TestRtPxListBucketsPassesRequestContext()** (3 connections) — `internal/proxy/handlers/root/listbuckets_coverage_test.go`
- **TestRtPxListBucketsToleratesUnsetFields()** (3 connections) — `internal/proxy/handlers/root/listbuckets_coverage_test.go`
- **RtPxrequest** (3 connections) — `internal/proxy/handlers/root/listbuckets_coverage_test.go`
- **RtPxdiscard** (2 connections) — `internal/proxy/handlers/root/listbuckets_coverage_test.go`
- **Handler** (1 connections)
- **MockS3Backend** (1 connections)
- **.Write()** (1 connections) — `internal/proxy/handlers/root/listbuckets_coverage_test.go`
- **.Write()** (1 connections) — `internal/proxy/handlers/root/listbuckets_coverage_test.go`
- *... and 1 more nodes in this community*

## Relationships

- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (13 shared connections)
- [MockS3Backend Tagging and Policy](MockS3Backend_Tagging_and_Policy.md) (3 shared connections)
- [Object Dispatch Coverage Tests](Object_Dispatch_Coverage_Tests.md) (3 shared connections)
- [ListBuckets Root Handler](ListBuckets_Root_Handler.md) (2 shared connections)
- [Integration Failing Writer Fixtures](Integration_Failing_Writer_Fixtures.md) (2 shared connections)
- [XML Document Marshalling](XML_Document_Marshalling.md) (1 shared connections)
- [Bucket Handler Error Fixtures](Bucket_Handler_Error_Fixtures.md) (1 shared connections)
- [CORS Middleware and SSE-C Stripping](CORS_Middleware_and_SSE-C_Stripping.md) (1 shared connections)
- [Bucket ACL and Accelerate Handlers](Bucket_ACL_and_Accelerate_Handlers.md) (1 shared connections)
- [Object Listing Handler](Object_Listing_Handler.md) (1 shared connections)
- [Request Parser and Framing Tests](Request_Parser_and_Framing_Tests.md) (1 shared connections)
- [Exec](Exec.md) (1 shared connections)

## Source Files

- `internal/proxy/handlers/root/listbuckets_coverage_test.go`
- `internal/proxy/middleware/identity.go`

## Audit Trail

- EXTRACTED: 75 (96%)
- INFERRED: 3 (4%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*