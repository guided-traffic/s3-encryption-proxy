# ListBuckets Root Handler

> 31 nodes · cohesion 0.10

## Key Concepts

- **listbuckets_coverage_test.go** (13 connections) — `internal/proxy/handlers/root/listbuckets_coverage_test.go`
- **NewHandler()** (12 connections) — `internal/proxy/handlers/root/handler.go`
- **RtPxdoListBuckets()** (10 connections) — `internal/proxy/handlers/root/listbuckets_coverage_test.go`
- **RtPxnewHandler()** (8 connections) — `internal/proxy/handlers/root/listbuckets_coverage_test.go`
- **root/handler.go** (6 connections) — `internal/proxy/handlers/root/handler.go`
- **RtPxfailingWriter** (6 connections) — `internal/proxy/handlers/root/listbuckets_coverage_test.go`
- **.Header()** (5 connections) — `internal/proxy/handlers/root/listbuckets_coverage_test.go`
- **handler_test.go** (4 connections) — `internal/proxy/handlers/root/handler_test.go`
- **TestRtPxListBucketsBackendErrors()** (4 connections) — `internal/proxy/handlers/root/listbuckets_coverage_test.go`
- **TestRtPxListBucketsClientDisconnect()** (4 connections) — `internal/proxy/handlers/root/listbuckets_coverage_test.go`
- **TestRtPxListBucketsDocumentShape()** (4 connections) — `internal/proxy/handlers/root/listbuckets_coverage_test.go`
- **ListAllMyBucketsResult** (4 connections) — `internal/proxy/handlers/root/handler.go`
- **TestHandleListBuckets()** (3 connections) — `internal/proxy/handlers/root/handler_test.go`
- **TestHandleListBucketsError()** (3 connections) — `internal/proxy/handlers/root/handler_test.go`
- **TestHandleListBucketsMultipleBuckets()** (3 connections) — `internal/proxy/handlers/root/handler_test.go`
- **TestNewHandler()** (3 connections) — `internal/proxy/handlers/root/handler_test.go`
- **TestRtPxListBucketsEmptyAccount()** (3 connections) — `internal/proxy/handlers/root/listbuckets_coverage_test.go`
- **TestRtPxListBucketsPassesRequestContext()** (3 connections) — `internal/proxy/handlers/root/listbuckets_coverage_test.go`
- **TestRtPxListBucketsTolerartesUnsetFields()** (3 connections) — `internal/proxy/handlers/root/listbuckets_coverage_test.go`
- **TestRtPxListBucketsWithoutOwner()** (3 connections) — `internal/proxy/handlers/root/listbuckets_coverage_test.go`
- **TestRtPxNewHandlerIsUsableImmediately()** (3 connections) — `internal/proxy/handlers/root/listbuckets_coverage_test.go`
- **S3Bucket** (3 connections) — `internal/proxy/handlers/root/handler.go`
- **S3Buckets** (3 connections) — `internal/proxy/handlers/root/handler.go`
- **RtPxdiscard** (2 connections) — `internal/proxy/handlers/root/listbuckets_coverage_test.go`
- **RtPxlistBucketsDoc** (2 connections) — `internal/proxy/handlers/root/listbuckets_coverage_test.go`
- *... and 6 more nodes in this community*

## Relationships

- [Config Accessor Tests](Config_Accessor_Tests.md) (14 shared connections)
- [Multipart Handler Construction](Multipart_Handler_Construction.md) (4 shared connections)
- [Multipart Handler Tests](Multipart_Handler_Tests.md) (2 shared connections)
- [Object Header Conformance Tests](Object_Header_Conformance_Tests.md) (2 shared connections)
- [Bucket Sub-Resource Tests](Bucket_Sub-Resource_Tests.md) (1 shared connections)
- [Proxy Utility Functions](Proxy_Utility_Functions.md) (1 shared connections)
- [S3 Backend Interface Types](S3_Backend_Interface_Types.md) (1 shared connections)
- [DeleteObjects Handler Tests](DeleteObjects_Handler_Tests.md) (1 shared connections)
- [Proxy Utils Tests](Proxy_Utils_Tests.md) (1 shared connections)
- [SigV4 Test Signer](SigV4_Test_Signer.md) (1 shared connections)

## Source Files

- `internal/proxy/handlers/root/handler.go`
- `internal/proxy/handlers/root/handler_test.go`
- `internal/proxy/handlers/root/listbuckets_coverage_test.go`

## Audit Trail

- EXTRACTED: 70 (92%)
- INFERRED: 6 (8%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*