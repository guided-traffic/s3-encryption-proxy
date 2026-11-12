# Bucket Handler Tests

> 92 nodes · cohesion 0.06

## Key Concepts

- **subresource_methods_coverage_test.go** (57 connections) — `internal/proxy/handlers/bucket/subresource_methods_coverage_test.go`
- **BktnewHandlerWith()** (43 connections) — `internal/proxy/handlers/bucket/subresource_methods_coverage_test.go`
- **Bktserve()** (28 connections) — `internal/proxy/handlers/bucket/subresource_methods_coverage_test.go`
- **BktparseError()** (27 connections) — `internal/proxy/handlers/bucket/subresource_matrix_coverage_test.go`
- **BktauthGet()** (19 connections) — `internal/proxy/handlers/bucket/operations_coverage_test.go`
- **BktcaptureV2()** (18 connections) — `internal/proxy/handlers/bucket/operations_coverage_test.go`
- **BktnewBackend()** (17 connections) — `internal/proxy/handlers/bucket/subresource_matrix_coverage_test.go`
- **Bktrequest()** (16 connections) — `internal/proxy/handlers/bucket/subresource_methods_coverage_test.go`
- **BktapiError()** (15 connections) — `internal/proxy/handlers/bucket/subresource_methods_coverage_test.go`
- **BktnewRouter()** (13 connections) — `internal/proxy/handlers/bucket/subresource_matrix_coverage_test.go`
- **BktcaptureV1()** (12 connections) — `internal/proxy/handlers/bucket/operations_coverage_test.go`
- **BktnewHandlerWithProvider()** (10 connections) — `internal/proxy/handlers/bucket/operations_coverage_test.go`
- **TestBktHeadBucketIsARealHeadBucket()** (8 connections) — `internal/proxy/handlers/bucket/operations_coverage_test.go`
- **TestBktListObjectsElementOrder()** (8 connections) — `internal/proxy/handlers/bucket/operations_coverage_test.go`
- **BktChunkedHandler()** (8 connections) — `internal/proxy/handlers/bucket/subresource_chunked_body_test.go`
- **TestBktBodyCarryingSubResourcePutsAreRefusedOrSilentlyEmptied()** (8 connections) — `internal/proxy/handlers/bucket/subresource_methods_coverage_test.go`
- **TestBktCreateBucketParsesTheLocationConstraint()** (7 connections) — `internal/proxy/handlers/bucket/operations_coverage_test.go`
- **TestBktDeleteBucketAnswers204()** (7 connections) — `internal/proxy/handlers/bucket/operations_coverage_test.go`
- **TestBktListObjectsEmptyBucketIsAWellFormedDocument()** (7 connections) — `internal/proxy/handlers/bucket/operations_coverage_test.go`
- **TestBktListObjectsMaxKeys()** (7 connections) — `internal/proxy/handlers/bucket/operations_coverage_test.go`
- **TestBktListObjectsOwnerIsTheCaller()** (7 connections) — `internal/proxy/handlers/bucket/operations_coverage_test.go`
- **TestBktListObjectsSizeIsThePlaintextSize()** (7 connections) — `internal/proxy/handlers/bucket/operations_coverage_test.go`
- **TestBktListObjectsV1IsARealListBucketResult()** (7 connections) — `internal/proxy/handlers/bucket/operations_coverage_test.go`
- **TestBktListObjectsV2IsARealListBucketResult()** (7 connections) — `internal/proxy/handlers/bucket/operations_coverage_test.go`
- **TestBktResponseWriteFailuresAreLoggedNotPropagated()** (7 connections) — `internal/proxy/handlers/bucket/operations_coverage_test.go`
- *... and 67 more nodes in this community*

## Relationships

- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (86 shared connections)
- [Shutdown and Test Contexts](Shutdown_and_Test_Contexts.md) (60 shared connections)
- [Sub-Resource Handler Tests](Sub-Resource_Handler_Tests.md) (6 shared connections)
- [Multipart Handlers and Manager](Multipart_Handlers_and_Manager.md) (5 shared connections)
- [Misc (19)](Misc_19.md) (2 shared connections)
- [Misc (32)](Misc_32.md) (2 shared connections)
- [Misc (33)](Misc_33.md) (2 shared connections)
- [Misc (2)](Misc_2.md) (2 shared connections)
- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (2 shared connections)
- [Method Not Allowed Handler](Method_Not_Allowed_Handler.md) (2 shared connections)
- [DeleteObjects Handling](DeleteObjects_Handling.md) (1 shared connections)
- [CORS and Middleware](CORS_and_Middleware.md) (1 shared connections)

## Source Files

- `internal/proxy/handlers/bucket/etag_marker_test.go`
- `internal/proxy/handlers/bucket/operations_coverage_test.go`
- `internal/proxy/handlers/bucket/routing_test.go`
- `internal/proxy/handlers/bucket/subresource_chunked_body_test.go`
- `internal/proxy/handlers/bucket/subresource_matrix_coverage_test.go`
- `internal/proxy/handlers/bucket/subresource_methods_coverage_test.go`
- `internal/proxy/router.go`

## Audit Trail

- EXTRACTED: 342 (81%)
- INFERRED: 80 (19%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*