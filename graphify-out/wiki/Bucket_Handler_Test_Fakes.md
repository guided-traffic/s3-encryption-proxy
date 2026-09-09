# Bucket Handler Test Fakes

> 71 nodes · cohesion 0.09

## Key Concepts

- **BktnewHandlerWith()** (38 connections) — `internal/proxy/handlers/bucket/subresource_methods_coverage_test.go`
- **Bktserve()** (35 connections) — `internal/proxy/handlers/bucket/subresource_methods_coverage_test.go`
- **subresource_methods_coverage_test.go** (26 connections) — `internal/proxy/handlers/bucket/subresource_methods_coverage_test.go`
- **BktparseError()** (24 connections) — `internal/proxy/handlers/bucket/subresource_matrix_coverage_test.go`
- **operations_coverage_test.go** (19 connections) — `internal/proxy/handlers/bucket/operations_coverage_test.go`
- **BktapiError()** (15 connections) — `internal/proxy/handlers/bucket/subresource_methods_coverage_test.go`
- **Bktrequest()** (14 connections) — `internal/proxy/handlers/bucket/subresource_methods_coverage_test.go`
- **BktcaptureV2()** (13 connections) — `internal/proxy/handlers/bucket/operations_coverage_test.go`
- **subresource_matrix_coverage_test.go** (13 connections) — `internal/proxy/handlers/bucket/subresource_matrix_coverage_test.go`
- **BktnewBackend()** (12 connections) — `internal/proxy/handlers/bucket/subresource_matrix_coverage_test.go`
- **BktnewRouter()** (12 connections) — `internal/proxy/handlers/bucket/subresource_matrix_coverage_test.go`
- **TestBktCreateBucketParsesTheLocationConstraint()** (8 connections) — `internal/proxy/handlers/bucket/operations_coverage_test.go`
- **TestBktHeadBucketIsImplementedAsAListing()** (8 connections) — `internal/proxy/handlers/bucket/operations_coverage_test.go`
- **TestBktBodyCarryingSubResourcePutsAreRefusedOrSilentlyEmptied()** (8 connections) — `internal/proxy/handlers/bucket/subresource_methods_coverage_test.go`
- **BktcaptureV1()** (7 connections) — `internal/proxy/handlers/bucket/operations_coverage_test.go`
- **TestBktDeleteBucketAnswers204()** (7 connections) — `internal/proxy/handlers/bucket/operations_coverage_test.go`
- **TestBktResponseWriteFailuresAreLoggedNotPropagated()** (7 connections) — `internal/proxy/handlers/bucket/operations_coverage_test.go`
- **TestBktACLPutParsesTheBodyWhenNoCannedHeader()** (7 connections) — `internal/proxy/handlers/bucket/subresource_methods_coverage_test.go`
- **TestBktCORSRoundTrip()** (7 connections) — `internal/proxy/handlers/bucket/subresource_methods_coverage_test.go`
- **TestBktLoggingPutRoundTrip()** (7 connections) — `internal/proxy/handlers/bucket/subresource_methods_coverage_test.go`
- **TestBktPolicyPutValidatesJSONBeforeForwarding()** (7 connections) — `internal/proxy/handlers/bucket/subresource_methods_coverage_test.go`
- **TestBktWriteOnlySubResourcesAreNotImplemented()** (7 connections) — `internal/proxy/handlers/bucket/subresource_methods_coverage_test.go`
- **.Header()** (6 connections) — `internal/proxy/handlers/bucket/operations_coverage_test.go`
- **TestBktListObjectsBackendErrors()** (6 connections) — `internal/proxy/handlers/bucket/operations_coverage_test.go`
- **TestBktListObjectsEmptyBucketIsAWellFormedDocument()** (6 connections) — `internal/proxy/handlers/bucket/operations_coverage_test.go`
- *... and 46 more nodes in this community*

## Relationships

- [Config Accessor Tests](Config_Accessor_Tests.md) (43 shared connections)
- [Bucket Lifecycle Handler](Bucket_Lifecycle_Handler.md) (3 shared connections)
- [Object Header Conformance Tests](Object_Header_Conformance_Tests.md) (2 shared connections)
- [ListObjects Backend Method](ListObjects_Backend_Method.md) (2 shared connections)
- [ListObjectsV2 Backend Method](ListObjectsV2_Backend_Method.md) (2 shared connections)
- [Multipart Handler Tests](Multipart_Handler_Tests.md) (2 shared connections)
- [DeleteObjects Handler Tests](DeleteObjects_Handler_Tests.md) (2 shared connections)
- [Middleware Chain Setup Tests](Middleware_Chain_Setup_Tests.md) (1 shared connections)
- [Multipart Handler Construction](Multipart_Handler_Construction.md) (1 shared connections)
- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (1 shared connections)

## Source Files

- `internal/proxy/handlers/bucket/operations_coverage_test.go`
- `internal/proxy/handlers/bucket/subresource_matrix_coverage_test.go`
- `internal/proxy/handlers/bucket/subresource_methods_coverage_test.go`

## Audit Trail

- EXTRACTED: 222 (80%)
- INFERRED: 57 (20%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*