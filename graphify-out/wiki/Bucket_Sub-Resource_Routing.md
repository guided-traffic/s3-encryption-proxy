# Bucket Sub-Resource Routing

> 134 nodes · cohesion 0.05

## Key Concepts

- **Server.setupRoutes (S3 route table)** (45 connections) — `internal/proxy/router.go`
- **.setupRoutes()** (42 connections) — `internal/proxy/router.go`
- **BktnewHandlerWith()** (37 connections) — `internal/proxy/handlers/bucket/subresource_methods_coverage_test.go`
- **Bktserve()** (33 connections) — `internal/proxy/handlers/bucket/subresource_methods_coverage_test.go`
- **subresource_methods_coverage_test.go** (26 connections) — `internal/proxy/handlers/bucket/subresource_methods_coverage_test.go`
- **BktnewRouter()** (24 connections) — `internal/proxy/handlers/bucket/subresource_matrix_coverage_test.go`
- **TestMpuHandlerFacadeWiresEverySubHandler()** (23 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **BktparseError()** (23 connections) — `internal/proxy/handlers/bucket/subresource_matrix_coverage_test.go`
- **TestBktSubResourceGetForwardsBackendErrorsUnchanged()** (21 connections) — `internal/proxy/handlers/bucket/subresource_methods_coverage_test.go`
- **Handler** (20 connections) — `internal/proxy/handlers/bucket/operations.go`
- **operations_coverage_test.go** (19 connections) — `internal/proxy/handlers/bucket/operations_coverage_test.go`
- **.GetLoggingHandler()** (18 connections) — `internal/proxy/handlers/bucket/handler.go`
- **.GetPolicyHandler()** (16 connections) — `internal/proxy/handlers/bucket/handler.go`
- **TestMainBucketHandler_NewHandlers()** (16 connections) — `internal/proxy/handlers/bucket/handlers_test.go`
- **BktapiError()** (15 connections) — `internal/proxy/handlers/bucket/subresource_methods_coverage_test.go`
- **.GetACLHandler()** (14 connections) — `internal/proxy/handlers/object/handler.go`
- **BktcaptureV2()** (14 connections) — `internal/proxy/handlers/bucket/operations_coverage_test.go`
- **TestBktACLPutParsesTheBodyWhenNoCannedHeader()** (14 connections) — `internal/proxy/handlers/bucket/subresource_methods_coverage_test.go`
- **TestBktBodyCarryingSubResourcePutsAreRefusedOrSilentlyEmptied()** (14 connections) — `internal/proxy/handlers/bucket/subresource_methods_coverage_test.go`
- **TestBktCORSRoundTrip()** (14 connections) — `internal/proxy/handlers/bucket/subresource_methods_coverage_test.go`
- **subresource_matrix_coverage_test.go** (13 connections) — `internal/proxy/handlers/bucket/subresource_matrix_coverage_test.go`
- **Handler** (13 connections) — `internal/proxy/handlers/multipart/handler.go`
- **Bktrequest()** (13 connections) — `internal/proxy/handlers/bucket/subresource_methods_coverage_test.go`
- **TestBktWriteOnlySubResourcesAreNotImplemented()** (13 connections) — `internal/proxy/handlers/bucket/subresource_methods_coverage_test.go`
- **TestBktCreateBucketParsesTheLocationConstraint()** (12 connections) — `internal/proxy/handlers/bucket/operations_coverage_test.go`
- *... and 109 more nodes in this community*

## Relationships

- No strong cross-community connections detected

## Source Files

- `docs/architecture/callgraph_proxy_layer.svg`
- `internal/proxy/handlers/bucket/acl.go`
- `internal/proxy/handlers/bucket/cors.go`
- `internal/proxy/handlers/bucket/handler.go`
- `internal/proxy/handlers/bucket/handlers_test.go`
- `internal/proxy/handlers/bucket/logging.go`
- `internal/proxy/handlers/bucket/operations.go`
- `internal/proxy/handlers/bucket/operations_coverage_test.go`
- `internal/proxy/handlers/bucket/subresource_matrix_coverage_test.go`
- `internal/proxy/handlers/bucket/subresource_methods_coverage_test.go`
- `internal/proxy/handlers/multipart/abort.go`
- `internal/proxy/handlers/multipart/complete.go`
- `internal/proxy/handlers/multipart/create.go`
- `internal/proxy/handlers/multipart/handler.go`
- `internal/proxy/handlers/multipart/list.go`
- `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- `internal/proxy/handlers/multipart/upload.go`
- `internal/proxy/handlers/object/handler.go`
- `internal/proxy/router.go`
- `internal/proxy/server_test.go`

## Audit Trail

- EXTRACTED: 528 (50%)
- INFERRED: 530 (50%)
- AMBIGUOUS: 1 (0%)

---

*Part of the graphify knowledge wiki. See [[index]] to navigate.*