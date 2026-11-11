# Router and Middleware Setup

> 43 nodes · cohesion 0.10

## Key Concepts

- **router_coverage_test.go** (38 connections) — `internal/proxy/router_coverage_test.go`
- **middleware_setup_coverage_test.go** (30 connections) — `internal/proxy/middleware_setup_coverage_test.go`
- **RtPxrouter()** (23 connections) — `internal/proxy/router_coverage_test.go`
- **RtPxserver()** (14 connections) — `internal/proxy/middleware_setup_coverage_test.go`
- **RtPxhandlerName()** (10 connections) — `internal/proxy/router_coverage_test.go`
- **github.com/gorilla/mux.Router** (8 connections)
- **RtPxmatch()** (8 connections) — `internal/proxy/router_coverage_test.go`
- **RtPxsignedRequest()** (7 connections) — `internal/proxy/middleware_setup_coverage_test.go`
- **TestRtPxABucketSubResourceWithATrailingSlashReachesItsHandler()** (5 connections) — `internal/proxy/router_coverage_test.go`
- **TestRtPxObjectKeyRouting()** (5 connections) — `internal/proxy/router_coverage_test.go`
- **TestRtPxProbeEndpointsDoNotShadowSameNamedBuckets()** (5 connections) — `internal/proxy/router_coverage_test.go`
- **net/http.HandlerFunc** (4 connections)
- **TestRtPxS3AuthMiddlewareAcceptsSignedRequest()** (4 connections) — `internal/proxy/middleware_setup_coverage_test.go`
- **TestRtPxS3AuthMiddlewareRejections()** (4 connections) — `internal/proxy/middleware_setup_coverage_test.go`
- **bucketRoute()** (4 connections) — `internal/proxy/router.go`
- **TestRtPxAKeyEndingInASlashIsStillAKey()** (4 connections) — `internal/proxy/router_coverage_test.go`
- **TestRtPxBaseBucketHandlerRefusesSubResourceRequests()** (4 connections) — `internal/proxy/router_coverage_test.go`
- **TestRtPxBucketSubResourceNeverReachesBaseBucketHandler()** (4 connections) — `internal/proxy/router_coverage_test.go`
- **TestRtPxMalformedPartUploadReachesTheObjectHandler()** (4 connections) — `internal/proxy/router_coverage_test.go`
- **TestRtPxMonitoringMiddlewareIsTransparent()** (4 connections) — `internal/proxy/router_coverage_test.go`
- **TestRtPxPathNormalisationMustNotRewriteTheKey()** (4 connections) — `internal/proxy/router_coverage_test.go`
- **TestRtPxRemovedEndpointsAreOrdinaryBuckets()** (4 connections) — `internal/proxy/router_coverage_test.go`
- **TestRtPxRouteDispatch()** (4 connections) — `internal/proxy/router_coverage_test.go`
- **go_pkg_github_com_aws_aws_sdk_go_v2_aws_signer_v4** (3 connections)
- **TestRtPxDetermineErrorCodeMapping()** (3 connections) — `internal/proxy/middleware_setup_coverage_test.go`
- *... and 18 more nodes in this community*

## Relationships

- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (35 shared connections)
- [Shutdown and Test Contexts](Shutdown_and_Test_Contexts.md) (32 shared connections)
- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (4 shared connections)
- [Bucket Handler Tests](Bucket_Handler_Tests.md) (3 shared connections)
- [CORS and Middleware](CORS_and_Middleware.md) (2 shared connections)
- [Multipart Handlers and Manager](Multipart_Handlers_and_Manager.md) (2 shared connections)
- [DeleteObjects Conformance](DeleteObjects_Conformance.md) (1 shared connections)
- [DeleteObjects Handling](DeleteObjects_Handling.md) (1 shared connections)
- [Backend TLS Trust](Backend_TLS_Trust.md) (1 shared connections)
- [Client Library and Storage Format](Client_Library_and_Storage_Format.md) (1 shared connections)

## Source Files

- `internal/proxy/middleware_setup_coverage_test.go`
- `internal/proxy/router.go`
- `internal/proxy/router_coverage_test.go`

## Audit Trail

- EXTRACTED: 163 (97%)
- INFERRED: 5 (3%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*