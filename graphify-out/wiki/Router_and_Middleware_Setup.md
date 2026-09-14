# Router and Middleware Setup

> 29 nodes · cohesion 0.14

## Key Concepts

- **RtPxrouter()** (15 connections) — `internal/proxy/router_coverage_test.go`
- **router_coverage_test.go** (13 connections) — `internal/proxy/router_coverage_test.go`
- **RtPxserver()** (12 connections) — `internal/proxy/middleware_setup_coverage_test.go`
- **middleware_setup_coverage_test.go** (10 connections) — `internal/proxy/middleware_setup_coverage_test.go`
- **RtPxhandlerName()** (8 connections) — `internal/proxy/router_coverage_test.go`
- **RtPxmatch()** (6 connections) — `internal/proxy/router_coverage_test.go`
- **github.com/gorilla/mux.Router** (5 connections)
- **RtPxsignedRequest()** (5 connections) — `internal/proxy/middleware_setup_coverage_test.go`
- **TestRtPxS3AuthMiddlewareAcceptsSignedRequest()** (4 connections) — `internal/proxy/middleware_setup_coverage_test.go`
- **TestRtPxS3AuthMiddlewareRejections()** (4 connections) — `internal/proxy/middleware_setup_coverage_test.go`
- **TestRtPxBaseBucketHandlerRefusesSubResourceRequests()** (4 connections) — `internal/proxy/router_coverage_test.go`
- **TestRtPxBucketSubResourceNeverReachesBaseBucketHandler()** (4 connections) — `internal/proxy/router_coverage_test.go`
- **TestRtPxHealthEndpointsShadowSameNamedBuckets()** (4 connections) — `internal/proxy/router_coverage_test.go`
- **TestRtPxMalformedPartUploadReachesTheObjectHandler()** (4 connections) — `internal/proxy/router_coverage_test.go`
- **TestRtPxObjectKeyRouting()** (4 connections) — `internal/proxy/router_coverage_test.go`
- **TestRtPxRouteDispatch()** (4 connections) — `internal/proxy/router_coverage_test.go`
- **TestRtPxDetermineErrorCodeMapping()** (3 connections) — `internal/proxy/middleware_setup_coverage_test.go`
- **TestRtPxMiddlewareChainStreamsBodyUnchanged()** (3 connections) — `internal/proxy/middleware_setup_coverage_test.go`
- **TestRtPxMiddlewareWrappersInitialiseOnDemand()** (3 connections) — `internal/proxy/middleware_setup_coverage_test.go`
- **TestRtPxSetupMiddlewareHonoursLogHealthRequests()** (3 connections) — `internal/proxy/middleware_setup_coverage_test.go`
- **TestRtPxWriteS3ErrorDocument()** (3 connections) — `internal/proxy/middleware_setup_coverage_test.go`
- **TestRtPxHealthBypassesAuthButS3DoesNot()** (3 connections) — `internal/proxy/router_coverage_test.go`
- **TestRtPxMonitoringMiddlewareIsTransparent()** (3 connections) — `internal/proxy/router_coverage_test.go`
- **TestRtPxPathNormalisationRedirectsToADifferentKey()** (3 connections) — `internal/proxy/router_coverage_test.go`
- **TestRtPxUnroutedMethodsBypassTheMiddlewareChain()** (3 connections) — `internal/proxy/router_coverage_test.go`
- *... and 4 more nodes in this community*

## Relationships

- [Config Env Expansion](Config_Env_Expansion.md) (22 shared connections)
- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (3 shared connections)
- [Multipart Handler](Multipart_Handler.md) (1 shared connections)
- [Bucket Handler Tests](Bucket_Handler_Tests.md) (1 shared connections)
- [Proxy Server Tests](Proxy_Server_Tests.md) (1 shared connections)

## Source Files

- `internal/proxy/middleware_setup_coverage_test.go`
- `internal/proxy/router_coverage_test.go`

## Audit Trail

- EXTRACTED: 80 (96%)
- INFERRED: 3 (4%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*