# Router and Middleware Setup

> 25 nodes · cohesion 0.17

## Key Concepts

- **router_coverage_test.go** (38 connections) — `internal/proxy/router_coverage_test.go`
- **RtPxrouter()** (23 connections) — `internal/proxy/router_coverage_test.go`
- **RtPxhandlerName()** (10 connections) — `internal/proxy/router_coverage_test.go`
- **RtPxmatch()** (8 connections) — `internal/proxy/router_coverage_test.go`
- **TestRtPxABucketSubResourceWithATrailingSlashReachesItsHandler()** (5 connections) — `internal/proxy/router_coverage_test.go`
- **TestRtPxObjectKeyRouting()** (5 connections) — `internal/proxy/router_coverage_test.go`
- **TestRtPxProbeEndpointsDoNotShadowSameNamedBuckets()** (5 connections) — `internal/proxy/router_coverage_test.go`
- **TestRtPxAKeyEndingInASlashIsStillAKey()** (4 connections) — `internal/proxy/router_coverage_test.go`
- **TestRtPxBaseBucketHandlerRefusesSubResourceRequests()** (4 connections) — `internal/proxy/router_coverage_test.go`
- **TestRtPxBucketSubResourceNeverReachesBaseBucketHandler()** (4 connections) — `internal/proxy/router_coverage_test.go`
- **TestRtPxMalformedPartUploadReachesTheObjectHandler()** (4 connections) — `internal/proxy/router_coverage_test.go`
- **TestRtPxMonitoringMiddlewareIsTransparent()** (4 connections) — `internal/proxy/router_coverage_test.go`
- **TestRtPxPathNormalisationMustNotRewriteTheKey()** (4 connections) — `internal/proxy/router_coverage_test.go`
- **TestRtPxRemovedEndpointsAreOrdinaryBuckets()** (4 connections) — `internal/proxy/router_coverage_test.go`
- **TestRtPxRouteDispatch()** (4 connections) — `internal/proxy/router_coverage_test.go`
- **TestRtPxBucketSubResourceRouteSetIsTheOneTheMatrixMirrors()** (3 connections) — `internal/proxy/router_coverage_test.go`
- **TestRtPxEveryAnswerStatesARequestID()** (3 connections) — `internal/proxy/router_coverage_test.go`
- **TestRtPxEveryBucketRouteAnswersWithATrailingSlashToo()** (3 connections) — `internal/proxy/router_coverage_test.go`
- **TestRtPxEveryRouteIsBoundToAuthentication()** (3 connections) — `internal/proxy/router_coverage_test.go`
- **TestRtPxPreflightReachesTheCORSMiddleware()** (3 connections) — `internal/proxy/router_coverage_test.go`
- **TestRtPxProbesBypassAuthButS3DoesNot()** (3 connections) — `internal/proxy/router_coverage_test.go`
- **TestRtPxUnroutedMethodsAnswerAnS3Error()** (3 connections) — `internal/proxy/router_coverage_test.go`
- **go_pkg_reflect** (2 connections)
- **RtPxwithoutRequestID()** (2 connections) — `internal/proxy/router_coverage_test.go`
- **Server** (1 connections)

## Relationships

- [Shutdown and Test Contexts](Shutdown_and_Test_Contexts.md) (21 shared connections)
- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (16 shared connections)
- [Misc (18)](Misc_18.md) (4 shared connections)
- [Method Not Allowed Handler](Method_Not_Allowed_Handler.md) (3 shared connections)
- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (2 shared connections)
- [Probe Request Detection](Probe_Request_Detection.md) (1 shared connections)
- [Client Library and Storage Format](Client_Library_and_Storage_Format.md) (1 shared connections)

## Source Files

- `internal/proxy/router_coverage_test.go`

## Audit Trail

- EXTRACTED: 96 (96%)
- INFERRED: 4 (4%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*