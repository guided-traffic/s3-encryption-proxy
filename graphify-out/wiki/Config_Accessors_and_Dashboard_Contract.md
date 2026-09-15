# Config Accessors and Dashboard Contract

> 62 nodes · cohesion 0.08

## Key Concepts

- **testing.T** (1619 connections)
- **RtPxrouter()** (23 connections) — `internal/proxy/router_coverage_test.go`
- **router_coverage_test.go** (22 connections) — `internal/proxy/router_coverage_test.go`
- **RtPxserver()** (14 connections) — `internal/proxy/middleware_setup_coverage_test.go`
- **middleware_setup_coverage_test.go** (12 connections) — `internal/proxy/middleware_setup_coverage_test.go`
- **RtPxhandlerName()** (10 connections) — `internal/proxy/router_coverage_test.go`
- **monExportedSeries()** (9 connections) — `internal/monitoring/dashboard_contract_test.go`
- **RtPxmatch()** (8 connections) — `internal/proxy/router_coverage_test.go`
- **RtPxsignedRequest()** (7 connections) — `internal/proxy/middleware_setup_coverage_test.go`
- **dashboard_contract_test.go** (6 connections) — `internal/monitoring/dashboard_contract_test.go`
- **accessors_coverage_test.go** (5 connections) — `internal/config/accessors_coverage_test.go`
- **cors_test.go** (5 connections) — `internal/proxy/handlers/bucket/cors_test.go`
- **TestRtPxABucketSubResourceWithATrailingSlashReachesItsHandler()** (5 connections) — `internal/proxy/router_coverage_test.go`
- **TestRtPxProbeEndpointsDoNotShadowSameNamedBuckets()** (5 connections) — `internal/proxy/router_coverage_test.go`
- **TestRtPxS3AuthMiddlewareAcceptsSignedRequest()** (4 connections) — `internal/proxy/middleware_setup_coverage_test.go`
- **TestRtPxS3AuthMiddlewareRejections()** (4 connections) — `internal/proxy/middleware_setup_coverage_test.go`
- **TestRtPxAKeyEndingInASlashIsStillAKey()** (4 connections) — `internal/proxy/router_coverage_test.go`
- **TestRtPxBaseBucketHandlerRefusesSubResourceRequests()** (4 connections) — `internal/proxy/router_coverage_test.go`
- **TestRtPxBucketSubResourceNeverReachesBaseBucketHandler()** (4 connections) — `internal/proxy/router_coverage_test.go`
- **TestRtPxMalformedPartUploadReachesTheObjectHandler()** (4 connections) — `internal/proxy/router_coverage_test.go`
- **TestRtPxMonitoringMiddlewareIsTransparent()** (4 connections) — `internal/proxy/router_coverage_test.go`
- **TestRtPxObjectKeyRouting()** (4 connections) — `internal/proxy/router_coverage_test.go`
- **TestRtPxPathNormalisationMustNotRewriteTheKey()** (4 connections) — `internal/proxy/router_coverage_test.go`
- **TestRtPxRemovedEndpointsAreOrdinaryBuckets()** (4 connections) — `internal/proxy/router_coverage_test.go`
- **TestRtPxRouteDispatch()** (4 connections) — `internal/proxy/router_coverage_test.go`
- *... and 37 more nodes in this community*

## Relationships

- [Object GET Coverage Tests](Object_GET_Coverage_Tests.md) (107 shared connections)
- [Multipart Handler Coverage Tests](Multipart_Handler_Coverage_Tests.md) (71 shared connections)
- [Chunked Streaming Test Harness](Chunked_Streaming_Test_Harness.md) (70 shared connections)
- [Velero E2E Backup Suite](Velero_E2E_Backup_Suite.md) (58 shared connections)
- [Bucket Handler Error Fixtures](Bucket_Handler_Error_Fixtures.md) (56 shared connections)
- [DeleteObjects Handler Tests](DeleteObjects_Handler_Tests.md) (56 shared connections)
- [Checksum and ETag Echo Tests](Checksum_and_ETag_Echo_Tests.md) (51 shared connections)
- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (39 shared connections)
- [Authentication Integration Tests](Authentication_Integration_Tests.md) (34 shared connections)
- [Segmented Session Tests](Segmented_Session_Tests.md) (34 shared connections)
- [DEK Cache and Provider Manager](DEK_Cache_and_Provider_Manager.md) (32 shared connections)
- [Keygen and KEK Factory](Keygen_and_KEK_Factory.md) (31 shared connections)

## Source Files

- `internal/config/accessors_coverage_test.go`
- `internal/config/optimizations_test.go`
- `internal/monitoring/dashboard_contract_test.go`
- `internal/proxy/handlers/bucket/cors_test.go`
- `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- `internal/proxy/middleware_setup_coverage_test.go`
- `internal/proxy/router_coverage_test.go`

## Audit Trail

- EXTRACTED: 1723 (99%)
- INFERRED: 13 (1%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*