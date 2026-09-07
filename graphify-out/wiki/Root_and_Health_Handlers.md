# Root and Health Handlers

> 92 nodes · cohesion 0.04

## Key Concepts

- **NewHandler()** (77 connections) — `internal/proxy/handlers/root/handler.go`
- **root.Handler.HandleListBuckets** (18 connections) — `internal/proxy/handlers/root/handler.go`
- **handler_coverage_test.go** (16 connections) — `internal/proxy/handlers/health/handler_coverage_test.go`
- **.HandleListBuckets()** (14 connections) — `internal/proxy/handlers/root/handler.go`
- **HlthnewTestLogger()** (13 connections) — `internal/proxy/handlers/health/handler_coverage_test.go`
- **.Health()** (13 connections) — `internal/proxy/handlers/health/handler.go`
- **.SetShutdownStateHandler()** (13 connections) — `internal/proxy/handlers/health/handler.go`
- **listbuckets_coverage_test.go** (13 connections) — `internal/proxy/handlers/root/listbuckets_coverage_test.go`
- **TestHandleListBucketsError()** (11 connections) — `internal/proxy/handlers/root/handler_test.go`
- **TestHlthResponseWriteFailureIsLogged()** (10 connections) — `internal/proxy/handlers/health/handler_coverage_test.go`
- **TestHandleListBuckets()** (10 connections) — `internal/proxy/handlers/root/handler_test.go`
- **.SetRequestTracker()** (10 connections) — `internal/proxy/handlers/health/handler.go`
- **TestHlthHealthShutdownStateHandlerVariants()** (9 connections) — `internal/proxy/handlers/health/handler_coverage_test.go`
- **TestHandleListBucketsMultipleBuckets()** (9 connections) — `internal/proxy/handlers/root/handler_test.go`
- **.Version()** (9 connections) — `internal/proxy/handlers/health/handler.go`
- **TestRtPxListBucketsBackendErrors()** (9 connections) — `internal/proxy/handlers/root/listbuckets_coverage_test.go`
- **TestServer_HealthEndpointLogging()** (9 connections) — `internal/proxy/server_test.go`
- **TestHlthLogHealthRequests()** (8 connections) — `internal/proxy/handlers/health/handler_coverage_test.go`
- **TestHlthRequestTrackerInvocation()** (8 connections) — `internal/proxy/handlers/health/handler_coverage_test.go`
- **TestHlthVersionResponse()** (8 connections) — `internal/proxy/handlers/health/handler_coverage_test.go`
- **RtPxdoListBuckets()** (8 connections) — `internal/proxy/handlers/root/listbuckets_coverage_test.go`
- **TestRtPxListBucketsClientDisconnect()** (8 connections) — `internal/proxy/handlers/root/listbuckets_coverage_test.go`
- **TestRtPxListBucketsDocumentShape()** (8 connections) — `internal/proxy/handlers/root/listbuckets_coverage_test.go`
- **TestHlthHealthHealthyResponse()** (7 connections) — `internal/proxy/handlers/health/handler_coverage_test.go`
- **TestHlthHealthShutdownStateIsReEvaluatedPerRequest()** (7 connections) — `internal/proxy/handlers/health/handler_coverage_test.go`
- *... and 67 more nodes in this community*

## Relationships

- No strong cross-community connections detected

## Source Files

- `internal/proxy/handlers/bucket/acl.go`
- `internal/proxy/handlers/bucket/base.go`
- `internal/proxy/handlers/bucket/cors.go`
- `internal/proxy/handlers/bucket/handler.go`
- `internal/proxy/handlers/bucket/location.go`
- `internal/proxy/handlers/bucket/logging.go`
- `internal/proxy/handlers/bucket/policy.go`
- `internal/proxy/handlers/bucket/test_helpers_test.go`
- `internal/proxy/handlers/health/handler.go`
- `internal/proxy/handlers/health/handler_coverage_test.go`
- `internal/proxy/handlers/multipart/handler.go`
- `internal/proxy/handlers/multipart/multipart_test.go`
- `internal/proxy/handlers/object/handler.go`
- `internal/proxy/handlers/object/metadata.go`
- `internal/proxy/handlers/root/handler.go`
- `internal/proxy/handlers/root/handler_test.go`
- `internal/proxy/handlers/root/listbuckets_coverage_test.go`
- `internal/proxy/interfaces/s3_backend.go`
- `internal/proxy/server_test.go`

## Audit Trail

- EXTRACTED: 278 (53%)
- INFERRED: 238 (46%)
- AMBIGUOUS: 5 (1%)

---

*Part of the graphify knowledge wiki. See [[index]] to navigate.*