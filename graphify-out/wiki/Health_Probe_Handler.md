# Health Probe Handler

> 29 nodes · cohesion 0.14

## Key Concepts

- **handler_coverage_test.go** (16 connections) — `internal/proxy/handlers/health/handler_coverage_test.go`
- **NewHandler()** (15 connections) — `internal/proxy/handlers/health/handler.go`
- **HlthnewTestLogger()** (14 connections) — `internal/proxy/handlers/health/handler_coverage_test.go`
- **Handler** (10 connections) — `internal/proxy/handlers/health/handler.go`
- **HlthfailingWriter** (6 connections) — `internal/proxy/handlers/health/handler_coverage_test.go`
- **.Live()** (5 connections) — `internal/proxy/handlers/health/handler.go`
- **.Ready()** (5 connections) — `internal/proxy/handlers/health/handler.go`
- **TestHlthLiveIsConstantEvenWhileDraining()** (5 connections) — `internal/proxy/handlers/health/handler_coverage_test.go`
- **TestHlthReadyReportsTheDrain()** (5 connections) — `internal/proxy/handlers/health/handler_coverage_test.go`
- **TestHlthResponseWriteFailureIsLogged()** (5 connections) — `internal/proxy/handlers/health/handler_coverage_test.go`
- **.track()** (4 connections) — `internal/proxy/handlers/health/handler.go`
- **.writeJSON()** (4 connections) — `internal/proxy/handlers/health/handler.go`
- **.Header()** (4 connections) — `internal/proxy/handlers/health/handler_coverage_test.go`
- **TestHlthLogHealthRequests()** (4 connections) — `internal/proxy/handlers/health/handler_coverage_test.go`
- **TestHlthNewHandler()** (4 connections) — `internal/proxy/handlers/health/handler_coverage_test.go`
- **TestHlthReadyShutdownStateIsReEvaluatedPerRequest()** (4 connections) — `internal/proxy/handlers/health/handler_coverage_test.go`
- **TestHlthRequestTrackerInvocation()** (4 connections) — `internal/proxy/handlers/health/handler_coverage_test.go`
- **TestHlthRequestTrackerIsBalancedAcrossRequests()** (4 connections) — `internal/proxy/handlers/health/handler_coverage_test.go`
- **TestHlthRequestTrackerPartiallyConfigured()** (4 connections) — `internal/proxy/handlers/health/handler_coverage_test.go`
- **TestHlthSetRequestTracker()** (4 connections) — `internal/proxy/handlers/health/handler_coverage_test.go`
- **TestHlthSetShutdownStateHandler()** (4 connections) — `internal/proxy/handlers/health/handler_coverage_test.go`
- **HlthrecordingWriter** (3 connections) — `internal/proxy/handlers/health/handler_coverage_test.go`
- **HlthnewFailingWriter()** (3 connections) — `internal/proxy/handlers/health/handler_coverage_test.go`
- **.SetShutdownStateHandler()** (2 connections) — `internal/proxy/handlers/health/handler.go`
- **health/handler.go** (2 connections) — `internal/proxy/handlers/health/handler.go`
- *... and 4 more nodes in this community*

## Relationships

- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (11 shared connections)
- [Bucket Website and Create/Delete](Bucket_Website_and_Create-Delete.md) (4 shared connections)
- [Multipart Handler Constructors](Multipart_Handler_Constructors.md) (3 shared connections)
- [Replication and ACL Handlers](Replication_and_ACL_Handlers.md) (3 shared connections)
- [S3 Signing Helper](S3_Signing_Helper.md) (2 shared connections)
- [S3 Method Error Mapping Tests](S3_Method_Error_Mapping_Tests.md) (2 shared connections)
- [DeleteObjects Handler Tests](DeleteObjects_Handler_Tests.md) (1 shared connections)
- [Object GET Coverage Tests](Object_GET_Coverage_Tests.md) (1 shared connections)
- [Router](Router.md) (1 shared connections)

## Source Files

- `internal/proxy/handlers/health/handler.go`
- `internal/proxy/handlers/health/handler_coverage_test.go`

## Audit Trail

- EXTRACTED: 75 (87%)
- INFERRED: 11 (13%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*