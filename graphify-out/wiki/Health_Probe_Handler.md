# Health Probe Handler

> 22 nodes · cohesion 0.20

## Key Concepts

- **handler_coverage_test.go** (16 connections) — `internal/proxy/handlers/health/handler_coverage_test.go`
- **NewHandler()** (15 connections) — `internal/proxy/handlers/health/handler.go`
- **HlthnewTestLogger()** (14 connections) — `internal/proxy/handlers/health/handler_coverage_test.go`
- **HlthfailingWriter** (6 connections) — `internal/proxy/handlers/health/handler_coverage_test.go`
- **TestHlthLiveIsConstantEvenWhileDraining()** (5 connections) — `internal/proxy/handlers/health/handler_coverage_test.go`
- **TestHlthReadyReportsTheDrain()** (5 connections) — `internal/proxy/handlers/health/handler_coverage_test.go`
- **TestHlthResponseWriteFailureIsLogged()** (5 connections) — `internal/proxy/handlers/health/handler_coverage_test.go`
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
- **health/handler.go** (2 connections) — `internal/proxy/handlers/health/handler.go`
- **.Write()** (1 connections) — `internal/proxy/handlers/health/handler_coverage_test.go`
- **.WriteHeader()** (1 connections) — `internal/proxy/handlers/health/handler_coverage_test.go`
- **.Write()** (1 connections) — `internal/proxy/handlers/health/handler_coverage_test.go`

## Relationships

- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (11 shared connections)
- [Integration Failing Writer Fixtures](Integration_Failing_Writer_Fixtures.md) (2 shared connections)
- [Health Probes and Request Tracker](Health_Probes_and_Request_Tracker.md) (2 shared connections)
- [Multipart Handler Wiring](Multipart_Handler_Wiring.md) (2 shared connections)
- [Object Dispatch Coverage Tests](Object_Dispatch_Coverage_Tests.md) (1 shared connections)
- [Bucket ACL and Accelerate Handlers](Bucket_ACL_and_Accelerate_Handlers.md) (1 shared connections)
- [Object GET Coverage Tests](Object_GET_Coverage_Tests.md) (1 shared connections)
- [Router](Router.md) (1 shared connections)

## Source Files

- `internal/proxy/handlers/health/handler.go`
- `internal/proxy/handlers/health/handler_coverage_test.go`

## Audit Trail

- EXTRACTED: 56 (84%)
- INFERRED: 11 (16%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*