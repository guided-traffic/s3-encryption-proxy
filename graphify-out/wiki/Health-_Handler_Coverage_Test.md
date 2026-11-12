# Health: Handler Coverage Test

> 21 nodes · cohesion 0.20

## Key Concepts

- **handler_coverage_test.go** (27 connections) — `internal/proxy/handlers/health/handler_coverage_test.go`
- **NewHandler()** (15 connections) — `internal/proxy/handlers/health/handler.go`
- **HlthnewTestLogger()** (14 connections) — `internal/proxy/handlers/health/handler_coverage_test.go`
- **HlthfailingWriter** (6 connections) — `internal/proxy/handlers/health/handler_coverage_test.go`
- **TestHlthResponseWriteFailureIsLogged()** (5 connections) — `internal/proxy/handlers/health/handler_coverage_test.go`
- **TestHlthLiveIsConstantEvenWhileDraining()** (4 connections) — `internal/proxy/handlers/health/handler_coverage_test.go`
- **TestHlthLogHealthRequests()** (4 connections) — `internal/proxy/handlers/health/handler_coverage_test.go`
- **TestHlthNewHandler()** (4 connections) — `internal/proxy/handlers/health/handler_coverage_test.go`
- **TestHlthReadyReportsTheDrain()** (4 connections) — `internal/proxy/handlers/health/handler_coverage_test.go`
- **TestHlthReadyShutdownStateIsReEvaluatedPerRequest()** (4 connections) — `internal/proxy/handlers/health/handler_coverage_test.go`
- **TestHlthRequestTrackerInvocation()** (4 connections) — `internal/proxy/handlers/health/handler_coverage_test.go`
- **TestHlthRequestTrackerIsBalancedAcrossRequests()** (4 connections) — `internal/proxy/handlers/health/handler_coverage_test.go`
- **TestHlthRequestTrackerPartiallyConfigured()** (4 connections) — `internal/proxy/handlers/health/handler_coverage_test.go`
- **TestHlthSetRequestTracker()** (4 connections) — `internal/proxy/handlers/health/handler_coverage_test.go`
- **TestHlthSetShutdownStateHandler()** (4 connections) — `internal/proxy/handlers/health/handler_coverage_test.go`
- **HlthrecordingWriter** (3 connections) — `internal/proxy/handlers/health/handler_coverage_test.go`
- **HlthnewFailingWriter()** (3 connections) — `internal/proxy/handlers/health/handler_coverage_test.go`
- **.Header()** (2 connections) — `internal/proxy/handlers/health/handler_coverage_test.go`
- **.Write()** (1 connections) — `internal/proxy/handlers/health/handler_coverage_test.go`
- **.WriteHeader()** (1 connections) — `internal/proxy/handlers/health/handler_coverage_test.go`
- **.Write()** (1 connections) — `internal/proxy/handlers/health/handler_coverage_test.go`

## Relationships

- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (12 shared connections)
- [Shutdown and Test Contexts](Shutdown_and_Test_Contexts.md) (11 shared connections)
- [Multipart Handlers and Manager](Multipart_Handlers_and_Manager.md) (3 shared connections)
- [Request Middleware Plumbing](Request_Middleware_Plumbing.md) (2 shared connections)
- [Misc (19)](Misc_19.md) (1 shared connections)
- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (1 shared connections)
- [Response: Error Mapping Coverage Test](Response-_Error_Mapping_Coverage_Test.md) (1 shared connections)
- [Server and Listings](Server_and_Listings.md) (1 shared connections)

## Source Files

- `internal/proxy/handlers/health/handler.go`
- `internal/proxy/handlers/health/handler_coverage_test.go`

## Audit Trail

- EXTRACTED: 64 (85%)
- INFERRED: 11 (15%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*