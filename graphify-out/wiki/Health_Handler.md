# Health Handler

> 22 nodes · cohesion 0.21

## Key Concepts

- **handler_coverage_test.go** (16 connections) — `internal/proxy/handlers/health/handler_coverage_test.go`
- **NewHandler()** (16 connections) — `internal/proxy/handlers/health/handler.go`
- **HlthnewTestLogger()** (15 connections) — `internal/proxy/handlers/health/handler_coverage_test.go`
- **HlthfailingWriter** (6 connections) — `internal/proxy/handlers/health/handler_coverage_test.go`
- **.Header()** (5 connections) — `internal/proxy/handlers/health/handler_coverage_test.go`
- **TestHlthHealthHealthyResponse()** (5 connections) — `internal/proxy/handlers/health/handler_coverage_test.go`
- **TestHlthHealthShutdownStateHandlerVariants()** (5 connections) — `internal/proxy/handlers/health/handler_coverage_test.go`
- **TestHlthResponseWriteFailureIsLogged()** (5 connections) — `internal/proxy/handlers/health/handler_coverage_test.go`
- **TestHlthVersionResponse()** (5 connections) — `internal/proxy/handlers/health/handler_coverage_test.go`
- **TestHlthHealthShutdownStateIsReEvaluatedPerRequest()** (4 connections) — `internal/proxy/handlers/health/handler_coverage_test.go`
- **TestHlthLogHealthRequests()** (4 connections) — `internal/proxy/handlers/health/handler_coverage_test.go`
- **TestHlthNewHandler()** (4 connections) — `internal/proxy/handlers/health/handler_coverage_test.go`
- **TestHlthRequestTrackerInvocation()** (4 connections) — `internal/proxy/handlers/health/handler_coverage_test.go`
- **TestHlthRequestTrackerIsBalancedAcrossRequests()** (4 connections) — `internal/proxy/handlers/health/handler_coverage_test.go`
- **TestHlthRequestTrackerPartiallyConfigured()** (4 connections) — `internal/proxy/handlers/health/handler_coverage_test.go`
- **TestHlthSetRequestTracker()** (4 connections) — `internal/proxy/handlers/health/handler_coverage_test.go`
- **TestHlthSetShutdownStateHandler()** (4 connections) — `internal/proxy/handlers/health/handler_coverage_test.go`
- **HlthrecordingWriter** (3 connections) — `internal/proxy/handlers/health/handler_coverage_test.go`
- **HlthnewFailingWriter()** (3 connections) — `internal/proxy/handlers/health/handler_coverage_test.go`
- **.Write()** (1 connections) — `internal/proxy/handlers/health/handler_coverage_test.go`
- **.WriteHeader()** (1 connections) — `internal/proxy/handlers/health/handler_coverage_test.go`
- **.Write()** (1 connections) — `internal/proxy/handlers/health/handler_coverage_test.go`

## Relationships

- [Config Env Expansion](Config_Env_Expansion.md) (12 shared connections)
- [Multipart Handler](Multipart_Handler.md) (3 shared connections)
- [Object Header Conformance](Object_Header_Conformance.md) (2 shared connections)
- [SigV4 Signing Helper](SigV4_Signing_Helper.md) (2 shared connections)
- [Object Dispatch and Metadata Tests](Object_Dispatch_and_Metadata_Tests.md) (1 shared connections)
- [License Logging](License_Logging.md) (1 shared connections)

## Source Files

- `internal/proxy/handlers/health/handler.go`
- `internal/proxy/handlers/health/handler_coverage_test.go`

## Audit Trail

- EXTRACTED: 58 (83%)
- INFERRED: 12 (17%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*