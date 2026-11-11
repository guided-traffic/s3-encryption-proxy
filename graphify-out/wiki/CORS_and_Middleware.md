# CORS and Middleware

> 35 nodes · cohesion 0.08

## Key Concepts

- **net/http.Handler** (15 connections)
- **MwtestLogger()** (7 connections) — `internal/proxy/middleware/http_middleware_coverage_test.go`
- **NewCORS()** (6 connections) — `internal/proxy/middleware/cors.go`
- **NewLogger()** (6 connections) — `internal/proxy/middleware/logging.go`
- **EnsureRequestID()** (6 connections) — `internal/proxy/middleware/requestid.go`
- **RequestID()** (6 connections) — `internal/proxy/middleware/requestid.go`
- **RequestIDMiddleware()** (6 connections) — `internal/proxy/middleware/requestid.go`
- **RequestTracker** (6 connections) — `internal/proxy/middleware/tracking.go`
- **.methodNotAllowedHandler()** (6 connections) — `internal/proxy/router.go`
- **CORS** (5 connections) — `internal/proxy/middleware/cors.go`
- **MwechoHandler()** (5 connections) — `internal/proxy/middleware/http_middleware_coverage_test.go`
- **TestMwCORSMiddleware()** (5 connections) — `internal/proxy/middleware/http_middleware_coverage_test.go`
- **TestMwLoggerMiddleware()** (5 connections) — `internal/proxy/middleware/http_middleware_coverage_test.go`
- **TestMwRequestTracker()** (5 connections) — `internal/proxy/middleware/http_middleware_coverage_test.go`
- **Logger** (5 connections) — `internal/proxy/middleware/logging.go`
- **TestMwEnsureRequestIDDoesNotRestateAnExistingID()** (5 connections) — `internal/proxy/middleware/requestid_test.go`
- **NewRequestTracker()** (5 connections) — `internal/proxy/middleware/tracking.go`
- **TestMwLoggerDefaultsToOKWithoutExplicitWriteHeader()** (4 connections) — `internal/proxy/middleware/http_middleware_coverage_test.go`
- **TestMwRequestIDIsStatedAndReachesTheHandler()** (4 connections) — `internal/proxy/middleware/requestid_test.go`
- **allowedMethods()** (4 connections) — `internal/proxy/router.go`
- **.setupMiddleware()** (4 connections) — `internal/proxy/middleware_setup.go`
- **SSECustomerHeader()** (3 connections) — `internal/proxy/handlers/object/storage_headers.go`
- **NewRequestID()** (3 connections) — `internal/proxy/middleware/requestid.go`
- **TestMwRequestIDIsEmptyOutsideTheMiddleware()** (3 connections) — `internal/proxy/middleware/requestid_test.go`
- **TestMwRequestIDIsUniquePerRequest()** (3 connections) — `internal/proxy/middleware/requestid_test.go`
- *... and 10 more nodes in this community*

## Relationships

- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (22 shared connections)
- [Shutdown and Test Contexts](Shutdown_and_Test_Contexts.md) (11 shared connections)
- [Multipart Handlers and Manager](Multipart_Handlers_and_Manager.md) (7 shared connections)
- [Sub-Resource Handler Tests](Sub-Resource_Handler_Tests.md) (4 shared connections)
- [Server and Listings](Server_and_Listings.md) (3 shared connections)
- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (3 shared connections)
- [Router and Middleware Setup](Router_and_Middleware_Setup.md) (2 shared connections)
- [Monitoring: Metrics Coverage Test](Monitoring-_Metrics_Coverage_Test.md) (1 shared connections)
- [Request Middleware Plumbing](Request_Middleware_Plumbing.md) (1 shared connections)
- [Object Checksum and Tagging Tests](Object_Checksum_and_Tagging_Tests.md) (1 shared connections)
- [Tampering Harness](Tampering_Harness.md) (1 shared connections)

## Source Files

- `internal/proxy/handlers/object/storage_headers.go`
- `internal/proxy/middleware/cors.go`
- `internal/proxy/middleware/http_middleware_coverage_test.go`
- `internal/proxy/middleware/logging.go`
- `internal/proxy/middleware/requestid.go`
- `internal/proxy/middleware/requestid_test.go`
- `internal/proxy/middleware/tracking.go`
- `internal/proxy/middleware_setup.go`
- `internal/proxy/router.go`

## Audit Trail

- EXTRACTED: 91 (88%)
- INFERRED: 12 (12%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*