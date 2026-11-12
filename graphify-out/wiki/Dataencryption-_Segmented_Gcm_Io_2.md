# Dataencryption: Segmented Gcm Io (2)

> 10 nodes · cohesion 0.31

## Key Concepts

- **MwtestLogger()** (7 connections) — `internal/proxy/middleware/http_middleware_coverage_test.go`
- **NewCORS()** (6 connections) — `internal/proxy/middleware/cors.go`
- **NewLogger()** (6 connections) — `internal/proxy/middleware/logging.go`
- **MwechoHandler()** (5 connections) — `internal/proxy/middleware/http_middleware_coverage_test.go`
- **TestMwCORSMiddleware()** (5 connections) — `internal/proxy/middleware/http_middleware_coverage_test.go`
- **TestMwLoggerMiddleware()** (5 connections) — `internal/proxy/middleware/http_middleware_coverage_test.go`
- **TestMwRequestTracker()** (5 connections) — `internal/proxy/middleware/http_middleware_coverage_test.go`
- **NewRequestTracker()** (5 connections) — `internal/proxy/middleware/tracking.go`
- **TestMwLoggerDefaultsToOKWithoutExplicitWriteHeader()** (4 connections) — `internal/proxy/middleware/http_middleware_coverage_test.go`
- **.setupMiddleware()** (4 connections) — `internal/proxy/middleware_setup.go`

## Relationships

- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (9 shared connections)
- [Shutdown and Test Contexts](Shutdown_and_Test_Contexts.md) (5 shared connections)
- [Multipart Handlers and Manager](Multipart_Handlers_and_Manager.md) (4 shared connections)
- [CORS and Middleware](CORS_and_Middleware.md) (3 shared connections)
- [Method Not Allowed Handler](Method_Not_Allowed_Handler.md) (1 shared connections)
- [Response: Error Mapping Coverage Test](Response-_Error_Mapping_Coverage_Test.md) (1 shared connections)
- [Adr: 0027 Conformance Is Asserted Against A Backend That Is Not Minio](Adr-_0027_Conformance_Is_Asserted_Against_A_Backend_That_Is_Not_Minio.md) (1 shared connections)

## Source Files

- `internal/proxy/middleware/cors.go`
- `internal/proxy/middleware/http_middleware_coverage_test.go`
- `internal/proxy/middleware/logging.go`
- `internal/proxy/middleware/tracking.go`
- `internal/proxy/middleware_setup.go`

## Audit Trail

- EXTRACTED: 34 (89%)
- INFERRED: 4 (11%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*