# Misc

> 19 nodes · cohesion 0.13

## Key Concepts

- **net.Conn** (8 connections)
- **MwHijackWriter** (6 connections) — `internal/proxy/middleware/http_middleware_coverage_test.go`
- **MonHijackWriter** (6 connections) — `internal/monitoring/middleware_coverage_test.go`
- **MonfailingListener** (5 connections) — `internal/monitoring/server_coverage_test.go`
- **bufio.ReadWriter** (4 connections)
- **.Hijack()** (3 connections) — `internal/proxy/middleware/http_middleware_coverage_test.go`
- **.Hijack()** (3 connections) — `internal/proxy/middleware/logging.go`
- **.Hijack()** (3 connections) — `internal/monitoring/middleware_coverage_test.go`
- **.Hijack()** (3 connections) — `internal/monitoring/middleware.go`
- **.Header()** (2 connections) — `internal/proxy/middleware/http_middleware_coverage_test.go`
- **.Accept()** (2 connections) — `internal/monitoring/server_coverage_test.go`
- **.Header()** (2 connections) — `internal/monitoring/middleware_coverage_test.go`
- **net.Listener** (1 connections)
- **sync/atomic.Bool** (1 connections)
- **.Write()** (1 connections) — `internal/proxy/middleware/http_middleware_coverage_test.go`
- **.WriteHeader()** (1 connections) — `internal/proxy/middleware/http_middleware_coverage_test.go`
- **.Close()** (1 connections) — `internal/monitoring/server_coverage_test.go`
- **.Write()** (1 connections) — `internal/monitoring/middleware_coverage_test.go`
- **.WriteHeader()** (1 connections) — `internal/monitoring/middleware_coverage_test.go`

## Relationships

- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (2 shared connections)
- [Request Middleware Plumbing](Request_Middleware_Plumbing.md) (2 shared connections)
- [Failing Listener Test Fixture](Failing_Listener_Test_Fixture.md) (1 shared connections)
- [Middleware: Logging](Middleware-_Logging.md) (1 shared connections)
- [Monitoring: Server Coverage Test](Monitoring-_Server_Coverage_Test.md) (1 shared connections)
- [Monitoring: Middleware](Monitoring-_Middleware.md) (1 shared connections)

## Source Files

- `internal/monitoring/middleware.go`
- `internal/monitoring/middleware_coverage_test.go`
- `internal/monitoring/server_coverage_test.go`
- `internal/proxy/middleware/http_middleware_coverage_test.go`
- `internal/proxy/middleware/logging.go`

## Audit Trail

- EXTRACTED: 31 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*