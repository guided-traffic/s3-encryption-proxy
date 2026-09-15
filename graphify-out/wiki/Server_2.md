# Server

> 6 nodes · cohesion 0.33

## Key Concepts

- **RtPxfailingListener** (6 connections) — `internal/proxy/server_coverage_test.go`
- **sync.Once** (2 connections)
- **.Accept()** (2 connections) — `internal/proxy/server_coverage_test.go`
- **.Addr()** (2 connections) — `internal/proxy/server_coverage_test.go`
- **net.Addr** (1 connections)
- **.Close()** (1 connections) — `internal/proxy/server_coverage_test.go`

## Relationships

- [Proxy Server Lifecycle Tests](Proxy_Server_Lifecycle_Tests.md) (2 shared connections)
- [Types](Types.md) (1 shared connections)
- [HTTP Middleware Coverage Tests](HTTP_Middleware_Coverage_Tests.md) (1 shared connections)

## Source Files

- `internal/proxy/server_coverage_test.go`

## Audit Trail

- EXTRACTED: 9 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*