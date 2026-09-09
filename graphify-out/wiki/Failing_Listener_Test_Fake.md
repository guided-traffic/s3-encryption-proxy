# Failing Listener Test Fake

> 5 nodes · cohesion 0.40

## Key Concepts

- **RtPxfailingListener** (6 connections) — `internal/proxy/server_coverage_test.go`
- **.Accept()** (2 connections) — `internal/proxy/server_coverage_test.go`
- **.Addr()** (2 connections) — `internal/proxy/server_coverage_test.go`
- **net.Addr** (1 connections)
- **.Close()** (1 connections) — `internal/proxy/server_coverage_test.go`

## Relationships

- [Proxy Server Construction Tests](Proxy_Server_Construction_Tests.md) (2 shared connections)
- [License Claims Validation](License_Claims_Validation.md) (1 shared connections)
- [Monitoring Middleware Tests](Monitoring_Middleware_Tests.md) (1 shared connections)

## Source Files

- `internal/proxy/server_coverage_test.go`

## Audit Trail

- EXTRACTED: 8 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*