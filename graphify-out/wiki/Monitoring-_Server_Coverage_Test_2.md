# Monitoring: Server Coverage Test (2)

> 5 nodes · cohesion 0.40

## Key Concepts

- **MonfailingWriter** (5 connections) — `internal/monitoring/server_coverage_test.go`
- **TestMonServerEndpointsSurviveWriteFailures()** (4 connections) — `internal/monitoring/server_coverage_test.go`
- **.Header()** (3 connections) — `internal/monitoring/server_coverage_test.go`
- **.Write()** (1 connections) — `internal/monitoring/server_coverage_test.go`
- **.WriteHeader()** (1 connections) — `internal/monitoring/server_coverage_test.go`

## Relationships

- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (2 shared connections)
- [Request Middleware Plumbing](Request_Middleware_Plumbing.md) (2 shared connections)
- [Shutdown and Test Contexts](Shutdown_and_Test_Contexts.md) (1 shared connections)
- [Monitoring: Server Coverage Test](Monitoring-_Server_Coverage_Test.md) (1 shared connections)

## Source Files

- `internal/monitoring/server_coverage_test.go`

## Audit Trail

- EXTRACTED: 8 (80%)
- INFERRED: 2 (20%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*