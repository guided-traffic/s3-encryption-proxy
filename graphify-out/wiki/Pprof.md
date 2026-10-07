# Pprof

> 11 nodes · cohesion 0.25

## Key Concepts

- **NewPprofServer()** (7 connections) — `internal/monitoring/pprof.go`
- **PprofServer** (5 connections) — `internal/monitoring/pprof.go`
- **pprof_coverage_test.go** (4 connections) — `internal/monitoring/pprof_coverage_test.go`
- **TestPprofServerServesOnlyProfiling()** (4 connections) — `internal/monitoring/pprof_coverage_test.go`
- **TestPprofServerStartServesAndShutsDownOnContextCancel()** (4 connections) — `internal/monitoring/pprof_coverage_test.go`
- **net/http.Server** (3 connections)
- **pprof.go** (3 connections) — `internal/monitoring/pprof.go`
- **TestPprofNewServerConfiguration()** (3 connections) — `internal/monitoring/pprof_coverage_test.go`
- **TestPprofServerReportsItsFailures()** (3 connections) — `internal/monitoring/pprof_coverage_test.go`
- **pprof on its own loopback-only listener** (2 connections) — `docs/security/request-authentication.md`
- **.Start()** (2 connections) — `internal/monitoring/pprof.go`

## Relationships

- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (4 shared connections)
- [Monitoring Test Imports](Monitoring_Test_Imports.md) (2 shared connections)
- [ADR Web: Auth, Checksums, Config](ADR_Web-_Auth,_Checksums,_Config.md) (1 shared connections)
- [Server](Server.md) (1 shared connections)
- [Monitoring HTTP Server](Monitoring_HTTP_Server.md) (1 shared connections)
- [Main](Main.md) (1 shared connections)
- [Multipart Handler Wiring](Multipart_Handler_Wiring.md) (1 shared connections)
- [MockS3Backend Tagging and Policy](MockS3Backend_Tagging_and_Policy.md) (1 shared connections)

## Source Files

- `docs/security/request-authentication.md`
- `internal/monitoring/pprof.go`
- `internal/monitoring/pprof_coverage_test.go`

## Audit Trail

- EXTRACTED: 20 (77%)
- INFERRED: 6 (23%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*