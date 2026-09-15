# Monitoring Status Endpoint

> 20 nodes · cohesion 0.19

## Key Concepts

- **SetLicenseInfo()** (8 connections) — `internal/monitoring/metrics.go`
- **status.go** (8 connections) — `internal/monitoring/status.go`
- **StatusSnapshot()** (7 connections) — `internal/monitoring/status.go`
- **status_test.go** (7 connections) — `internal/monitoring/status_test.go`
- **MonresetStatusState()** (7 connections) — `internal/monitoring/status_test.go`
- **TestMonStatusCarriesBuildAndActiveProvider()** (7 connections) — `internal/monitoring/status_test.go`
- **TestMonStatusEndpointRendersTheObservedBackend()** (7 connections) — `internal/monitoring/status_test.go`
- **MonstatusBody()** (6 connections) — `internal/monitoring/status_test.go`
- **StatusDocument** (6 connections) — `internal/monitoring/status.go`
- **TestMonStatusBeforeAnythingHappened()** (5 connections) — `internal/monitoring/status_test.go`
- **TestMonStatusExpiredLicenseRemainsAtZero()** (5 connections) — `internal/monitoring/status_test.go`
- **TestMonStatusLicenseRemainingIsComputedAtReadTime()** (5 connections) — `internal/monitoring/status_test.go`
- **TestMonSetLicenseInfo()** (4 connections) — `internal/monitoring/metrics_coverage_test.go`
- **SetActiveProvider()** (4 connections) — `internal/monitoring/status.go`
- **BackendStatus** (3 connections) — `internal/monitoring/backend.go`
- **setStatusBuild()** (2 connections) — `internal/monitoring/status.go`
- **setStatusLicense()** (2 connections) — `internal/monitoring/status.go`
- **BuildStatus** (2 connections) — `internal/monitoring/status.go`
- **EncryptionStatus** (2 connections) — `internal/monitoring/status.go`
- **LicenseStatus** (2 connections) — `internal/monitoring/status.go`

## Relationships

- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (9 shared connections)
- [Backend Call Observation](Backend_Call_Observation.md) (6 shared connections)
- [Monitoring HTTP Server](Monitoring_HTTP_Server.md) (5 shared connections)
- [Metrics](Metrics.md) (3 shared connections)
- [Backend](Backend.md) (2 shared connections)
- [Main](Main.md) (1 shared connections)
- [Proxy Server Lifecycle Tests](Proxy_Server_Lifecycle_Tests.md) (1 shared connections)

## Source Files

- `internal/monitoring/backend.go`
- `internal/monitoring/metrics.go`
- `internal/monitoring/metrics_coverage_test.go`
- `internal/monitoring/status.go`
- `internal/monitoring/status_test.go`

## Audit Trail

- EXTRACTED: 42 (67%)
- INFERRED: 21 (33%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*