# Monitoring: Status

> 13 nodes · cohesion 0.22

## Key Concepts

- **status.go** (16 connections) — `internal/monitoring/status.go`
- **TestMonStatusCarriesBuildAndActiveProvider()** (7 connections) — `internal/monitoring/status_test.go`
- **TestMonStatusEndpointRendersTheObservedBackend()** (7 connections) — `internal/monitoring/status_test.go`
- **recordBackendResponse()** (5 connections) — `internal/monitoring/backend.go`
- **StatusSnapshot()** (5 connections) — `internal/monitoring/status.go`
- **MonresetStatusState()** (5 connections) — `internal/monitoring/status_test.go`
- **TestMonStatusBeforeAnythingHappened()** (5 connections) — `internal/monitoring/status_test.go`
- **StatusDocument** (5 connections) — `internal/monitoring/status.go`
- **SetActiveProvider()** (4 connections) — `internal/monitoring/status.go`
- **BackendStatus** (3 connections) — `internal/monitoring/backend.go`
- **setStatusBuild()** (2 connections) — `internal/monitoring/status.go`
- **BuildStatus** (2 connections) — `internal/monitoring/status.go`
- **EncryptionStatus** (2 connections) — `internal/monitoring/status.go`

## Relationships

- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (13 shared connections)
- [Monitoring: Backend Test](Monitoring-_Backend_Test.md) (5 shared connections)
- [Monitoring: Server Coverage Test](Monitoring-_Server_Coverage_Test.md) (5 shared connections)
- [Shutdown and Test Contexts](Shutdown_and_Test_Contexts.md) (4 shared connections)
- [Monitoring and Licence Removal](Monitoring_and_Licence_Removal.md) (2 shared connections)
- [Monitoring: Backend](Monitoring-_Backend.md) (1 shared connections)
- [Server and Listings](Server_and_Listings.md) (1 shared connections)
- [Orchestration: Providers](Orchestration-_Providers.md) (1 shared connections)
- [Backend TLS Trust](Backend_TLS_Trust.md) (1 shared connections)
- [Monitoring: Metrics Coverage Test](Monitoring-_Metrics_Coverage_Test.md) (1 shared connections)

## Source Files

- `internal/monitoring/backend.go`
- `internal/monitoring/status.go`
- `internal/monitoring/status_test.go`

## Audit Trail

- EXTRACTED: 39 (76%)
- INFERRED: 12 (24%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*