# Monitoring: Backend Test

> 17 nodes · cohesion 0.37

## Key Concepts

- **MonresetBackendObservation()** (16 connections) — `internal/monitoring/backend_test.go`
- **MondefaultMetric()** (15 connections) — `internal/monitoring/metrics_coverage_test.go`
- **ObserveBackendClient()** (13 connections) — `internal/monitoring/backend.go`
- **MonbackendRequest()** (12 connections) — `internal/monitoring/backend_test.go`
- **backendSnapshot()** (11 connections) — `internal/monitoring/backend.go`
- **MoncounterValue()** (8 connections) — `internal/monitoring/backend_test.go`
- **TestMonBackendClassifiesFailures()** (7 connections) — `internal/monitoring/backend_test.go`
- **TestMonBackendObservationIsRaceFree()** (7 connections) — `internal/monitoring/backend_test.go`
- **TestMonBackendOwnBodyFailureIsNotTheBackends()** (7 connections) — `internal/monitoring/backend_test.go`
- **TestMonBackendRecordsAFailureAsFailing()** (7 connections) — `internal/monitoring/backend_test.go`
- **TestMonBackendRecordsAnyResponseAsReachability()** (7 connections) — `internal/monitoring/backend_test.go`
- **TestMonBackendRecordsNothingForOurOwnCancellation()** (7 connections) — `internal/monitoring/backend_test.go`
- **TestMonBackendTransportFailureWithAHealthyBodyIsRecorded()** (7 connections) — `internal/monitoring/backend_test.go`
- **TestMonBackendCancelledRequestIsNeitherCountedNorLogged()** (6 connections) — `internal/monitoring/backend_test.go`
- **TestMonBackendFailureIsCountedAndLogged()** (6 connections) — `internal/monitoring/backend_test.go`
- **TestMonBackendResponseIsCounted()** (6 connections) — `internal/monitoring/backend_test.go`
- **TestMonBackendUnobservedSaysSoRatherThanOK()** (5 connections) — `internal/monitoring/backend_test.go`

## Relationships

- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (17 shared connections)
- [Shutdown and Test Contexts](Shutdown_and_Test_Contexts.md) (14 shared connections)
- [Monitoring: Status](Monitoring-_Status.md) (5 shared connections)
- [Monitoring: Metrics Coverage Test](Monitoring-_Metrics_Coverage_Test.md) (4 shared connections)
- [Monitoring: Backend](Monitoring-_Backend.md) (3 shared connections)
- [Monitoring: Server Coverage Test](Monitoring-_Server_Coverage_Test.md) (2 shared connections)
- [Config Types and Monitoring Plan](Config_Types_and_Monitoring_Plan.md) (1 shared connections)
- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (1 shared connections)

## Source Files

- `internal/monitoring/backend.go`
- `internal/monitoring/backend_test.go`
- `internal/monitoring/metrics_coverage_test.go`

## Audit Trail

- EXTRACTED: 65 (67%)
- INFERRED: 32 (33%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*