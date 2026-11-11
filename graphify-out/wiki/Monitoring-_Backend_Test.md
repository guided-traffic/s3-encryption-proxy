# Monitoring: Backend Test

> 18 nodes · cohesion 0.39

## Key Concepts

- **backend_test.go** (44 connections) — `internal/monitoring/backend_test.go`
- **MonresetBackendObservation()** (16 connections) — `internal/monitoring/backend_test.go`
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
- **TestMonBackendVerdictFollowsTheNewerEvent()** (6 connections) — `internal/monitoring/backend_test.go`
- **TestMonBackendUnobservedSaysSoRatherThanOK()** (5 connections) — `internal/monitoring/backend_test.go`

## Relationships

- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (28 shared connections)
- [Shutdown and Test Contexts](Shutdown_and_Test_Contexts.md) (14 shared connections)
- [Monitoring: Metrics Coverage Test](Monitoring-_Metrics_Coverage_Test.md) (7 shared connections)
- [Monitoring: Status](Monitoring-_Status.md) (5 shared connections)
- [Monitoring: Backend](Monitoring-_Backend.md) (3 shared connections)
- [Backend TLS Trust](Backend_TLS_Trust.md) (1 shared connections)
- [Monitoring: Backend Test (2)](Monitoring-_Backend_Test_2.md) (1 shared connections)
- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (1 shared connections)
- [Monitoring: Server Coverage Test](Monitoring-_Server_Coverage_Test.md) (1 shared connections)
- [Monitoring: Backend (2)](Monitoring-_Backend_2.md) (1 shared connections)

## Source Files

- `internal/monitoring/backend.go`
- `internal/monitoring/backend_test.go`

## Audit Trail

- EXTRACTED: 91 (75%)
- INFERRED: 31 (25%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*