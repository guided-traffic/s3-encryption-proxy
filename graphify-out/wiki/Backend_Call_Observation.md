# Backend Call Observation

> 21 nodes · cohesion 0.38

## Key Concepts

- **backend_test.go** (18 connections) — `internal/monitoring/backend_test.go`
- **MonresetBackendObservation()** (16 connections) — `internal/monitoring/backend_test.go`
- **MondefaultMetric()** (16 connections) — `internal/monitoring/metrics_coverage_test.go`
- **ObserveBackendClient()** (13 connections) — `internal/monitoring/backend.go`
- **.Do()** (13 connections) — `internal/monitoring/backend_test.go`
- **MonbackendRequest()** (12 connections) — `internal/monitoring/backend_test.go`
- **backendSnapshot()** (11 connections) — `internal/monitoring/backend.go`
- **MoncounterValue()** (8 connections) — `internal/monitoring/backend_test.go`
- **TestMonBackendClassifiesFailures()** (8 connections) — `internal/monitoring/backend_test.go`
- **TestMonBackendObservationIsRaceFree()** (8 connections) — `internal/monitoring/backend_test.go`
- **TestMonBackendOwnBodyFailureIsNotTheBackends()** (8 connections) — `internal/monitoring/backend_test.go`
- **TestMonBackendRecordsAFailureAsFailing()** (8 connections) — `internal/monitoring/backend_test.go`
- **TestMonBackendRecordsAnyResponseAsReachability()** (8 connections) — `internal/monitoring/backend_test.go`
- **TestMonBackendRecordsNothingForOurOwnCancellation()** (8 connections) — `internal/monitoring/backend_test.go`
- **TestMonBackendTransportFailureWithAHealthyBodyIsRecorded()** (8 connections) — `internal/monitoring/backend_test.go`
- **TestMonBackendCancelledRequestIsNeitherCountedNorLogged()** (7 connections) — `internal/monitoring/backend_test.go`
- **TestMonBackendFailureIsCountedAndLogged()** (7 connections) — `internal/monitoring/backend_test.go`
- **TestMonBackendResponseIsCounted()** (7 connections) — `internal/monitoring/backend_test.go`
- **TestMonBackendVerdictFollowsTheNewerEvent()** (6 connections) — `internal/monitoring/backend_test.go`
- **TestMonBackendUnobservedSaysSoRatherThanOK()** (5 connections) — `internal/monitoring/backend_test.go`
- **MonreadingBackend** (2 connections) — `internal/monitoring/backend_test.go`

## Relationships

- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (15 shared connections)
- [Backend](Backend.md) (8 shared connections)
- [Monitoring Status Endpoint](Monitoring_Status_Endpoint.md) (6 shared connections)
- [Metrics](Metrics.md) (5 shared connections)
- [Replication and ACL Handlers](Replication_and_ACL_Handlers.md) (2 shared connections)
- [Backend Client](Backend_Client.md) (1 shared connections)
- [Monitoring HTTP Server](Monitoring_HTTP_Server.md) (1 shared connections)
- [Monitoring Middleware Tests](Monitoring_Middleware_Tests.md) (1 shared connections)

## Source Files

- `internal/monitoring/backend.go`
- `internal/monitoring/backend_test.go`
- `internal/monitoring/metrics_coverage_test.go`

## Audit Trail

- EXTRACTED: 84 (71%)
- INFERRED: 34 (29%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*