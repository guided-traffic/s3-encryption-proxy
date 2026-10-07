# Backend Call Observation

> 20 nodes · cohesion 0.38

## Key Concepts

- **backend_test.go** (18 connections) — `internal/monitoring/backend_test.go`
- **MonresetBackendObservation()** (16 connections) — `internal/monitoring/backend_test.go`
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

- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (14 shared connections)
- [Metrics](Metrics.md) (7 shared connections)
- [Backend](Backend.md) (5 shared connections)
- [Monitoring Status Endpoint](Monitoring_Status_Endpoint.md) (4 shared connections)
- [Monitoring Backend Stub](Monitoring_Backend_Stub.md) (2 shared connections)
- [Bucket ACL and Accelerate Handlers](Bucket_ACL_and_Accelerate_Handlers.md) (2 shared connections)
- [Backend Client](Backend_Client.md) (1 shared connections)
- [Monitoring Failing Body Stub](Monitoring_Failing_Body_Stub.md) (1 shared connections)
- [Monitoring HTTP Server](Monitoring_HTTP_Server.md) (1 shared connections)

## Source Files

- `internal/monitoring/backend.go`
- `internal/monitoring/backend_test.go`

## Audit Trail

- EXTRACTED: 78 (72%)
- INFERRED: 31 (28%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*