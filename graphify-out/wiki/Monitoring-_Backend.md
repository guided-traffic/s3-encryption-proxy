# Monitoring: Backend

> 24 nodes · cohesion 0.11

## Key Concepts

- **.Do()** (8 connections) — `internal/monitoring/backend.go`
- **observedBody** (7 connections) — `internal/monitoring/backend.go`
- **net/http.Response** (6 connections)
- **classifyBackendFailure()** (6 connections) — `internal/monitoring/backend.go`
- **recordBackendFailure()** (6 connections) — `internal/monitoring/backend.go`
- **TestMonBackendVerdictFollowsTheNewerEvent()** (6 connections) — `internal/monitoring/backend_test.go`
- **.Do()** (6 connections) — `internal/monitoring/backend.go`
- **recordBackendResponse()** (5 connections) — `internal/monitoring/backend.go`
- **Backend Transport Observer (five failure classes)** (4 connections) — `docs/tickets/039-backend-certificate-verification-failure-is-named.md`
- **observeRequestBody()** (4 connections) — `internal/monitoring/backend.go`
- **BackendHTTPClient** (4 connections) — `internal/monitoring/backend.go`
- **.Do()** (4 connections) — `internal/monitoring/backend_test.go`
- **.Do()** (4 connections) — `internal/monitoring/backend_test.go`
- **Split tls into tls_certificate and tls Failure Classes** (3 connections) — `docs/tickets/039-backend-certificate-verification-failure-is-named.md`
- **isTLSFailure()** (3 connections) — `internal/monitoring/backend.go`
- **MonstubBackend** (3 connections) — `internal/monitoring/backend_test.go`
- **observedBackendClient** (3 connections) — `internal/monitoring/backend.go`
- **isConnectFailure()** (2 connections) — `internal/monitoring/backend.go`
- **isTimeoutFailure()** (2 connections) — `internal/monitoring/backend.go`
- **MonreadingBackend** (2 connections) — `internal/monitoring/backend_test.go`
- **sync/atomic.Pointer** (1 connections)
- **.Close()** (1 connections) — `internal/monitoring/backend.go`
- **.failed()** (1 connections) — `internal/monitoring/backend.go`
- **.Read()** (1 connections) — `internal/monitoring/backend.go`

## Relationships

- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (13 shared connections)
- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (6 shared connections)
- [Monitoring: Backend Test](Monitoring-_Backend_Test.md) (3 shared connections)
- [Shutdown and Test Contexts](Shutdown_and_Test_Contexts.md) (2 shared connections)
- [Server and Listings](Server_and_Listings.md) (2 shared connections)
- [Monitoring and Licence Removal](Monitoring_and_Licence_Removal.md) (1 shared connections)
- [SigV4 Authentication Rules](SigV4_Authentication_Rules.md) (1 shared connections)
- [Monitoring: Status](Monitoring-_Status.md) (1 shared connections)
- [Dataencryption: Segmented Gcm Range](Dataencryption-_Segmented_Gcm_Range.md) (1 shared connections)

## Source Files

- `docs/tickets/039-backend-certificate-verification-failure-is-named.md`
- `internal/monitoring/backend.go`
- `internal/monitoring/backend_test.go`

## Audit Trail

- EXTRACTED: 54 (89%)
- INFERRED: 7 (11%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*