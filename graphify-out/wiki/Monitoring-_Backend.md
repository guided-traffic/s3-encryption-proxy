# Monitoring: Backend

> 15 nodes · cohesion 0.18

## Key Concepts

- **.Do()** (8 connections) — `internal/monitoring/backend.go`
- **observedBody** (7 connections) — `internal/monitoring/backend.go`
- **net/http.Response** (6 connections)
- **.Do()** (6 connections) — `internal/monitoring/backend.go`
- **observeRequestBody()** (4 connections) — `internal/monitoring/backend.go`
- **BackendHTTPClient** (4 connections) — `internal/monitoring/backend.go`
- **.Do()** (4 connections) — `internal/monitoring/backend_test.go`
- **.Do()** (4 connections) — `internal/monitoring/backend_test.go`
- **MonstubBackend** (3 connections) — `internal/monitoring/backend_test.go`
- **observedBackendClient** (3 connections) — `internal/monitoring/backend.go`
- **MonreadingBackend** (2 connections) — `internal/monitoring/backend_test.go`
- **sync/atomic.Pointer** (1 connections)
- **.Close()** (1 connections) — `internal/monitoring/backend.go`
- **.failed()** (1 connections) — `internal/monitoring/backend.go`
- **.Read()** (1 connections) — `internal/monitoring/backend.go`

## Relationships

- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (5 shared connections)
- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (4 shared connections)
- [Monitoring: Backend Test](Monitoring-_Backend_Test.md) (3 shared connections)
- [Monitoring: Backend (2)](Monitoring-_Backend_2.md) (2 shared connections)
- [Shutdown and Test Contexts](Shutdown_and_Test_Contexts.md) (1 shared connections)
- [Monitoring: Status](Monitoring-_Status.md) (1 shared connections)
- [Keygen and Encrypt Readers](Keygen_and_Encrypt_Readers.md) (1 shared connections)

## Source Files

- `internal/monitoring/backend.go`
- `internal/monitoring/backend_test.go`

## Audit Trail

- EXTRACTED: 33 (92%)
- INFERRED: 3 (8%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*