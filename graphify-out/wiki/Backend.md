# Backend

> 19 nodes · cohesion 0.17

## Key Concepts

- **monitoring/backend.go** (13 connections) — `internal/monitoring/backend.go`
- **.Do()** (8 connections) — `internal/monitoring/backend.go`
- **observedBody** (7 connections) — `internal/monitoring/backend.go`
- **net/http.Response** (5 connections)
- **classifyBackendFailure()** (5 connections) — `internal/monitoring/backend.go`
- **recordBackendFailure()** (5 connections) — `internal/monitoring/backend.go`
- **recordBackendResponse()** (5 connections) — `internal/monitoring/backend.go`
- **observeRequestBody()** (4 connections) — `internal/monitoring/backend.go`
- **BackendHTTPClient** (3 connections) — `internal/monitoring/backend.go`
- **MonstubBackend** (3 connections) — `internal/monitoring/backend_test.go`
- **.Do()** (3 connections) — `internal/monitoring/backend_test.go`
- **observedBackendClient** (3 connections) — `internal/monitoring/backend.go`
- **isConnectFailure()** (2 connections) — `internal/monitoring/backend.go`
- **isTimeoutFailure()** (2 connections) — `internal/monitoring/backend.go`
- **isTLSFailure()** (2 connections) — `internal/monitoring/backend.go`
- **.failed()** (2 connections) — `internal/monitoring/backend.go`
- **sync/atomic.Pointer** (1 connections)
- **.Close()** (1 connections) — `internal/monitoring/backend.go`
- **.Read()** (1 connections) — `internal/monitoring/backend.go`

## Relationships

- [Backend Call Observation](Backend_Call_Observation.md) (7 shared connections)
- [Replication and ACL Handlers](Replication_and_ACL_Handlers.md) (4 shared connections)
- [Monitoring Status Endpoint](Monitoring_Status_Endpoint.md) (2 shared connections)
- [S3 Signing Helper](S3_Signing_Helper.md) (2 shared connections)
- [Authentication Integration Tests](Authentication_Integration_Tests.md) (1 shared connections)
- [Segmented Manager Streaming IO](Segmented_Manager_Streaming_IO.md) (1 shared connections)

## Source Files

- `internal/monitoring/backend.go`
- `internal/monitoring/backend_test.go`

## Audit Trail

- EXTRACTED: 43 (93%)
- INFERRED: 3 (7%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*