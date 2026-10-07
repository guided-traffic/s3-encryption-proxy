# Backend

> 19 nodes · cohesion 0.18

## Key Concepts

- **monitoring/backend.go** (14 connections) — `internal/monitoring/backend.go`
- **.Do()** (8 connections) — `internal/monitoring/backend.go`
- **Split transport failure class tls into tls_certificate and tls** (7 connections) — `docs/tickets/039-backend-certificate-verification-failure-is-named.md`
- **observedBody** (7 connections) — `internal/monitoring/backend.go`
- **classifyBackendFailure()** (6 connections) — `internal/monitoring/backend.go`
- **recordBackendFailure()** (6 connections) — `internal/monitoring/backend.go`
- **recordBackendResponse()** (5 connections) — `internal/monitoring/backend.go`
- **Backend observer on o.HTTPClient below the SDK (classifyBackendFailure: dns/tls/timeout/connect/other)** (4 connections) — `docs/tickets/039-backend-certificate-verification-failure-is-named.md`
- **observeRequestBody()** (4 connections) — `internal/monitoring/backend.go`
- **isTLSFailure()** (3 connections) — `internal/monitoring/backend.go`
- **BackendHTTPClient** (3 connections) — `internal/monitoring/backend.go`
- **observedBackendClient** (3 connections) — `internal/monitoring/backend.go`
- **s3ep_backend_transport_failures_total{class}** (2 connections) — `docs/tickets/039-backend-certificate-verification-failure-is-named.md`
- **isConnectFailure()** (2 connections) — `internal/monitoring/backend.go`
- **isTimeoutFailure()** (2 connections) — `internal/monitoring/backend.go`
- **.failed()** (2 connections) — `internal/monitoring/backend.go`
- **sync/atomic.Pointer** (1 connections)
- **.Close()** (1 connections) — `internal/monitoring/backend.go`
- **.Read()** (1 connections) — `internal/monitoring/backend.go`

## Relationships

- [Backend Call Observation](Backend_Call_Observation.md) (5 shared connections)
- [Bucket ACL and Accelerate Handlers](Bucket_ACL_and_Accelerate_Handlers.md) (3 shared connections)
- [ADR Web: Auth, Checksums, Config](ADR_Web-_Auth,_Checksums,_Config.md) (2 shared connections)
- [Transfer Bounds and Shutdown](Transfer_Bounds_and_Shutdown.md) (2 shared connections)
- [Monitoring Status Endpoint](Monitoring_Status_Endpoint.md) (2 shared connections)
- [Health Probes and Request Tracker](Health_Probes_and_Request_Tracker.md) (2 shared connections)
- [Multipart Part Layout Decisions](Multipart_Part_Layout_Decisions.md) (1 shared connections)
- [Monitoring Backend Stub](Monitoring_Backend_Stub.md) (1 shared connections)
- [Segmented Manager Streaming IO](Segmented_Manager_Streaming_IO.md) (1 shared connections)

## Source Files

- `docs/tickets/039-backend-certificate-verification-failure-is-named.md`
- `internal/monitoring/backend.go`

## Audit Trail

- EXTRACTED: 44 (88%)
- INFERRED: 6 (12%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*