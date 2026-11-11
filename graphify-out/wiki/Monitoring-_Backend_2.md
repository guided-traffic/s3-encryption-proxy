# Monitoring: Backend (2)

> 7 nodes · cohesion 0.33

## Key Concepts

- **classifyBackendFailure()** (6 connections) — `internal/monitoring/backend.go`
- **recordBackendFailure()** (6 connections) — `internal/monitoring/backend.go`
- **Backend Transport Observer (five failure classes)** (4 connections) — `docs/tickets/039-backend-certificate-verification-failure-is-named.md`
- **Split tls into tls_certificate and tls Failure Classes** (3 connections) — `docs/tickets/039-backend-certificate-verification-failure-is-named.md`
- **isTLSFailure()** (3 connections) — `internal/monitoring/backend.go`
- **isConnectFailure()** (2 connections) — `internal/monitoring/backend.go`
- **isTimeoutFailure()** (2 connections) — `internal/monitoring/backend.go`

## Relationships

- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (5 shared connections)
- [Monitoring: Backend](Monitoring-_Backend.md) (2 shared connections)
- [Monitoring and Licence Removal](Monitoring_and_Licence_Removal.md) (1 shared connections)
- [Planned Work: SSE-C and HA](Planned_Work-_SSE-C_and_HA.md) (1 shared connections)
- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (1 shared connections)
- [Server and Listings](Server_and_Listings.md) (1 shared connections)
- [Monitoring: Backend Test](Monitoring-_Backend_Test.md) (1 shared connections)

## Source Files

- `docs/tickets/039-backend-certificate-verification-failure-is-named.md`
- `internal/monitoring/backend.go`

## Audit Trail

- EXTRACTED: 18 (95%)
- INFERRED: 1 (5%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*