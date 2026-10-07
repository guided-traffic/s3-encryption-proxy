# Monitoring HTTP Server

> 5 nodes · cohesion 0.60

## Key Concepts

- **NewServer()** (8 connections) — `internal/monitoring/server.go`
- **Server** (5 connections) — `internal/monitoring/server.go`
- **monitoring/server.go** (4 connections) — `internal/monitoring/server.go`
- **Config** (2 connections) — `internal/monitoring/server.go`
- **.Start()** (2 connections) — `internal/monitoring/server.go`

## Relationships

- [Monitoring Status Endpoint](Monitoring_Status_Endpoint.md) (2 shared connections)
- [ADR Web: Auth, Checksums, Config](ADR_Web-_Auth,_Checksums,_Config.md) (1 shared connections)
- [Main](Main.md) (1 shared connections)
- [Backend Call Observation](Backend_Call_Observation.md) (1 shared connections)
- [Metrics](Metrics.md) (1 shared connections)
- [Pprof](Pprof.md) (1 shared connections)
- [Multipart Handler Wiring](Multipart_Handler_Wiring.md) (1 shared connections)
- [MockS3Backend Tagging and Policy](MockS3Backend_Tagging_and_Policy.md) (1 shared connections)

## Source Files

- `internal/monitoring/server.go`

## Audit Trail

- EXTRACTED: 11 (73%)
- INFERRED: 4 (27%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*