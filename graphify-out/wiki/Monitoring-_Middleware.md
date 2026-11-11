# Monitoring: Middleware

> 5 nodes · cohesion 0.40

## Key Concepts

- **responseWriter** (7 connections) — `internal/monitoring/middleware.go`
- **.Unwrap()** (2 connections) — `internal/monitoring/middleware.go`
- **.Flush()** (1 connections) — `internal/monitoring/middleware.go`
- **.FlushError()** (1 connections) — `internal/monitoring/middleware.go`
- **.WriteHeader()** (1 connections) — `internal/monitoring/middleware.go`

## Relationships

- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (2 shared connections)
- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (1 shared connections)
- [Misc](Misc.md) (1 shared connections)

## Source Files

- `internal/monitoring/middleware.go`

## Audit Trail

- EXTRACTED: 8 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*