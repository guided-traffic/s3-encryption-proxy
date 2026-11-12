# Middleware: Logging

> 5 nodes · cohesion 0.40

## Key Concepts

- **responseWriter** (7 connections) — `internal/proxy/middleware/logging.go`
- **.Unwrap()** (2 connections) — `internal/proxy/middleware/logging.go`
- **.Flush()** (1 connections) — `internal/proxy/middleware/logging.go`
- **.FlushError()** (1 connections) — `internal/proxy/middleware/logging.go`
- **.WriteHeader()** (1 connections) — `internal/proxy/middleware/logging.go`

## Relationships

- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (2 shared connections)
- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (1 shared connections)
- [Misc](Misc.md) (1 shared connections)

## Source Files

- `internal/proxy/middleware/logging.go`

## Audit Trail

- EXTRACTED: 8 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*