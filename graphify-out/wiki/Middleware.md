# Middleware

> 6 nodes · cohesion 0.40

## Key Concepts

- **responseWriter** (7 connections) — `internal/monitoring/middleware.go`
- **middleware.go** (2 connections) — `internal/monitoring/middleware.go`
- **.Flush()** (2 connections) — `internal/monitoring/middleware.go`
- **.FlushError()** (2 connections) — `internal/monitoring/middleware.go`
- **.Unwrap()** (2 connections) — `internal/monitoring/middleware.go`
- **.WriteHeader()** (1 connections) — `internal/monitoring/middleware.go`

## Relationships

- [Bucket Website and Create/Delete](Bucket_Website_and_Create-Delete.md) (2 shared connections)
- [Monitoring Middleware Tests](Monitoring_Middleware_Tests.md) (1 shared connections)
- [HTTP Middleware Coverage Tests](HTTP_Middleware_Coverage_Tests.md) (1 shared connections)

## Source Files

- `internal/monitoring/middleware.go`

## Audit Trail

- EXTRACTED: 10 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*