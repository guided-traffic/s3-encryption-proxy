# Monitoring Flusher Fallback

> 4 nodes · cohesion 0.50

## Key Concepts

- **MonNotAFlusher** (4 connections) — `internal/monitoring/middleware_coverage_test.go`
- **.Header()** (2 connections) — `internal/monitoring/middleware_coverage_test.go`
- **.Write()** (1 connections) — `internal/monitoring/middleware_coverage_test.go`
- **.WriteHeader()** (1 connections) — `internal/monitoring/middleware_coverage_test.go`

## Relationships

- [Monitoring Middleware](Monitoring_Middleware.md) (1 shared connections)
- [Object Header Conformance](Object_Header_Conformance.md) (1 shared connections)

## Source Files

- `internal/monitoring/middleware_coverage_test.go`

## Audit Trail

- EXTRACTED: 5 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*