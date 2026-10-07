# Monitoring Backend Stub

> 3 nodes · cohesion 1.00

## Key Concepts

- **net/http.Response** (5 connections)
- **MonstubBackend** (3 connections) — `internal/monitoring/backend_test.go`
- **.Do()** (3 connections) — `internal/monitoring/backend_test.go`

## Relationships

- [Backend Call Observation](Backend_Call_Observation.md) (2 shared connections)
- [Authentication Integration Tests](Authentication_Integration_Tests.md) (1 shared connections)
- [Backend](Backend.md) (1 shared connections)
- [Bucket ACL and Accelerate Handlers](Bucket_ACL_and_Accelerate_Handlers.md) (1 shared connections)

## Source Files

- `internal/monitoring/backend_test.go`

## Audit Trail

- EXTRACTED: 8 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*