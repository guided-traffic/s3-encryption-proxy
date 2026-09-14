# Bucket CORS Handler

> 9 nodes · cohesion 0.36

## Key Concepts

- **CORSHandler** (10 connections) — `internal/proxy/handlers/bucket/cors.go`
- **.Handle()** (7 connections) — `internal/proxy/handlers/bucket/cors.go`
- **.handleDeleteCORS()** (4 connections) — `internal/proxy/handlers/bucket/cors.go`
- **.handleGetCORS()** (4 connections) — `internal/proxy/handlers/bucket/cors.go`
- **.handleMockCORS()** (4 connections) — `internal/proxy/handlers/bucket/cors.go`
- **.handlePutCORS()** (4 connections) — `internal/proxy/handlers/bucket/cors.go`
- **NewCORSHandler()** (4 connections) — `internal/proxy/handlers/bucket/cors.go`
- **.GetCORSHandler()** (2 connections) — `internal/proxy/handlers/bucket/handler.go`
- **bucket/cors.go** (2 connections) — `internal/proxy/handlers/bucket/cors.go`

## Relationships

- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (10 shared connections)
- [Bucket Handler Routing](Bucket_Handler_Routing.md) (4 shared connections)
- [Bucket CRUD Tests](Bucket_CRUD_Tests.md) (1 shared connections)

## Source Files

- `internal/proxy/handlers/bucket/cors.go`
- `internal/proxy/handlers/bucket/handler.go`

## Audit Trail

- EXTRACTED: 27 (96%)
- INFERRED: 1 (4%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*