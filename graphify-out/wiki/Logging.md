# Logging

> 8 nodes · cohesion 0.39

## Key Concepts

- **LoggingHandler** (9 connections) — `internal/proxy/handlers/bucket/logging.go`
- **.Handle()** (6 connections) — `internal/proxy/handlers/bucket/logging.go`
- **.handleGetLogging()** (6 connections) — `internal/proxy/handlers/bucket/logging.go`
- **.handleDeleteLogging()** (5 connections) — `internal/proxy/handlers/bucket/logging.go`
- **.handlePutLogging()** (5 connections) — `internal/proxy/handlers/bucket/logging.go`
- **NewLoggingHandler()** (4 connections) — `internal/proxy/handlers/bucket/logging.go`
- **.GetLoggingHandler()** (2 connections) — `internal/proxy/handlers/bucket/handler.go`
- **bucket/logging.go** (2 connections) — `internal/proxy/handlers/bucket/logging.go`

## Relationships

- [Replication and ACL Handlers](Replication_and_ACL_Handlers.md) (4 shared connections)
- [Bucket Website and Create/Delete](Bucket_Website_and_Create-Delete.md) (4 shared connections)
- [ACL, CORS and Lifecycle Handlers](ACL,_CORS_and_Lifecycle_Handlers.md) (3 shared connections)
- [Bucket Handler Dispatch](Bucket_Handler_Dispatch.md) (2 shared connections)
- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (2 shared connections)
- [Subresource Documents](Subresource_Documents.md) (1 shared connections)
- [Bucket Crud](Bucket_Crud.md) (1 shared connections)

## Source Files

- `internal/proxy/handlers/bucket/handler.go`
- `internal/proxy/handlers/bucket/logging.go`

## Audit Trail

- EXTRACTED: 26 (93%)
- INFERRED: 2 (7%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*