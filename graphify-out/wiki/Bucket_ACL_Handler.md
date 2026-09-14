# Bucket ACL Handler

> 7 nodes · cohesion 0.48

## Key Concepts

- **ACLHandler** (7 connections) — `internal/proxy/handlers/bucket/acl.go`
- **.Handle()** (6 connections) — `internal/proxy/handlers/bucket/acl.go`
- **.handleGetACL()** (4 connections) — `internal/proxy/handlers/bucket/acl.go`
- **.handleMockACL()** (4 connections) — `internal/proxy/handlers/bucket/acl.go`
- **.handlePutACL()** (4 connections) — `internal/proxy/handlers/bucket/acl.go`
- **NewACLHandler()** (4 connections) — `internal/proxy/handlers/bucket/acl.go`
- **bucket/acl.go** (2 connections) — `internal/proxy/handlers/bucket/acl.go`

## Relationships

- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (8 shared connections)
- [Bucket Handler Routing](Bucket_Handler_Routing.md) (2 shared connections)
- [Bucket CRUD Tests](Bucket_CRUD_Tests.md) (1 shared connections)

## Source Files

- `internal/proxy/handlers/bucket/acl.go`

## Audit Trail

- EXTRACTED: 20 (95%)
- INFERRED: 1 (5%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*