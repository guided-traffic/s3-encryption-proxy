# Bucket Lifecycle Handler

> 5 nodes · cohesion 0.50

## Key Concepts

- **TestLifecycleHandler_ComplexRules()** (7 connections) — `internal/proxy/handlers/bucket/lifecycle_test.go`
- **TestLifecycleHandler_Handle()** (7 connections) — `internal/proxy/handlers/bucket/lifecycle_test.go`
- **NewLifecycleHandler()** (6 connections) — `internal/proxy/handlers/bucket/lifecycle.go`
- **lifecycle.go** (2 connections) — `internal/proxy/handlers/bucket/lifecycle.go`
- **lifecycle_test.go** (2 connections) — `internal/proxy/handlers/bucket/lifecycle_test.go`

## Relationships

- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (6 shared connections)
- [Bucket ACL and Accelerate Handlers](Bucket_ACL_and_Accelerate_Handlers.md) (2 shared connections)
- [Bucket Sub-Resource Handler Registry](Bucket_Sub-Resource_Handler_Registry.md) (2 shared connections)
- [Copy and Delete Object Handlers](Copy_and_Delete_Object_Handlers.md) (2 shared connections)
- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (2 shared connections)

## Source Files

- `internal/proxy/handlers/bucket/lifecycle.go`
- `internal/proxy/handlers/bucket/lifecycle_test.go`

## Audit Trail

- EXTRACTED: 14 (74%)
- INFERRED: 5 (26%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*