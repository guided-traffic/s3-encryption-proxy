# Bucket Versioning Handler

> 8 nodes · cohesion 0.39

## Key Concepts

- **VersioningHandler** (8 connections) — `internal/proxy/handlers/bucket/versioning.go`
- **NewVersioningHandler()** (8 connections) — `internal/proxy/handlers/bucket/versioning.go`
- **TestVersioningHandler_Handle()** (7 connections) — `internal/proxy/handlers/bucket/versioning_test.go`
- **TestVersioningHandler_HandleErrors()** (7 connections) — `internal/proxy/handlers/bucket/versioning_test.go`
- **TestVersioningHandler_MFAValidation()** (7 connections) — `internal/proxy/handlers/bucket/versioning_test.go`
- **TestVersioningHandler_XMLParsing()** (7 connections) — `internal/proxy/handlers/bucket/versioning_test.go`
- **versioning_test.go** (4 connections) — `internal/proxy/handlers/bucket/versioning_test.go`
- **versioning.go** (2 connections) — `internal/proxy/handlers/bucket/versioning.go`

## Relationships

- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (12 shared connections)
- [Copy and Delete Object Handlers](Copy_and_Delete_Object_Handlers.md) (4 shared connections)
- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (4 shared connections)
- [Bucket Sub-Resource Handler Registry](Bucket_Sub-Resource_Handler_Registry.md) (3 shared connections)
- [Bucket ACL and Accelerate Handlers](Bucket_ACL_and_Accelerate_Handlers.md) (3 shared connections)
- [Bucket CORS Handler](Bucket_CORS_Handler.md) (2 shared connections)

## Source Files

- `internal/proxy/handlers/bucket/versioning.go`
- `internal/proxy/handlers/bucket/versioning_test.go`

## Audit Trail

- EXTRACTED: 30 (77%)
- INFERRED: 9 (23%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*