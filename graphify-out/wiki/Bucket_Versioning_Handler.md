# Bucket Versioning Handler

> 7 nodes · cohesion 0.43

## Key Concepts

- **NewVersioningHandler()** (8 connections) — `internal/proxy/handlers/bucket/versioning.go`
- **TestVersioningHandler_Handle()** (7 connections) — `internal/proxy/handlers/bucket/versioning_test.go`
- **TestVersioningHandler_HandleErrors()** (7 connections) — `internal/proxy/handlers/bucket/versioning_test.go`
- **TestVersioningHandler_MFAValidation()** (7 connections) — `internal/proxy/handlers/bucket/versioning_test.go`
- **TestVersioningHandler_XMLParsing()** (7 connections) — `internal/proxy/handlers/bucket/versioning_test.go`
- **versioning_test.go** (4 connections) — `internal/proxy/handlers/bucket/versioning_test.go`
- **versioning.go** (2 connections) — `internal/proxy/handlers/bucket/versioning.go`

## Relationships

- [Bucket NotImplemented Tests](Bucket_NotImplemented_Tests.md) (8 shared connections)
- [XML Response Helpers](XML_Response_Helpers.md) (4 shared connections)
- [Error Response Tests](Error_Response_Tests.md) (4 shared connections)
- [Config Env Expansion](Config_Env_Expansion.md) (4 shared connections)
- [Bucket Handler Routing](Bucket_Handler_Routing.md) (3 shared connections)
- [Bucket CRUD Tests](Bucket_CRUD_Tests.md) (1 shared connections)

## Source Files

- `internal/proxy/handlers/bucket/versioning.go`
- `internal/proxy/handlers/bucket/versioning_test.go`

## Audit Trail

- EXTRACTED: 24 (73%)
- INFERRED: 9 (27%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*