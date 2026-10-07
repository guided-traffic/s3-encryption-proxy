# Object Handler Dependencies

> 10 nodes · cohesion 0.36

## Key Concepts

- **TaggingHandler** (11 connections) — `internal/proxy/handlers/object/tagging.go`
- **NewTaggingHandler()** (8 connections) — `internal/proxy/handlers/object/tagging.go`
- **.Handle()** (6 connections) — `internal/proxy/handlers/object/tagging.go`
- **.handleDeleteTagging()** (4 connections) — `internal/proxy/handlers/object/tagging.go`
- **.handleGetTagging()** (4 connections) — `internal/proxy/handlers/object/tagging.go`
- **.handlePutTagging()** (4 connections) — `internal/proxy/handlers/object/tagging.go`
- **github.com/guided-traffic/s3-encryption-proxy/internal/proxy/interfaces.S3BackendInterface** (2 connections)
- **github.com/guided-traffic/s3-encryption-proxy/internal/proxy/request.Parser** (2 connections)
- **github.com/guided-traffic/s3-encryption-proxy/internal/proxy/response.ErrorWriter** (2 connections)
- **github.com/guided-traffic/s3-encryption-proxy/internal/proxy/response.XMLWriter** (2 connections)

## Relationships

- [Bucket ACL and Accelerate Handlers](Bucket_ACL_and_Accelerate_Handlers.md) (8 shared connections)
- [Multipart Handler Wiring](Multipart_Handler_Wiring.md) (3 shared connections)
- [Object Lock Imports](Object_Lock_Imports.md) (2 shared connections)

## Source Files

- `internal/proxy/handlers/object/tagging.go`

## Audit Trail

- EXTRACTED: 28 (97%)
- INFERRED: 1 (3%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*