# Object Handler Helpers

> 8 nodes · cohesion 0.32

## Key Concepts

- **Handler** (8 connections) — `internal/proxy/handlers/object/helpers.go`
- **.prepareEncryptionMetadata()** (4 connections) — `internal/proxy/handlers/object/helpers.go`
- **.isEncryptionMetadata()** (3 connections) — `internal/proxy/handlers/object/helpers.go`
- **.cleanMetadata()** (2 connections) — `internal/proxy/handlers/object/helpers.go`
- **.decodeEncryptedDEK()** (1 connections) — `internal/proxy/handlers/object/helpers.go`
- **.extractEncryptionMetadata()** (1 connections) — `internal/proxy/handlers/object/helpers.go`
- **.getMultipartUploadConcurrency()** (1 connections) — `internal/proxy/handlers/object/helpers.go`
- **.getSegmentSize()** (1 connections) — `internal/proxy/handlers/object/helpers.go`

## Relationships

- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (2 shared connections)
- [Multipart Session State](Multipart_Session_State.md) (1 shared connections)

## Source Files

- `internal/proxy/handlers/object/helpers.go`

## Audit Trail

- EXTRACTED: 12 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*