# Object Operations Handler

> 27 nodes · cohesion 0.16

## Key Concepts

- **.handleGetObjectRange()** (16 connections) — `internal/proxy/handlers/object/range.go`
- **Handler** (14 connections) — `internal/proxy/handlers/object/operations.go`
- **objectVersionID()** (10 connections) — `internal/proxy/handlers/object/helpers.go`
- **copyWithPooledBuffer()** (9 connections) — `internal/proxy/handlers/object/helpers.go`
- **writeVersionHeaders()** (9 connections) — `internal/proxy/handlers/object/helpers.go`
- **.writeRangeResponse()** (9 connections) — `internal/proxy/handlers/object/range.go`
- **PlaintextSize()** (8 connections) — `internal/orchestration/segmented.go`
- **.serveWholeObject()** (8 connections) — `internal/proxy/handlers/object/operations.go`
- **.handleHeadObject()** (7 connections) — `internal/proxy/handlers/object/operations.go`
- **.writeGetObjectResponse()** (7 connections) — `internal/proxy/handlers/object/operations.go`
- **writeEntityHeaders()** (6 connections) — `internal/proxy/handlers/object/helpers.go`
- **Handler** (6 connections) — `internal/proxy/handlers/object/range.go`
- **.passThroughRange()** (6 connections) — `internal/proxy/handlers/object/range.go`
- **helpers.go** (5 connections) — `internal/proxy/handlers/object/helpers.go`
- **.handleDeleteObject()** (5 connections) — `internal/proxy/handlers/object/operations.go`
- **.handlePutObject()** (5 connections) — `internal/proxy/handlers/object/operations.go`
- **.plaintextLength()** (5 connections) — `internal/proxy/handlers/object/range.go`
- **.putObjectSegmented()** (5 connections) — `internal/proxy/handlers/object/operations.go`
- **.handleObjectTorrent()** (4 connections) — `internal/proxy/handlers/object/operations.go`
- **.handleGetObject()** (4 connections) — `internal/proxy/handlers/object/operations.go`
- **.objectIsSegmented()** (4 connections) — `internal/proxy/handlers/object/range.go`
- **.writeDecryptionError()** (4 connections) — `internal/proxy/handlers/object/operations.go`
- **.handleDeleteObjects()** (3 connections) — `internal/proxy/handlers/object/operations.go`
- **.handleObjectLegalHold()** (3 connections) — `internal/proxy/handlers/object/operations.go`
- **.handleObjectRetention()** (3 connections) — `internal/proxy/handlers/object/operations.go`
- *... and 2 more nodes in this community*

## Relationships

- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (35 shared connections)
- [Object GET Handler Tests](Object_GET_Handler_Tests.md) (6 shared connections)
- [Object Dispatch and Metadata Tests](Object_Dispatch_and_Metadata_Tests.md) (6 shared connections)
- [Copy Benchmarks](Copy_Benchmarks.md) (4 shared connections)
- [Mock: GetObject](Mock-_GetObject.md) (3 shared connections)
- [Object Helper Functions](Object_Helper_Functions.md) (3 shared connections)
- [Sealed Part Arithmetic](Sealed_Part_Arithmetic.md) (2 shared connections)
- [Segment Codec Tests](Segment_Codec_Tests.md) (1 shared connections)
- [Segmented Orchestration Tests](Segmented_Orchestration_Tests.md) (1 shared connections)

## Source Files

- `internal/orchestration/segmented.go`
- `internal/proxy/handlers/object/helpers.go`
- `internal/proxy/handlers/object/operations.go`
- `internal/proxy/handlers/object/range.go`

## Audit Trail

- EXTRACTED: 91 (78%)
- INFERRED: 25 (22%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*