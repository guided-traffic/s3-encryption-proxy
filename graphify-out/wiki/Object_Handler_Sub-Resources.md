# Object Handler Sub-Resources

> 18 nodes · cohesion 0.13

## Key Concepts

- **Handler** (22 connections) — `internal/proxy/handlers/object/handler.go`
- **.Handle()** (5 connections) — `internal/proxy/handlers/object/handler.go`
- **IsAWSProtocolQueryParam()** (4 connections) — `internal/proxy/request/queryparams.go`
- **.handleBaseObjectOperations()** (4 connections) — `internal/proxy/handlers/object/handler.go`
- **.HandleDeleteObjects()** (3 connections) — `internal/proxy/handlers/object/handler.go`
- **.HandleObjectLegalHold()** (3 connections) — `internal/proxy/handlers/object/handler.go`
- **.HandleObjectRetention()** (3 connections) — `internal/proxy/handlers/object/handler.go`
- **.HandleObjectTorrent()** (3 connections) — `internal/proxy/handlers/object/handler.go`
- **.HandleSelectObjectContent()** (3 connections) — `internal/proxy/handlers/object/handler.go`
- **TestReqIsAWSProtocolQueryParam()** (3 connections) — `internal/proxy/request/queryparams_test.go`
- **object/handler.go** (2 connections) — `internal/proxy/handlers/object/handler.go`
- **ACLHandler** (2 connections)
- **TaggingHandler** (2 connections)
- **.GetACLHandler()** (2 connections) — `internal/proxy/handlers/object/handler.go`
- **.GetMetadataHandler()** (2 connections) — `internal/proxy/handlers/object/handler.go`
- **.GetTaggingHandler()** (2 connections) — `internal/proxy/handlers/object/handler.go`
- **queryparams.go** (1 connections) — `internal/proxy/request/queryparams.go`
- **queryparams_test.go** (1 connections) — `internal/proxy/request/queryparams_test.go`

## Relationships

- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (14 shared connections)
- [Multipart Handler Construction](Multipart_Handler_Construction.md) (10 shared connections)
- [Configuration Accessors](Configuration_Accessors.md) (1 shared connections)
- [Bucket Sub-Resource Registry](Bucket_Sub-Resource_Registry.md) (1 shared connections)
- [Config Accessor Tests](Config_Accessor_Tests.md) (1 shared connections)

## Source Files

- `internal/proxy/handlers/object/handler.go`
- `internal/proxy/request/queryparams.go`
- `internal/proxy/request/queryparams_test.go`

## Audit Trail

- EXTRACTED: 46 (98%)
- INFERRED: 1 (2%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*