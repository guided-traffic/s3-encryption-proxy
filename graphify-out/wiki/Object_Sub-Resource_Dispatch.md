# Object Sub-Resource Dispatch

> 17 nodes · cohesion 0.14

## Key Concepts

- **Handler** (20 connections) — `internal/proxy/handlers/object/handler.go`
- **.Handle()** (5 connections) — `internal/proxy/handlers/object/handler.go`
- **IsAWSProtocolQueryParam()** (4 connections) — `internal/proxy/request/queryparams.go`
- **.handleBaseObjectOperations()** (4 connections) — `internal/proxy/handlers/object/handler.go`
- **object/handler.go** (3 connections) — `internal/proxy/handlers/object/handler.go`
- **.HandleDeleteObjects()** (3 connections) — `internal/proxy/handlers/object/handler.go`
- **.HandleObjectLegalHold()** (3 connections) — `internal/proxy/handlers/object/handler.go`
- **.HandleObjectRetention()** (3 connections) — `internal/proxy/handlers/object/handler.go`
- **.HandleObjectTorrent()** (3 connections) — `internal/proxy/handlers/object/handler.go`
- **.HandleSelectObjectContent()** (3 connections) — `internal/proxy/handlers/object/handler.go`
- **TestReqIsAWSProtocolQueryParam()** (3 connections) — `internal/proxy/request/queryparams_test.go`
- **ACLHandler** (2 connections)
- **TaggingHandler** (2 connections)
- **.GetACLHandler()** (2 connections) — `internal/proxy/handlers/object/handler.go`
- **.GetTaggingHandler()** (2 connections) — `internal/proxy/handlers/object/handler.go`
- **queryparams.go** (1 connections) — `internal/proxy/request/queryparams.go`
- **queryparams_test.go** (1 connections) — `internal/proxy/request/queryparams_test.go`

## Relationships

- [Bucket ACL and Accelerate Handlers](Bucket_ACL_and_Accelerate_Handlers.md) (15 shared connections)
- [Multipart Handler Wiring](Multipart_Handler_Wiring.md) (7 shared connections)
- [Forward-or-Refuse Response Rules](Forward-or-Refuse_Response_Rules.md) (1 shared connections)
- [Configuration Struct and Accessors](Configuration_Struct_and_Accessors.md) (1 shared connections)
- [Bucket CORS Handler](Bucket_CORS_Handler.md) (1 shared connections)
- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (1 shared connections)

## Source Files

- `internal/proxy/handlers/object/handler.go`
- `internal/proxy/request/queryparams.go`
- `internal/proxy/request/queryparams_test.go`

## Audit Trail

- EXTRACTED: 44 (98%)
- INFERRED: 1 (2%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*