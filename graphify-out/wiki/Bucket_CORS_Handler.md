# Bucket CORS Handler

> 29 nodes · cohesion 0.11

## Key Concepts

- **Handler** (37 connections) — `internal/proxy/handlers/bucket/handler.go`
- **CORSHandler** (9 connections) — `internal/proxy/handlers/bucket/cors.go`
- **PolicyHandler** (9 connections) — `internal/proxy/handlers/bucket/policy.go`
- **ReplicationHandler** (9 connections) — `internal/proxy/handlers/bucket/replication.go`
- **.Handle()** (6 connections) — `internal/proxy/handlers/bucket/cors.go`
- **.handleGetCORS()** (6 connections) — `internal/proxy/handlers/bucket/cors.go`
- **.Handle()** (6 connections) — `internal/proxy/handlers/bucket/policy.go`
- **.Handle()** (6 connections) — `internal/proxy/handlers/bucket/replication.go`
- **.handleGetBucketReplication()** (6 connections) — `internal/proxy/handlers/bucket/replication.go`
- **.handleDeleteCORS()** (5 connections) — `internal/proxy/handlers/bucket/cors.go`
- **.handlePutCORS()** (5 connections) — `internal/proxy/handlers/bucket/cors.go`
- **.Handle()** (5 connections) — `internal/proxy/handlers/bucket/handler.go`
- **.handleDeletePolicy()** (5 connections) — `internal/proxy/handlers/bucket/policy.go`
- **.handleGetPolicy()** (5 connections) — `internal/proxy/handlers/bucket/policy.go`
- **.handlePutPolicy()** (5 connections) — `internal/proxy/handlers/bucket/policy.go`
- **.handleDeleteBucketReplication()** (5 connections) — `internal/proxy/handlers/bucket/replication.go`
- **.handleBaseBucketOperations()** (4 connections) — `internal/proxy/handlers/bucket/handler.go`
- **.handlePutBucketReplication()** (4 connections) — `internal/proxy/handlers/bucket/replication.go`
- **.GetAccelerateHandler()** (2 connections) — `internal/proxy/handlers/bucket/handler.go`
- **.GetACLHandler()** (2 connections) — `internal/proxy/handlers/bucket/handler.go`
- **.GetCORSHandler()** (2 connections) — `internal/proxy/handlers/bucket/handler.go`
- **.GetNotificationHandler()** (2 connections) — `internal/proxy/handlers/bucket/handler.go`
- **.GetPolicyHandler()** (2 connections) — `internal/proxy/handlers/bucket/handler.go`
- **.GetReplicationHandler()** (2 connections) — `internal/proxy/handlers/bucket/handler.go`
- **.GetRequestPaymentHandler()** (2 connections) — `internal/proxy/handlers/bucket/handler.go`
- *... and 4 more nodes in this community*

## Relationships

- [Bucket ACL and Accelerate Handlers](Bucket_ACL_and_Accelerate_Handlers.md) (35 shared connections)
- [Bucket Sub-Resource Handler Registry](Bucket_Sub-Resource_Handler_Registry.md) (16 shared connections)
- [Object Response Header Helpers](Object_Response_Header_Helpers.md) (8 shared connections)
- [Multipart Handler Wiring](Multipart_Handler_Wiring.md) (5 shared connections)
- [Bucket Versioning Handler](Bucket_Versioning_Handler.md) (2 shared connections)
- [Bucket Replication Handler](Bucket_Replication_Handler.md) (2 shared connections)
- [Bucket CORS Documents](Bucket_CORS_Documents.md) (1 shared connections)
- [Object Sub-Resource Dispatch](Object_Sub-Resource_Dispatch.md) (1 shared connections)
- [Bucket Replication Documents](Bucket_Replication_Documents.md) (1 shared connections)
- [Configuration Struct and Accessors](Configuration_Struct_and_Accessors.md) (1 shared connections)
- [Forward-or-Refuse Response Rules](Forward-or-Refuse_Response_Rules.md) (1 shared connections)

## Source Files

- `internal/proxy/handlers/bucket/cors.go`
- `internal/proxy/handlers/bucket/handler.go`
- `internal/proxy/handlers/bucket/policy.go`
- `internal/proxy/handlers/bucket/replication.go`

## Audit Trail

- EXTRACTED: 114 (98%)
- INFERRED: 2 (2%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*