# Bucket Replication Handler

> 8 nodes · cohesion 0.39

## Key Concepts

- **NewReplicationHandler()** (9 connections) — `internal/proxy/handlers/bucket/replication.go`
- **TestReplicationHandler_ComplexConfigurations()** (7 connections) — `internal/proxy/handlers/bucket/replication_test.go`
- **TestReplicationHandler_Handle()** (7 connections) — `internal/proxy/handlers/bucket/replication_test.go`
- **TestReplicationHandler_HandleErrors()** (7 connections) — `internal/proxy/handlers/bucket/replication_test.go`
- **TestReplicationHandler_ReplicationMetrics()** (7 connections) — `internal/proxy/handlers/bucket/replication_test.go`
- **TestReplicationHandler_XMLValidation()** (7 connections) — `internal/proxy/handlers/bucket/replication_test.go`
- **replication_test.go** (5 connections) — `internal/proxy/handlers/bucket/replication_test.go`
- **replication.go** (2 connections) — `internal/proxy/handlers/bucket/replication.go`

## Relationships

- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (15 shared connections)
- [Copy and Delete Object Handlers](Copy_and_Delete_Object_Handlers.md) (5 shared connections)
- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (5 shared connections)
- [Bucket CORS Handler](Bucket_CORS_Handler.md) (2 shared connections)
- [Bucket Sub-Resource Handler Registry](Bucket_Sub-Resource_Handler_Registry.md) (2 shared connections)

## Source Files

- `internal/proxy/handlers/bucket/replication.go`
- `internal/proxy/handlers/bucket/replication_test.go`

## Audit Trail

- EXTRACTED: 29 (72%)
- INFERRED: 11 (28%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*