# Bucket Sub-Resource Handlers

> 137 nodes · cohesion 0.04

## Key Concepts

- **net/http.Request** (188 connections)
- **net/http.ResponseWriter** (135 connections)
- **ExpectedBucketOwner()** (60 connections) — `internal/proxy/request/bucketowner.go`
- **Handler** (49 connections) — `internal/proxy/handlers/object/handler.go`
- **objectVersionID()** (16 connections) — `internal/proxy/handlers/object/helpers.go`
- **.handleGetObjectRange()** (15 connections) — `internal/proxy/handlers/object/range.go`
- **.putObjectSegmented()** (14 connections) — `internal/proxy/handlers/object/operations.go`
- **readDocument()** (12 connections) — `internal/proxy/handlers/object/helpers.go`
- **writeVersionHeaders()** (12 connections) — `internal/proxy/handlers/object/helpers.go`
- **ReadConditionalHeaders()** (12 connections) — `internal/proxy/handlers/object/storage_headers.go`
- **.fetchObjectTail()** (10 connections) — `internal/proxy/handlers/object/tail.go`
- **.writeHeadResponse()** (10 connections) — `internal/proxy/handlers/object/operations.go`
- **CORSHandler** (9 connections) — `internal/proxy/handlers/bucket/cors.go`
- **LifecycleHandler** (9 connections) — `internal/proxy/handlers/bucket/lifecycle.go`
- **PolicyHandler** (9 connections) — `internal/proxy/handlers/bucket/policy.go`
- **ReplicationHandler** (9 connections) — `internal/proxy/handlers/bucket/replication.go`
- **WebsiteHandler** (9 connections) — `internal/proxy/handlers/bucket/website.go`
- **Ranged GET window planning** (9 connections) — `docs/developer/request-paths.md`
- **.writeGetObjectResponse()** (9 connections) — `internal/proxy/handlers/object/operations.go`
- **.writeRangeResponse()** (9 connections) — `internal/proxy/handlers/object/range.go`
- **PlaintextSize()** (8 connections) — `internal/orchestration/segmented.go`
- **WriteSSEHeaders()** (8 connections) — `internal/proxy/handlers/object/helpers.go`
- **.handleObjectLegalHold()** (8 connections) — `internal/proxy/handlers/object/objectlock.go`
- **.handleObjectRetention()** (8 connections) — `internal/proxy/handlers/object/objectlock.go`
- **.handleHeadObject()** (8 connections) — `internal/proxy/handlers/object/operations.go`
- *... and 112 more nodes in this community*

## Relationships

- [Request Documents and Owner Guard](Request_Documents_and_Owner_Guard.md) (72 shared connections)
- [Object: Metadata Coverage Test](Object-_Metadata_Coverage_Test.md) (50 shared connections)
- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (37 shared connections)
- [Multipart Handlers and Manager](Multipart_Handlers_and_Manager.md) (20 shared connections)
- [Server and Listings](Server_and_Listings.md) (17 shared connections)
- [Sub-Resource Handler Tests](Sub-Resource_Handler_Tests.md) (16 shared connections)
- [Object: Storage Headers](Object-_Storage_Headers.md) (16 shared connections)
- [Shutdown and Test Contexts](Shutdown_and_Test_Contexts.md) (10 shared connections)
- [Misc (24)](Misc_24.md) (9 shared connections)
- [Dataencryption: Segmented Gcm Range](Dataencryption-_Segmented_Gcm_Range.md) (7 shared connections)
- [Monitoring: Backend](Monitoring-_Backend.md) (6 shared connections)
- [Checksum Verifier](Checksum_Verifier.md) (5 shared connections)

## Source Files

- `docs/developer/request-paths.md`
- `internal/monitoring/metrics.go`
- `internal/orchestration/segmented.go`
- `internal/proxy/handlers/bucket/acl.go`
- `internal/proxy/handlers/bucket/cors.go`
- `internal/proxy/handlers/bucket/handler.go`
- `internal/proxy/handlers/bucket/lifecycle.go`
- `internal/proxy/handlers/bucket/listing.go`
- `internal/proxy/handlers/bucket/location.go`
- `internal/proxy/handlers/bucket/logging.go`
- `internal/proxy/handlers/bucket/operations.go`
- `internal/proxy/handlers/bucket/policy.go`
- `internal/proxy/handlers/bucket/replication.go`
- `internal/proxy/handlers/bucket/request_payment.go`
- `internal/proxy/handlers/bucket/tagging.go`
- `internal/proxy/handlers/bucket/website.go`
- `internal/proxy/handlers/health/handler.go`
- `internal/proxy/handlers/health/handler_coverage_test.go`
- `internal/proxy/handlers/object/acl.go`
- `internal/proxy/handlers/object/copy_bench_test.go`

## Audit Trail

- EXTRACTED: 630 (86%)
- INFERRED: 101 (14%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*