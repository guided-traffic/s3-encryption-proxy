# Bucket Sub-Resource Handlers

> 162 nodes · cohesion 0.04

## Key Concepts

- **net/http.Request** (188 connections)
- **net/http.ResponseWriter** (135 connections)
- **ExpectedBucketOwner()** (60 connections) — `internal/proxy/request/bucketowner.go`
- **Handler** (50 connections) — `internal/proxy/handlers/object/handler.go`
- **Handler** (46 connections) — `internal/proxy/handlers/bucket/handler.go`
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
- **LoggingHandler** (9 connections) — `internal/proxy/handlers/bucket/logging.go`
- **PolicyHandler** (9 connections) — `internal/proxy/handlers/bucket/policy.go`
- **ReplicationHandler** (9 connections) — `internal/proxy/handlers/bucket/replication.go`
- **WebsiteHandler** (9 connections) — `internal/proxy/handlers/bucket/website.go`
- **.writeGetObjectResponse()** (9 connections) — `internal/proxy/handlers/object/operations.go`
- **.writeRangeResponse()** (9 connections) — `internal/proxy/handlers/object/range.go`
- **AccelerateHandler** (8 connections) — `internal/proxy/handlers/bucket/accelerate.go`
- **NotificationHandler** (8 connections) — `internal/proxy/handlers/bucket/notification.go`
- **RequestPaymentHandler** (8 connections) — `internal/proxy/handlers/bucket/request_payment.go`
- **VersioningHandler** (8 connections) — `internal/proxy/handlers/bucket/versioning.go`
- *... and 137 more nodes in this community*

## Relationships

- [Request Documents and Owner Guard](Request_Documents_and_Owner_Guard.md) (70 shared connections)
- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (39 shared connections)
- [Sub-Resource Handler Tests](Sub-Resource_Handler_Tests.md) (28 shared connections)
- [Multipart Handlers and Manager](Multipart_Handlers_and_Manager.md) (28 shared connections)
- [Server and Listings](Server_and_Listings.md) (19 shared connections)
- [Object: Storage Headers](Object-_Storage_Headers.md) (16 shared connections)
- [Middleware: S3Auth Robust](Middleware-_S3Auth_Robust.md) (9 shared connections)
- [Object: Range (2)](Object-_Range_2.md) (7 shared connections)
- [Object: Metadata Coverage Test](Object-_Metadata_Coverage_Test.md) (6 shared connections)
- [S3 API Behaviour](S3_API_Behaviour.md) (5 shared connections)
- [Monitoring: Backend](Monitoring-_Backend.md) (5 shared connections)
- [Shutdown and Test Contexts](Shutdown_and_Test_Contexts.md) (5 shared connections)

## Source Files

- `docs/tickets/027-whole-object-read-first-window.md`
- `internal/monitoring/metrics.go`
- `internal/orchestration/segmented.go`
- `internal/proxy/handlers/bucket/accelerate.go`
- `internal/proxy/handlers/bucket/acl.go`
- `internal/proxy/handlers/bucket/cors.go`
- `internal/proxy/handlers/bucket/handler.go`
- `internal/proxy/handlers/bucket/lifecycle.go`
- `internal/proxy/handlers/bucket/listing.go`
- `internal/proxy/handlers/bucket/location.go`
- `internal/proxy/handlers/bucket/logging.go`
- `internal/proxy/handlers/bucket/notification.go`
- `internal/proxy/handlers/bucket/operations.go`
- `internal/proxy/handlers/bucket/policy.go`
- `internal/proxy/handlers/bucket/replication.go`
- `internal/proxy/handlers/bucket/request_payment.go`
- `internal/proxy/handlers/bucket/tagging.go`
- `internal/proxy/handlers/bucket/versioning.go`
- `internal/proxy/handlers/bucket/website.go`
- `internal/proxy/handlers/health/handler.go`

## Audit Trail

- EXTRACTED: 683 (87%)
- INFERRED: 106 (13%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*