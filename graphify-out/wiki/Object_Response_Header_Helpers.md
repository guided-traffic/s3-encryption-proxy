# Object Response Header Helpers

> 54 nodes · cohesion 0.09

## Key Concepts

- **ExpectedBucketOwner()** (54 connections) — `internal/proxy/request/bucketowner.go`
- **.handleGetObjectRange()** (21 connections) — `internal/proxy/handlers/object/range.go`
- **Handler** (14 connections) — `internal/proxy/handlers/object/operations.go`
- **helpers.go** (13 connections) — `internal/proxy/handlers/object/helpers.go`
- **.fetchObjectTail()** (13 connections) — `internal/proxy/handlers/object/tail.go`
- **range.go** (12 connections) — `internal/proxy/handlers/object/range.go`
- **.Handle()** (12 connections) — `internal/proxy/handlers/multipart/complete.go`
- **objectVersionID()** (11 connections) — `internal/proxy/handlers/object/helpers.go`
- **ReadConditionalHeaders()** (11 connections) — `internal/proxy/handlers/object/storage_headers.go`
- **.putObjectAutoMultipart()** (11 connections) — `internal/proxy/handlers/object/operations.go`
- **.writeGetObjectResponse()** (11 connections) — `internal/proxy/handlers/object/operations.go`
- **.writeHeadResponse()** (11 connections) — `internal/proxy/handlers/object/operations.go`
- **.writeRangeResponse()** (11 connections) — `internal/proxy/handlers/object/range.go`
- **.handleHeadObject()** (10 connections) — `internal/proxy/handlers/object/operations.go`
- **.putObjectSegmented()** (10 connections) — `internal/proxy/handlers/object/operations.go`
- **.servePerObject()** (10 connections) — `internal/proxy/handlers/object/operations.go`
- **PlaintextSize()** (9 connections) — `internal/orchestration/segmented.go`
- **writeVersionHeaders()** (9 connections) — `internal/proxy/handlers/object/helpers.go`
- **.passThroughRange()** (9 connections) — `internal/proxy/handlers/object/range.go`
- **.serveWholeObject()** (9 connections) — `internal/proxy/handlers/object/operations.go`
- **WriteSSEHeaders()** (8 connections) — `internal/proxy/handlers/object/helpers.go`
- **CleanupContext()** (8 connections) — `internal/proxy/utils/utils.go`
- **writeEntityHeaders()** (7 connections) — `internal/proxy/handlers/object/helpers.go`
- **.abortUpload()** (7 connections) — `internal/proxy/handlers/multipart/complete.go`
- **.headForRange()** (7 connections) — `internal/proxy/handlers/object/range.go`
- *... and 29 more nodes in this community*

## Relationships

- [Bucket ACL and Accelerate Handlers](Bucket_ACL_and_Accelerate_Handlers.md) (74 shared connections)
- [Bucket CORS Handler](Bucket_CORS_Handler.md) (8 shared connections)
- [Object Metadata Coverage Tests](Object_Metadata_Coverage_Tests.md) (7 shared connections)
- [Health Probes and Request Tracker](Health_Probes_and_Request_Tracker.md) (7 shared connections)
- [Object GET Coverage Tests](Object_GET_Coverage_Tests.md) (6 shared connections)
- [Multipart ListParts Handler](Multipart_ListParts_Handler.md) (6 shared connections)
- [Multipart Handler Wiring](Multipart_Handler_Wiring.md) (5 shared connections)
- [MockS3Backend Multipart Operations](MockS3Backend_Multipart_Operations.md) (4 shared connections)
- [Segmented GCM](Segmented_GCM.md) (3 shared connections)
- [Segmented Manager Streaming IO](Segmented_Manager_Streaming_IO.md) (3 shared connections)
- [Upload Length Guards and Exit Provider](Upload_Length_Guards_and_Exit_Provider.md) (3 shared connections)
- [Segment Seal and Open Internals](Segment_Seal_and_Open_Internals.md) (3 shared connections)

## Source Files

- `internal/monitoring/metrics.go`
- `internal/orchestration/segmented.go`
- `internal/proxy/handlers/multipart/complete.go`
- `internal/proxy/handlers/object/helpers.go`
- `internal/proxy/handlers/object/operations.go`
- `internal/proxy/handlers/object/range.go`
- `internal/proxy/handlers/object/rangeread_coverage_test.go`
- `internal/proxy/handlers/object/storage_headers.go`
- `internal/proxy/handlers/object/tail.go`
- `internal/proxy/request/bucketowner.go`
- `internal/proxy/utils/utils.go`
- `internal/proxy/utils/utils_coverage_test.go`

## Audit Trail

- EXTRACTED: 239 (83%)
- INFERRED: 50 (17%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*