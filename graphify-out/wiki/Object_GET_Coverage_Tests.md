# Object GET Coverage Tests

> 154 nodes · cohesion 0.05

## Key Concepts

- **ObjGetdo()** (67 connections) — `internal/proxy/handlers/object/getobject_coverage_test.go`
- **ObjGetpayload()** (60 connections) — `internal/proxy/handlers/object/getobject_coverage_test.go`
- **getobject_coverage_test.go** (48 connections) — `internal/proxy/handlers/object/getobject_coverage_test.go`
- **ObjGetnewHandler()** (41 connections) — `internal/proxy/handlers/object/getobject_coverage_test.go`
- **rangeread_coverage_test.go** (38 connections) — `internal/proxy/handlers/object/rangeread_coverage_test.go`
- **ObjGetrangeRequest()** (33 connections) — `internal/proxy/handlers/object/rangeread_coverage_test.go`
- **object_test.go** (31 connections) — `internal/proxy/handlers/object/object_test.go`
- **ObjGetrangeHandler()** (31 connections) — `internal/proxy/handlers/object/rangeread_coverage_test.go`
- **ObjGetparseError()** (30 connections) — `internal/proxy/handlers/object/getobject_coverage_test.go`
- **ObjGetstore()** (30 connections) — `internal/proxy/handlers/object/getobject_coverage_test.go`
- **ObjGetrangeStore()** (28 connections) — `internal/proxy/handlers/object/rangeread_coverage_test.go`
- **newEncryptingTestHandler()** (21 connections) — `internal/proxy/handlers/object/object_test.go`
- **ObjGetdigest()** (20 connections) — `internal/proxy/handlers/object/getobject_coverage_test.go`
- **ObjGetrangeAnswer()** (18 connections) — `internal/proxy/handlers/object/rangeread_coverage_test.go`
- **newResponseTestHandler()** (16 connections) — `internal/proxy/handlers/object/object_test.go`
- **ObjServeStored()** (16 connections) — `internal/proxy/handlers/object/test_helpers_test.go`
- **ObjGetgetOutput()** (15 connections) — `internal/proxy/handlers/object/getobject_coverage_test.go`
- **objCallAutoMultipart()** (15 connections) — `internal/proxy/handlers/object/object_test.go`
- **TestObjTagEveryObjectVerbAnswersTheMarker()** (14 connections) — `internal/proxy/handlers/object/etag_marker_test.go`
- **testPayload()** (13 connections) — `internal/proxy/handlers/object/object_test.go`
- **ObjGetserve()** (12 connections) — `internal/proxy/handlers/object/getobject_coverage_test.go`
- **TestObjGetGetObjectUnderTheExitProviderDecidesPerObject()** (11 connections) — `internal/proxy/handlers/object/getobject_coverage_test.go`
- **TestObjIntAMidStreamFaultIsLoggedAndCounted()** (11 connections) — `internal/proxy/handlers/object/integrity_report_test.go`
- **TestObjIntARangedFaultIsLoggedAndCounted()** (11 connections) — `internal/proxy/handlers/object/integrity_report_test.go`
- **TestObjGetRangeExitProviderRefusesAnObjectItCannotOpen()** (11 connections) — `internal/proxy/handlers/object/rangeread_coverage_test.go`
- *... and 129 more nodes in this community*

## Relationships

- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (114 shared connections)
- [Checksum and ETag Echo Tests](Checksum_and_ETag_Echo_Tests.md) (10 shared connections)
- [Object Response Header Helpers](Object_Response_Header_Helpers.md) (6 shared connections)
- [Multipart Handler Wiring](Multipart_Handler_Wiring.md) (5 shared connections)
- [Bucket ACL and Accelerate Handlers](Bucket_ACL_and_Accelerate_Handlers.md) (4 shared connections)
- [Logger](Logger.md) (3 shared connections)
- [Object Dispatch Coverage Tests](Object_Dispatch_Coverage_Tests.md) (3 shared connections)
- [MockS3Backend Multipart Operations](MockS3Backend_Multipart_Operations.md) (3 shared connections)
- [Orchestration Manager Coverage](Orchestration_Manager_Coverage.md) (3 shared connections)
- [Integration Failing Writer Fixtures](Integration_Failing_Writer_Fixtures.md) (3 shared connections)
- [Object Metadata Coverage Tests](Object_Metadata_Coverage_Tests.md) (3 shared connections)
- [Error Mapping Coverage Tests](Error_Mapping_Coverage_Tests.md) (2 shared connections)

## Source Files

- `internal/proxy/handlers/object/checksum_echo_test.go`
- `internal/proxy/handlers/object/etag_marker_test.go`
- `internal/proxy/handlers/object/getobject_coverage_test.go`
- `internal/proxy/handlers/object/integrity_report_test.go`
- `internal/proxy/handlers/object/object_test.go`
- `internal/proxy/handlers/object/range.go`
- `internal/proxy/handlers/object/range_test.go`
- `internal/proxy/handlers/object/rangeread_coverage_test.go`
- `internal/proxy/handlers/object/test_helpers_test.go`

## Audit Trail

- EXTRACTED: 622 (78%)
- INFERRED: 171 (22%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*