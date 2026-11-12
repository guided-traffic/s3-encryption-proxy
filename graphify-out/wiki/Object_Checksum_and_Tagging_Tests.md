# Object Checksum and Tagging Tests

> 119 nodes · cohesion 0.07

## Key Concepts

- **getobject_coverage_test.go** (107 connections) — `internal/proxy/handlers/object/getobject_coverage_test.go`
- **rangeread_coverage_test.go** (89 connections) — `internal/proxy/handlers/object/rangeread_coverage_test.go`
- **ObjGetdo()** (67 connections) — `internal/proxy/handlers/object/getobject_coverage_test.go`
- **ObjGetpayload()** (60 connections) — `internal/proxy/handlers/object/getobject_coverage_test.go`
- **ObjGetnewHandler()** (41 connections) — `internal/proxy/handlers/object/getobject_coverage_test.go`
- **ObjGetrangeRequest()** (33 connections) — `internal/proxy/handlers/object/rangeread_coverage_test.go`
- **ObjGetrangeHandler()** (31 connections) — `internal/proxy/handlers/object/rangeread_coverage_test.go`
- **ObjGetparseError()** (30 connections) — `internal/proxy/handlers/object/getobject_coverage_test.go`
- **ObjGetstore()** (30 connections) — `internal/proxy/handlers/object/getobject_coverage_test.go`
- **ObjGetrangeStore()** (28 connections) — `internal/proxy/handlers/object/rangeread_coverage_test.go`
- **ObjGetdigest()** (20 connections) — `internal/proxy/handlers/object/getobject_coverage_test.go`
- **ObjGetrangeAnswer()** (18 connections) — `internal/proxy/handlers/object/rangeread_coverage_test.go`
- **newResponseTestHandler()** (16 connections) — `internal/proxy/handlers/object/object_test.go`
- **ObjServeStored()** (16 connections) — `internal/proxy/handlers/object/test_helpers_test.go`
- **ObjGetgetOutput()** (15 connections) — `internal/proxy/handlers/object/getobject_coverage_test.go`
- **TestObjTagEveryObjectVerbAnswersTheMarker()** (14 connections) — `internal/proxy/handlers/object/etag_marker_test.go`
- **ObjGetserve()** (12 connections) — `internal/proxy/handlers/object/getobject_coverage_test.go`
- **TestObjGetGetObjectUnderTheExitProviderDecidesPerObject()** (11 connections) — `internal/proxy/handlers/object/getobject_coverage_test.go`
- **TestObjIntAMidStreamFaultIsLoggedAndCounted()** (11 connections) — `internal/proxy/handlers/object/integrity_report_test.go`
- **TestObjIntARangedFaultIsLoggedAndCounted()** (11 connections) — `internal/proxy/handlers/object/integrity_report_test.go`
- **TestObjGetRangeExitProviderRefusesAnObjectItCannotOpen()** (11 connections) — `internal/proxy/handlers/object/rangeread_coverage_test.go`
- **ObjGetnewProviderHandler()** (10 connections) — `internal/proxy/handlers/object/getobject_coverage_test.go`
- **TestObjGetGetObjectForgedExitFingerprintIsNotServed()** (10 connections) — `internal/proxy/handlers/object/getobject_coverage_test.go`
- **TestObjGetGetObjectUndecryptableMetadata()** (10 connections) — `internal/proxy/handlers/object/getobject_coverage_test.go`
- **TestObjGetHeadObjectRefusesWhatItCannotSize()** (10 connections) — `internal/proxy/handlers/object/getobject_coverage_test.go`
- *... and 94 more nodes in this community*

## Relationships

- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (130 shared connections)
- [Shutdown and Test Contexts](Shutdown_and_Test_Contexts.md) (90 shared connections)
- [GET Response Writing](GET_Response_Writing.md) (7 shared connections)
- [Object Checksum Agreement Tests](Object_Checksum_Agreement_Tests.md) (6 shared connections)
- [DeleteObjects Handling](DeleteObjects_Handling.md) (5 shared connections)
- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (4 shared connections)
- [Multipart Handlers and Manager](Multipart_Handlers_and_Manager.md) (4 shared connections)
- [Misc (26)](Misc_26.md) (3 shared connections)
- [Configuration Loading](Configuration_Loading.md) (2 shared connections)
- [Segment Codec and Range Planner](Segment_Codec_and_Range_Planner.md) (2 shared connections)
- [Manager Tests](Manager_Tests.md) (2 shared connections)
- [Response: Error Mapping Coverage Test](Response-_Error_Mapping_Coverage_Test.md) (2 shared connections)

## Source Files

- `internal/proxy/handlers/object/checksum_echo_test.go`
- `internal/proxy/handlers/object/etag_marker_test.go`
- `internal/proxy/handlers/object/getobject_coverage_test.go`
- `internal/proxy/handlers/object/integrity_report_test.go`
- `internal/proxy/handlers/object/object_test.go`
- `internal/proxy/handlers/object/range_test.go`
- `internal/proxy/handlers/object/rangeread_coverage_test.go`
- `internal/proxy/handlers/object/test_helpers_test.go`

## Audit Trail

- EXTRACTED: 619 (79%)
- INFERRED: 164 (21%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*