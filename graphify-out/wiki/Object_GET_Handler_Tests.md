# Object GET Handler Tests

> 115 nodes · cohesion 0.06

## Key Concepts

- **ObjGetdo()** (42 connections) — `internal/proxy/handlers/object/getobject_coverage_test.go`
- **getobject_coverage_test.go** (37 connections) — `internal/proxy/handlers/object/getobject_coverage_test.go`
- **ObjGetpayload()** (35 connections) — `internal/proxy/handlers/object/getobject_coverage_test.go`
- **rangeread_coverage_test.go** (31 connections) — `internal/proxy/handlers/object/rangeread_coverage_test.go`
- **ObjGetrangeHandler()** (24 connections) — `internal/proxy/handlers/object/rangeread_coverage_test.go`
- **ObjGetnewHandler()** (23 connections) — `internal/proxy/handlers/object/getobject_coverage_test.go`
- **ObjGetparseError()** (23 connections) — `internal/proxy/handlers/object/getobject_coverage_test.go`
- **object_test.go** (22 connections) — `internal/proxy/handlers/object/object_test.go`
- **ObjGetrangeRequest()** (21 connections) — `internal/proxy/handlers/object/rangeread_coverage_test.go`
- **ObjGetrangeStore()** (18 connections) — `internal/proxy/handlers/object/rangeread_coverage_test.go`
- **ObjGetstore()** (16 connections) — `internal/proxy/handlers/object/getobject_coverage_test.go`
- **ObjGetgetOutput()** (15 connections) — `internal/proxy/handlers/object/getobject_coverage_test.go`
- **newEncryptingTestHandler()** (15 connections) — `internal/proxy/handlers/object/object_test.go`
- **newResponseTestHandler()** (15 connections) — `internal/proxy/handlers/object/object_test.go`
- **ObjGetdigest()** (13 connections) — `internal/proxy/handlers/object/getobject_coverage_test.go`
- **ObjGetnewProviderHandler()** (10 connections) — `internal/proxy/handlers/object/getobject_coverage_test.go`
- **TestObjGetGetObjectForgedExitFingerprintIsNotServed()** (10 connections) — `internal/proxy/handlers/object/getobject_coverage_test.go`
- **TestObjGetGetObjectUndecryptableMetadata()** (10 connections) — `internal/proxy/handlers/object/getobject_coverage_test.go`
- **TestObjGetGetObjectUnderTheExitProviderDecidesPerObject()** (10 connections) — `internal/proxy/handlers/object/getobject_coverage_test.go`
- **TestObjGetRangeExitProviderStillDecryptsASealedObject()** (10 connections) — `internal/proxy/handlers/object/rangeread_coverage_test.go`
- **TestObjGetHeadObjectRefusesWhatItCannotSize()** (9 connections) — `internal/proxy/handlers/object/getobject_coverage_test.go`
- **ObjGetrangeHandlerWith()** (9 connections) — `internal/proxy/handlers/object/rangeread_coverage_test.go`
- **TestObjGetRangeReturnsThePlaintextWindow()** (9 connections) — `internal/proxy/handlers/object/rangeread_coverage_test.go`
- **TestObjGetRangeSuffixAndOpenEndedResolveAgainstTheHead()** (9 connections) — `internal/proxy/handlers/object/rangeread_coverage_test.go`
- **TestObjGetGetObjectBackendBodyCloseFailureStillDelivers()** (8 connections) — `internal/proxy/handlers/object/getobject_coverage_test.go`
- *... and 90 more nodes in this community*

## Relationships

- [Config Env Expansion](Config_Env_Expansion.md) (81 shared connections)
- [Object Operations Handler](Object_Operations_Handler.md) (6 shared connections)
- [Multipart Handler](Multipart_Handler.md) (4 shared connections)
- [Orchestration Manager](Orchestration_Manager.md) (3 shared connections)
- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (2 shared connections)
- [Object Dispatch and Metadata Tests](Object_Dispatch_and_Metadata_Tests.md) (2 shared connections)
- [Mock: GetObject](Mock-_GetObject.md) (2 shared connections)
- [Object Header Conformance](Object_Header_Conformance.md) (2 shared connections)
- [Copy Benchmarks](Copy_Benchmarks.md) (1 shared connections)
- [Error Response Tests](Error_Response_Tests.md) (1 shared connections)
- [Segment Codec Tests](Segment_Codec_Tests.md) (1 shared connections)
- [Object PUT Handler Tests](Object_PUT_Handler_Tests.md) (1 shared connections)

## Source Files

- `internal/proxy/handlers/object/getobject_coverage_test.go`
- `internal/proxy/handlers/object/object_test.go`
- `internal/proxy/handlers/object/range.go`
- `internal/proxy/handlers/object/range_test.go`
- `internal/proxy/handlers/object/rangeread_coverage_test.go`

## Audit Trail

- EXTRACTED: 430 (85%)
- INFERRED: 78 (15%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*