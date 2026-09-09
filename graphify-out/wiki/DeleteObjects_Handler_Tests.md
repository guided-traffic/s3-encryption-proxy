# DeleteObjects Handler Tests

> 88 nodes · cohesion 0.06

## Key Concepts

- **ObjMiscnewHandler()** (46 connections) — `internal/proxy/handlers/object/dispatch_coverage_test.go`
- **deleteobjects_coverage_test.go** (25 connections) — `internal/proxy/handlers/object/deleteobjects_coverage_test.go`
- **dispatch_coverage_test.go** (24 connections) — `internal/proxy/handlers/object/dispatch_coverage_test.go`
- **object/metadata_coverage_test.go** (21 connections) — `internal/proxy/handlers/object/metadata_coverage_test.go`
- **ObjMiscdeleteObjects()** (17 connections) — `internal/proxy/handlers/object/deleteobjects_coverage_test.go`
- **ObjMiscdo()** (17 connections) — `internal/proxy/handlers/object/dispatch_coverage_test.go`
- **ObjMiscdoFunc()** (17 connections) — `internal/proxy/handlers/object/dispatch_coverage_test.go`
- **ObjMiscassertNotImplemented()** (15 connections) — `internal/proxy/handlers/object/dispatch_coverage_test.go`
- **ObjMiscnewHandlerWithPrefix()** (12 connections) — `internal/proxy/handlers/object/dispatch_coverage_test.go`
- **net/http/httptest.ResponseRecorder** (11 connections)
- **ObjMiscparseError()** (10 connections) — `internal/proxy/handlers/object/dispatch_coverage_test.go`
- **copyWithPooledBuffer()** (9 connections) — `internal/proxy/handlers/object/helpers.go`
- **ObjMiscparseDeleteResult()** (8 connections) — `internal/proxy/handlers/object/deleteobjects_coverage_test.go`
- **TestObjMiscDefaultPrefixFiltersMetadataAndReturnsPlaintext()** (7 connections) — `internal/proxy/handlers/object/metadata_coverage_test.go`
- **TestObjMiscUppercaseMetadataPrefixDisablesDecryptionAndLeaksMetadata()** (7 connections) — `internal/proxy/handlers/object/metadata_coverage_test.go`
- **testLogEntry()** (7 connections) — `internal/proxy/handlers/object/object_test.go`
- **TestObjMiscDeleteObjectsHappyPath()** (6 connections) — `internal/proxy/handlers/object/deleteobjects_coverage_test.go`
- **TestObjMiscDeleteObjectsMalformedXMLIsRefused()** (6 connections) — `internal/proxy/handlers/object/deleteobjects_coverage_test.go`
- **ObjMiscfailWriter** (6 connections) — `internal/proxy/handlers/object/deleteobjects_coverage_test.go`
- **TestObjMiscDeleteObjectsBackendErrorsAreMapped()** (5 connections) — `internal/proxy/handlers/object/deleteobjects_coverage_test.go`
- **TestObjMiscDeleteObjectsBodyReadErrorIsRefused()** (5 connections) — `internal/proxy/handlers/object/deleteobjects_coverage_test.go`
- **TestObjMiscDeleteObjectsEmptyBodyIsMalformed()** (5 connections) — `internal/proxy/handlers/object/deleteobjects_coverage_test.go`
- **TestObjMiscDeleteObjectsEscapesKeysInTheResponse()** (5 connections) — `internal/proxy/handlers/object/deleteobjects_coverage_test.go`
- **TestObjMiscDeleteObjectsForwardsPerObjectVersionID()** (5 connections) — `internal/proxy/handlers/object/deleteobjects_coverage_test.go`
- **TestObjMiscDeleteObjectsPartialFailureIsReported()** (5 connections) — `internal/proxy/handlers/object/deleteobjects_coverage_test.go`
- *... and 63 more nodes in this community*

## Relationships

- [Config Accessor Tests](Config_Accessor_Tests.md) (56 shared connections)
- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (9 shared connections)
- [Object GET Handler Tests](Object_GET_Handler_Tests.md) (5 shared connections)
- [Multipart Handler Tests](Multipart_Handler_Tests.md) (3 shared connections)
- [Bucket Handler Test Fakes](Bucket_Handler_Test_Fakes.md) (2 shared connections)
- [Object PUT Handler Tests](Object_PUT_Handler_Tests.md) (2 shared connections)
- [Multipart Handler Construction](Multipart_Handler_Construction.md) (2 shared connections)
- [Object Header Conformance Tests](Object_Header_Conformance_Tests.md) (2 shared connections)
- [Monitoring HTTP Server](Monitoring_HTTP_Server.md) (1 shared connections)
- [ListBuckets Root Handler](ListBuckets_Root_Handler.md) (1 shared connections)
- [Health Handler Tests](Health_Handler_Tests.md) (1 shared connections)
- [Manager Construction Tests](Manager_Construction_Tests.md) (1 shared connections)

## Source Files

- `internal/proxy/handlers/object/deleteobjects_coverage_test.go`
- `internal/proxy/handlers/object/dispatch_coverage_test.go`
- `internal/proxy/handlers/object/helpers.go`
- `internal/proxy/handlers/object/metadata_coverage_test.go`
- `internal/proxy/handlers/object/object_test.go`

## Audit Trail

- EXTRACTED: 249 (82%)
- INFERRED: 56 (18%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*