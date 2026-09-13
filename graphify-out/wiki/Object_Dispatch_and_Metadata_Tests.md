# Object Dispatch and Metadata Tests

> 61 nodes · cohesion 0.08

## Key Concepts

- **ObjMiscnewHandler()** (47 connections) — `internal/proxy/handlers/object/dispatch_coverage_test.go`
- **dispatch_coverage_test.go** (26 connections) — `internal/proxy/handlers/object/dispatch_coverage_test.go`
- **ObjMiscdo()** (19 connections) — `internal/proxy/handlers/object/dispatch_coverage_test.go`
- **object/metadata_coverage_test.go** (19 connections) — `internal/proxy/handlers/object/metadata_coverage_test.go`
- **ObjMiscdoFunc()** (17 connections) — `internal/proxy/handlers/object/dispatch_coverage_test.go`
- **ObjMiscassertNotImplemented()** (15 connections) — `internal/proxy/handlers/object/dispatch_coverage_test.go`
- **net/http/httptest.ResponseRecorder** (14 connections)
- **ObjMiscnewHandlerWithPrefix()** (11 connections) — `internal/proxy/handlers/object/dispatch_coverage_test.go`
- **ObjMiscparseError()** (11 connections) — `internal/proxy/handlers/object/dispatch_coverage_test.go`
- **TestObjMiscDefaultPrefixFiltersMetadataAndReturnsPlaintext()** (7 connections) — `internal/proxy/handlers/object/metadata_coverage_test.go`
- **TestObjMiscUnmatchedMetadataPrefixRefusesInsteadOfLeaking()** (7 connections) — `internal/proxy/handlers/object/metadata_coverage_test.go`
- **TestObjMiscDeleteObjectsMalformedXMLIsRefused()** (6 connections) — `internal/proxy/handlers/object/deleteobjects_coverage_test.go`
- **ObjMiscsealed()** (6 connections) — `internal/proxy/handlers/object/dispatch_coverage_test.go`
- **ObjMiscpayload()** (6 connections) — `internal/proxy/handlers/object/metadata_coverage_test.go`
- **ObjMiscstore()** (6 connections) — `internal/proxy/handlers/object/metadata_coverage_test.go`
- **TestObjMiscVersionIDReachesHeadAndGet()** (6 connections) — `internal/proxy/handlers/object/metadata_coverage_test.go`
- **TestObjMiscDeleteObjectsBackendErrorsAreMapped()** (5 connections) — `internal/proxy/handlers/object/deleteobjects_coverage_test.go`
- **TestObjMiscDeleteObjectsBodyReadErrorIsRefused()** (5 connections) — `internal/proxy/handlers/object/deleteobjects_coverage_test.go`
- **TestObjMiscDeleteObjectsEmptyBodyIsMalformed()** (5 connections) — `internal/proxy/handlers/object/deleteobjects_coverage_test.go`
- **TestObjMiscDeleteObjectsWithoutMuxVars()** (5 connections) — `internal/proxy/handlers/object/deleteobjects_coverage_test.go`
- **TestObjMiscDeletePathsDropEveryAWSRequestHeader()** (5 connections) — `internal/proxy/handlers/object/deleteobjects_coverage_test.go`
- **TestObjMiscACLHandlerDirectEntryPoint()** (5 connections) — `internal/proxy/handlers/object/dispatch_coverage_test.go`
- **TestObjMiscHandleACLBeatsTaggingWhenBothArePresent()** (5 connections) — `internal/proxy/handlers/object/dispatch_coverage_test.go`
- **TestObjMiscHandleDispatchesEachMethodToItsOwnBackendCall()** (5 connections) — `internal/proxy/handlers/object/dispatch_coverage_test.go`
- **TestObjMiscHandleRefusesAnObjectThisProxyDidNotWrite()** (5 connections) — `internal/proxy/handlers/object/dispatch_coverage_test.go`
- *... and 36 more nodes in this community*

## Relationships

- [Config Env Expansion](Config_Env_Expansion.md) (45 shared connections)
- [DeleteObjects Handler Tests](DeleteObjects_Handler_Tests.md) (24 shared connections)
- [Object Operations Handler](Object_Operations_Handler.md) (6 shared connections)
- [Bucket Handler Tests](Bucket_Handler_Tests.md) (3 shared connections)
- [ListBuckets Handler Tests](ListBuckets_Handler_Tests.md) (2 shared connections)
- [Object GET Handler Tests](Object_GET_Handler_Tests.md) (2 shared connections)
- [Multipart Handler Tests](Multipart_Handler_Tests.md) (2 shared connections)
- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (2 shared connections)
- [Monitoring Server](Monitoring_Server.md) (1 shared connections)
- [Object PUT Handler Tests](Object_PUT_Handler_Tests.md) (1 shared connections)
- [Health Handler](Health_Handler.md) (1 shared connections)
- [Orchestration Manager](Orchestration_Manager.md) (1 shared connections)

## Source Files

- `internal/proxy/handlers/object/deleteobjects_coverage_test.go`
- `internal/proxy/handlers/object/dispatch_coverage_test.go`
- `internal/proxy/handlers/object/metadata_coverage_test.go`

## Audit Trail

- EXTRACTED: 194 (80%)
- INFERRED: 50 (20%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*