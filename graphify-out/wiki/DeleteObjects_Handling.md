# DeleteObjects Handling

> 70 nodes · cohesion 0.07

## Key Concepts

- **deleteobjects_coverage_test.go** (49 connections) — `internal/proxy/handlers/object/deleteobjects_coverage_test.go`
- **ObjMiscnewHandler()** (47 connections) — `internal/proxy/handlers/object/dispatch_coverage_test.go`
- **ObjMiscdeleteObjects()** (19 connections) — `internal/proxy/handlers/object/deleteobjects_coverage_test.go`
- **ObjMiscdo()** (19 connections) — `internal/proxy/handlers/object/dispatch_coverage_test.go`
- **ObjMiscdoFunc()** (17 connections) — `internal/proxy/handlers/object/dispatch_coverage_test.go`
- **ObjMiscparseError()** (17 connections) — `internal/proxy/handlers/object/dispatch_coverage_test.go`
- **ObjMiscassertNotImplemented()** (14 connections) — `internal/proxy/handlers/object/dispatch_coverage_test.go`
- **ObjMiscnewHandlerWithPrefix()** (11 connections) — `internal/proxy/handlers/object/dispatch_coverage_test.go`
- **ObjMiscbodyDigest()** (8 connections) — `internal/proxy/handlers/object/deleteobjects_coverage_test.go`
- **ObjMiscparseDeleteResult()** (8 connections) — `internal/proxy/handlers/object/deleteobjects_coverage_test.go`
- **TestObjMiscUnmatchedMetadataPrefixRefusesInsteadOfLeaking()** (8 connections) — `internal/proxy/handlers/object/metadata_coverage_test.go`
- **TestObjMiscVersionIDReachesHeadAndGet()** (8 connections) — `internal/proxy/handlers/object/metadata_coverage_test.go`
- **TestObjMiscDefaultPrefixFiltersMetadataAndReturnsPlaintext()** (7 connections) — `internal/proxy/handlers/object/metadata_coverage_test.go`
- **TestObjMiscDeleteObjectsBodyReadErrorIsRefused()** (6 connections) — `internal/proxy/handlers/object/deleteobjects_coverage_test.go`
- **TestObjMiscDeleteObjectsWithoutMuxVars()** (6 connections) — `internal/proxy/handlers/object/deleteobjects_coverage_test.go`
- **TestObjMiscDeletePathsCarryTheOwnerGuardAndDropTheRest()** (6 connections) — `internal/proxy/handlers/object/deleteobjects_coverage_test.go`
- **ObjMiscsealed()** (6 connections) — `internal/proxy/handlers/object/dispatch_coverage_test.go`
- **TestObjMiscHandleDispatchesEachMethodToItsOwnBackendCall()** (6 connections) — `internal/proxy/handlers/object/dispatch_coverage_test.go`
- **TestObjMiscHandleRefusesAnObjectThisProxyDidNotWrite()** (6 connections) — `internal/proxy/handlers/object/dispatch_coverage_test.go`
- **TestObjMiscHandleUnsupportedMethodIsRefusedNotSilently200()** (6 connections) — `internal/proxy/handlers/object/dispatch_coverage_test.go`
- **ObjMiscpayload()** (6 connections) — `internal/proxy/handlers/object/metadata_coverage_test.go`
- **ObjMiscstore()** (6 connections) — `internal/proxy/handlers/object/metadata_coverage_test.go`
- **TestObjMiscDeleteObjectsBackendErrorsAreMapped()** (5 connections) — `internal/proxy/handlers/object/deleteobjects_coverage_test.go`
- **TestObjMiscDeleteObjectsEmptyBodyIsMalformed()** (5 connections) — `internal/proxy/handlers/object/deleteobjects_coverage_test.go`
- **TestObjMiscDeleteObjectsEmptyDocumentIsRefused()** (5 connections) — `internal/proxy/handlers/object/deleteobjects_coverage_test.go`
- *... and 45 more nodes in this community*

## Relationships

- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (57 shared connections)
- [Shutdown and Test Contexts](Shutdown_and_Test_Contexts.md) (54 shared connections)
- [Misc (19)](Misc_19.md) (5 shared connections)
- [Object Checksum and Tagging Tests](Object_Checksum_and_Tagging_Tests.md) (5 shared connections)
- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (3 shared connections)
- [Request Middleware Plumbing](Request_Middleware_Plumbing.md) (2 shared connections)
- [Bucket XML Documents](Bucket_XML_Documents.md) (2 shared connections)
- [Dataencryption: Segmented Gcm Range](Dataencryption-_Segmented_Gcm_Range.md) (2 shared connections)
- [Bucket Handler Tests](Bucket_Handler_Tests.md) (1 shared connections)
- [Manager Tests](Manager_Tests.md) (1 shared connections)
- [Multipart Handlers and Manager](Multipart_Handlers_and_Manager.md) (1 shared connections)

## Source Files

- `internal/proxy/handlers/object/deleteobjects_coverage_test.go`
- `internal/proxy/handlers/object/dispatch_coverage_test.go`
- `internal/proxy/handlers/object/metadata_coverage_test.go`

## Audit Trail

- EXTRACTED: 251 (81%)
- INFERRED: 57 (19%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*