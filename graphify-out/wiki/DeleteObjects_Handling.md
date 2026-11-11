# DeleteObjects Handling

> 59 nodes · cohesion 0.09

## Key Concepts

- **deleteobjects_coverage_test.go** (49 connections) — `internal/proxy/handlers/object/deleteobjects_coverage_test.go`
- **ObjMiscnewHandler()** (47 connections) — `internal/proxy/handlers/object/dispatch_coverage_test.go`
- **ObjMiscdeleteObjects()** (19 connections) — `internal/proxy/handlers/object/deleteobjects_coverage_test.go`
- **ObjMiscdo()** (19 connections) — `internal/proxy/handlers/object/dispatch_coverage_test.go`
- **ObjMiscdoFunc()** (17 connections) — `internal/proxy/handlers/object/dispatch_coverage_test.go`
- **ObjMiscparseError()** (17 connections) — `internal/proxy/handlers/object/dispatch_coverage_test.go`
- **net/http/httptest.ResponseRecorder** (16 connections)
- **ObjMiscassertNotImplemented()** (14 connections) — `internal/proxy/handlers/object/dispatch_coverage_test.go`
- **ObjMiscbodyDigest()** (8 connections) — `internal/proxy/handlers/object/deleteobjects_coverage_test.go`
- **ObjMiscparseDeleteResult()** (8 connections) — `internal/proxy/handlers/object/deleteobjects_coverage_test.go`
- **TestObjMiscDeleteObjectsBodyReadErrorIsRefused()** (6 connections) — `internal/proxy/handlers/object/deleteobjects_coverage_test.go`
- **TestObjMiscDeleteObjectsWithoutMuxVars()** (6 connections) — `internal/proxy/handlers/object/deleteobjects_coverage_test.go`
- **TestObjMiscDeletePathsCarryTheOwnerGuardAndDropTheRest()** (6 connections) — `internal/proxy/handlers/object/deleteobjects_coverage_test.go`
- **ObjMiscsealed()** (6 connections) — `internal/proxy/handlers/object/dispatch_coverage_test.go`
- **TestObjMiscHandleDispatchesEachMethodToItsOwnBackendCall()** (6 connections) — `internal/proxy/handlers/object/dispatch_coverage_test.go`
- **TestObjMiscHandleRefusesAnObjectThisProxyDidNotWrite()** (6 connections) — `internal/proxy/handlers/object/dispatch_coverage_test.go`
- **TestObjMiscHandleUnsupportedMethodIsRefusedNotSilently200()** (6 connections) — `internal/proxy/handlers/object/dispatch_coverage_test.go`
- **TestObjMiscDeleteObjectsBackendErrorsAreMapped()** (5 connections) — `internal/proxy/handlers/object/deleteobjects_coverage_test.go`
- **TestObjMiscDeleteObjectsEmptyBodyIsMalformed()** (5 connections) — `internal/proxy/handlers/object/deleteobjects_coverage_test.go`
- **TestObjMiscDeleteObjectsEmptyDocumentIsRefused()** (5 connections) — `internal/proxy/handlers/object/deleteobjects_coverage_test.go`
- **TestObjMiscDeleteObjectsEscapesKeysInTheResponse()** (5 connections) — `internal/proxy/handlers/object/deleteobjects_coverage_test.go`
- **TestObjMiscDeleteObjectsForwardsPerObjectVersionID()** (5 connections) — `internal/proxy/handlers/object/deleteobjects_coverage_test.go`
- **TestObjMiscDeleteObjectsHappyPath()** (5 connections) — `internal/proxy/handlers/object/deleteobjects_coverage_test.go`
- **TestObjMiscDeleteObjectsIsBounded()** (5 connections) — `internal/proxy/handlers/object/deleteobjects_coverage_test.go`
- **TestObjMiscDeleteObjectsMalformedXMLIsRefused()** (5 connections) — `internal/proxy/handlers/object/deleteobjects_coverage_test.go`
- *... and 34 more nodes in this community*

## Relationships

- [Shutdown and Test Contexts](Shutdown_and_Test_Contexts.md) (45 shared connections)
- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (45 shared connections)
- [Object: Metadata Coverage Test](Object-_Metadata_Coverage_Test.md) (11 shared connections)
- [Object Checksum and Tagging Tests](Object_Checksum_and_Tagging_Tests.md) (3 shared connections)
- [Multipart Checksum Answers](Multipart_Checksum_Answers.md) (3 shared connections)
- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (3 shared connections)
- [Bucket Handler Tests](Bucket_Handler_Tests.md) (2 shared connections)
- [Request Middleware Plumbing](Request_Middleware_Plumbing.md) (2 shared connections)
- [Bucket XML Documents](Bucket_XML_Documents.md) (2 shared connections)
- [Monitoring: Server Coverage Test](Monitoring-_Server_Coverage_Test.md) (1 shared connections)
- [Object Checksum Agreement Tests](Object_Checksum_Agreement_Tests.md) (1 shared connections)
- [Health: Handler Coverage Test](Health-_Handler_Coverage_Test.md) (1 shared connections)

## Source Files

- `internal/proxy/handlers/object/deleteobjects_coverage_test.go`
- `internal/proxy/handlers/object/dispatch_coverage_test.go`
- `internal/proxy/handlers/object/metadata_coverage_test.go`
- `internal/proxy/handlers/root/listbuckets_coverage_test.go`

## Audit Trail

- EXTRACTED: 229 (83%)
- INFERRED: 48 (17%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*