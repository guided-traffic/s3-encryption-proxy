# DeleteObjects Coverage Tests

> 34 nodes · cohesion 0.13

## Key Concepts

- **deleteobjects_coverage_test.go** (28 connections) — `internal/proxy/handlers/object/deleteobjects_coverage_test.go`
- **ObjMiscdeleteObjects()** (19 connections) — `internal/proxy/handlers/object/deleteobjects_coverage_test.go`
- **ObjMiscparseError()** (17 connections) — `internal/proxy/handlers/object/dispatch_coverage_test.go`
- **ObjMiscbodyDigest()** (8 connections) — `internal/proxy/handlers/object/deleteobjects_coverage_test.go`
- **ObjMiscparseDeleteResult()** (8 connections) — `internal/proxy/handlers/object/deleteobjects_coverage_test.go`
- **TestObjMiscDeleteObjectsBodyReadErrorIsRefused()** (6 connections) — `internal/proxy/handlers/object/deleteobjects_coverage_test.go`
- **TestObjMiscDeleteObjectsEmptyDocumentIsRefused()** (6 connections) — `internal/proxy/handlers/object/deleteobjects_coverage_test.go`
- **TestObjMiscDeleteObjectsHappyPath()** (6 connections) — `internal/proxy/handlers/object/deleteobjects_coverage_test.go`
- **TestObjMiscDeleteObjectsMalformedXMLIsRefused()** (6 connections) — `internal/proxy/handlers/object/deleteobjects_coverage_test.go`
- **TestObjMiscDeleteObjectsWithoutMuxVars()** (6 connections) — `internal/proxy/handlers/object/deleteobjects_coverage_test.go`
- **TestObjMiscDeletePathsCarryTheOwnerGuardAndDropTheRest()** (6 connections) — `internal/proxy/handlers/object/deleteobjects_coverage_test.go`
- **ObjMiscfailWriter** (6 connections) — `internal/proxy/handlers/object/deleteobjects_coverage_test.go`
- **TestObjMiscDeleteObjectsBackendErrorsAreMapped()** (5 connections) — `internal/proxy/handlers/object/deleteobjects_coverage_test.go`
- **TestObjMiscDeleteObjectsEmptyBodyIsMalformed()** (5 connections) — `internal/proxy/handlers/object/deleteobjects_coverage_test.go`
- **TestObjMiscDeleteObjectsEscapesKeysInTheResponse()** (5 connections) — `internal/proxy/handlers/object/deleteobjects_coverage_test.go`
- **TestObjMiscDeleteObjectsForwardsPerObjectVersionID()** (5 connections) — `internal/proxy/handlers/object/deleteobjects_coverage_test.go`
- **TestObjMiscDeleteObjectsIsBounded()** (5 connections) — `internal/proxy/handlers/object/deleteobjects_coverage_test.go`
- **TestObjMiscDeleteObjectsObjectWithoutAKeyIsRefused()** (5 connections) — `internal/proxy/handlers/object/deleteobjects_coverage_test.go`
- **TestObjMiscDeleteObjectsPartialFailureIsReported()** (5 connections) — `internal/proxy/handlers/object/deleteobjects_coverage_test.go`
- **TestObjMiscDeleteObjectsQuietAnswerListsNothing()** (5 connections) — `internal/proxy/handlers/object/deleteobjects_coverage_test.go`
- **TestObjMiscDeleteObjectsReadsTheWholeBodyUnbounded()** (5 connections) — `internal/proxy/handlers/object/deleteobjects_coverage_test.go`
- **TestObjMiscDeleteObjectsRefusesAboveTheThousandKeyLimit()** (5 connections) — `internal/proxy/handlers/object/deleteobjects_coverage_test.go`
- **TestObjMiscDeleteObjectsSurvivesAFailingResponseWriter()** (5 connections) — `internal/proxy/handlers/object/deleteobjects_coverage_test.go`
- **TestObjMiscObjectSubResourceWritesAreBounded()** (5 connections) — `internal/proxy/handlers/object/deleteobjects_coverage_test.go`
- **.Header()** (5 connections) — `internal/proxy/handlers/object/deleteobjects_coverage_test.go`
- *... and 9 more nodes in this community*

## Relationships

- [Object Dispatch Coverage Tests](Object_Dispatch_Coverage_Tests.md) (34 shared connections)
- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (23 shared connections)
- [XML Document Marshalling](XML_Document_Marshalling.md) (2 shared connections)
- [Integration Failing Writer Fixtures](Integration_Failing_Writer_Fixtures.md) (2 shared connections)
- [Object Error Reader Stub](Object_Error_Reader_Stub.md) (1 shared connections)
- [Bucket ACL and Accelerate Handlers](Bucket_ACL_and_Accelerate_Handlers.md) (1 shared connections)

## Source Files

- `internal/proxy/handlers/object/deleteobjects_coverage_test.go`
- `internal/proxy/handlers/object/dispatch_coverage_test.go`

## Audit Trail

- EXTRACTED: 99 (73%)
- INFERRED: 37 (27%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*