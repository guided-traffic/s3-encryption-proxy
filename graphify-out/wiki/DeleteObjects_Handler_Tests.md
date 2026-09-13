# DeleteObjects Handler Tests

> 25 nodes · cohesion 0.14

## Key Concepts

- **deleteobjects_coverage_test.go** (25 connections) — `internal/proxy/handlers/object/deleteobjects_coverage_test.go`
- **ObjMiscdeleteObjects()** (17 connections) — `internal/proxy/handlers/object/deleteobjects_coverage_test.go`
- **ObjMiscparseDeleteResult()** (8 connections) — `internal/proxy/handlers/object/deleteobjects_coverage_test.go`
- **TestObjMiscDeleteObjectsHappyPath()** (6 connections) — `internal/proxy/handlers/object/deleteobjects_coverage_test.go`
- **ObjMiscfailWriter** (6 connections) — `internal/proxy/handlers/object/deleteobjects_coverage_test.go`
- **TestObjMiscDeleteObjectsEscapesKeysInTheResponse()** (5 connections) — `internal/proxy/handlers/object/deleteobjects_coverage_test.go`
- **TestObjMiscDeleteObjectsForwardsPerObjectVersionID()** (5 connections) — `internal/proxy/handlers/object/deleteobjects_coverage_test.go`
- **TestObjMiscDeleteObjectsPartialFailureIsReported()** (5 connections) — `internal/proxy/handlers/object/deleteobjects_coverage_test.go`
- **TestObjMiscDeleteObjectsQuietAnswerListsNothing()** (5 connections) — `internal/proxy/handlers/object/deleteobjects_coverage_test.go`
- **TestObjMiscDeleteObjectsAcceptsAnObjectWithoutAKey()** (4 connections) — `internal/proxy/handlers/object/deleteobjects_coverage_test.go`
- **TestObjMiscDeleteObjectsDoesNotEnforceTheThousandKeyLimit()** (4 connections) — `internal/proxy/handlers/object/deleteobjects_coverage_test.go`
- **TestObjMiscDeleteObjectsEmptyDocumentReachesTheBackend()** (4 connections) — `internal/proxy/handlers/object/deleteobjects_coverage_test.go`
- **TestObjMiscDeleteObjectsQuietFlagIsForwarded()** (4 connections) — `internal/proxy/handlers/object/deleteobjects_coverage_test.go`
- **TestObjMiscDeleteObjectsResponseHasNoS3Namespace()** (4 connections) — `internal/proxy/handlers/object/deleteobjects_coverage_test.go`
- **TestObjMiscDeleteObjectsSurvivesAFailingResponseWriter()** (4 connections) — `internal/proxy/handlers/object/deleteobjects_coverage_test.go`
- **.Header()** (4 connections) — `internal/proxy/handlers/object/deleteobjects_coverage_test.go`
- **ObjMiscnewFailWriter()** (3 connections) — `internal/proxy/handlers/object/deleteobjects_coverage_test.go`
- **ObjMiscdeleteResult** (3 connections) — `internal/proxy/handlers/object/deleteobjects_coverage_test.go`
- **ObjMiscerrReader** (3 connections) — `internal/proxy/handlers/object/deleteobjects_coverage_test.go`
- **TestObjMiscErrReaderReturnsItsError()** (2 connections) — `internal/proxy/handlers/object/deleteobjects_coverage_test.go`
- **Handler** (1 connections)
- **.Close()** (1 connections) — `internal/proxy/handlers/object/deleteobjects_coverage_test.go`
- **.Read()** (1 connections) — `internal/proxy/handlers/object/deleteobjects_coverage_test.go`
- **.Write()** (1 connections) — `internal/proxy/handlers/object/deleteobjects_coverage_test.go`
- **.WriteHeader()** (1 connections) — `internal/proxy/handlers/object/deleteobjects_coverage_test.go`

## Relationships

- [Object Dispatch and Metadata Tests](Object_Dispatch_and_Metadata_Tests.md) (24 shared connections)
- [Config Env Expansion](Config_Env_Expansion.md) (13 shared connections)
- [Object Header Conformance](Object_Header_Conformance.md) (2 shared connections)
- [Multipart XML Documents](Multipart_XML_Documents.md) (1 shared connections)

## Source Files

- `internal/proxy/handlers/object/deleteobjects_coverage_test.go`

## Audit Trail

- EXTRACTED: 71 (86%)
- INFERRED: 12 (14%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*