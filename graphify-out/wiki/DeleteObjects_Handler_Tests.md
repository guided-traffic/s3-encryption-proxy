# DeleteObjects Handler Tests

> 86 nodes · cohesion 0.06

## Key Concepts

- **ObjMiscnewHandler()** (48 connections) — `internal/proxy/handlers/object/dispatch_coverage_test.go`
- **deleteobjects_coverage_test.go** (28 connections) — `internal/proxy/handlers/object/deleteobjects_coverage_test.go`
- **dispatch_coverage_test.go** (26 connections) — `internal/proxy/handlers/object/dispatch_coverage_test.go`
- **object/metadata_coverage_test.go** (20 connections) — `internal/proxy/handlers/object/metadata_coverage_test.go`
- **ObjMiscdeleteObjects()** (19 connections) — `internal/proxy/handlers/object/deleteobjects_coverage_test.go`
- **ObjMiscdo()** (19 connections) — `internal/proxy/handlers/object/dispatch_coverage_test.go`
- **ObjMiscdoFunc()** (17 connections) — `internal/proxy/handlers/object/dispatch_coverage_test.go`
- **ObjMiscparseError()** (17 connections) — `internal/proxy/handlers/object/dispatch_coverage_test.go`
- **net/http/httptest.ResponseRecorder** (16 connections)
- **ObjMiscassertNotImplemented()** (14 connections) — `internal/proxy/handlers/object/dispatch_coverage_test.go`
- **ObjMiscnewHandlerWithPrefix()** (11 connections) — `internal/proxy/handlers/object/dispatch_coverage_test.go`
- **copyWithPooledBuffer()** (9 connections) — `internal/proxy/handlers/object/helpers.go`
- **ObjMiscbodyDigest()** (8 connections) — `internal/proxy/handlers/object/deleteobjects_coverage_test.go`
- **ObjMiscparseDeleteResult()** (8 connections) — `internal/proxy/handlers/object/deleteobjects_coverage_test.go`
- **TestObjMiscUnmatchedMetadataPrefixRefusesInsteadOfLeaking()** (8 connections) — `internal/proxy/handlers/object/metadata_coverage_test.go`
- **TestObjMiscVersionIDReachesHeadAndGet()** (8 connections) — `internal/proxy/handlers/object/metadata_coverage_test.go`
- **TestObjMiscDefaultPrefixFiltersMetadataAndReturnsPlaintext()** (7 connections) — `internal/proxy/handlers/object/metadata_coverage_test.go`
- **TestObjMiscDeleteObjectsBodyReadErrorIsRefused()** (6 connections) — `internal/proxy/handlers/object/deleteobjects_coverage_test.go`
- **TestObjMiscDeleteObjectsEmptyDocumentIsRefused()** (6 connections) — `internal/proxy/handlers/object/deleteobjects_coverage_test.go`
- **TestObjMiscDeleteObjectsHappyPath()** (6 connections) — `internal/proxy/handlers/object/deleteobjects_coverage_test.go`
- **TestObjMiscDeleteObjectsMalformedXMLIsRefused()** (6 connections) — `internal/proxy/handlers/object/deleteobjects_coverage_test.go`
- **TestObjMiscDeleteObjectsWithoutMuxVars()** (6 connections) — `internal/proxy/handlers/object/deleteobjects_coverage_test.go`
- **TestObjMiscDeletePathsCarryTheOwnerGuardAndDropTheRest()** (6 connections) — `internal/proxy/handlers/object/deleteobjects_coverage_test.go`
- **ObjMiscsealed()** (6 connections) — `internal/proxy/handlers/object/dispatch_coverage_test.go`
- **TestObjMiscHandleDispatchesEachMethodToItsOwnBackendCall()** (6 connections) — `internal/proxy/handlers/object/dispatch_coverage_test.go`
- *... and 61 more nodes in this community*

## Relationships

- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (56 shared connections)
- [Object GET Coverage Tests](Object_GET_Coverage_Tests.md) (6 shared connections)
- [Response Header Helpers](Response_Header_Helpers.md) (6 shared connections)
- [ListBuckets Root Handler](ListBuckets_Root_Handler.md) (3 shared connections)
- [Replication and ACL Handlers](Replication_and_ACL_Handlers.md) (3 shared connections)
- [XML Document Marshalling](XML_Document_Marshalling.md) (3 shared connections)
- [Bucket Handler Error Fixtures](Bucket_Handler_Error_Fixtures.md) (2 shared connections)
- [Multipart Handler Coverage Tests](Multipart_Handler_Coverage_Tests.md) (2 shared connections)
- [S3 Method Error Mapping Tests](S3_Method_Error_Mapping_Tests.md) (2 shared connections)
- [Monitoring HTTP Server](Monitoring_HTTP_Server.md) (1 shared connections)
- [Checksum and ETag Echo Tests](Checksum_and_ETag_Echo_Tests.md) (1 shared connections)
- [Multipart](Multipart.md) (1 shared connections)

## Source Files

- `internal/proxy/handlers/object/deleteobjects_coverage_test.go`
- `internal/proxy/handlers/object/dispatch_coverage_test.go`
- `internal/proxy/handlers/object/helpers.go`
- `internal/proxy/handlers/object/metadata_coverage_test.go`

## Audit Trail

- EXTRACTED: 269 (81%)
- INFERRED: 62 (19%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*