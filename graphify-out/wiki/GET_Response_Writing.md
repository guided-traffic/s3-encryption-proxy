# GET Response Writing

> 33 nodes · cohesion 0.11

## Key Concepts

- **newEncryptingTestHandler()** (21 connections) — `internal/proxy/handlers/object/object_test.go`
- **newResponseTestHandler()** (16 connections) — `internal/proxy/handlers/object/object_test.go`
- **objCallAutoMultipart()** (15 connections) — `internal/proxy/handlers/object/object_test.go`
- **testPayload()** (13 connections) — `internal/proxy/handlers/object/object_test.go`
- **TestHandleGetObject_VersionIDAndResponseHeaders()** (7 connections) — `internal/proxy/handlers/object/object_test.go`
- **TestPutObjectAutoMultipart_StoredChainReadsBackAsPlaintext()** (7 connections) — `internal/proxy/handlers/object/object_test.go`
- **TestHandleHeadObject_VersionIDAndPlaintextLength()** (6 connections) — `internal/proxy/handlers/object/object_test.go`
- **TestPutObjectAutoMultipart_ExactMultipleOfThePartSizeKeepsTheTrailer()** (6 connections) — `internal/proxy/handlers/object/object_test.go`
- **TestPutObjectAutoMultipart_MetadataRidesOnCreateWithoutARewrite()** (6 connections) — `internal/proxy/handlers/object/object_test.go`
- **assertNoChecksumHeaders()** (5 connections) — `internal/proxy/handlers/object/object_test.go`
- **headerNames()** (5 connections) — `internal/proxy/handlers/object/object_test.go`
- **storeSegmentedObject()** (5 connections) — `internal/proxy/handlers/object/object_test.go`
- **TestPutObjectAutoMultipart_AbortOutlivesClientDisconnect()** (5 connections) — `internal/proxy/handlers/object/object_test.go`
- **TestPutObjectAutoMultipart_ATruncatedStreamIsNotCommitted()** (5 connections) — `internal/proxy/handlers/object/object_test.go`
- **TestPutObjectAutoMultipart_CompletedUploadIsNotSweptAgain()** (5 connections) — `internal/proxy/handlers/object/object_test.go`
- **TestPutObjectAutoMultipart_ConcurrencyIsTheConfiguredNumber()** (5 connections) — `internal/proxy/handlers/object/object_test.go`
- **TestPutObjectAutoMultipart_ShortBodyAbortsInsteadOfCommitting()** (5 connections) — `internal/proxy/handlers/object/object_test.go`
- **TestPutObjectAutoMultipart_ShutdownSweepSeesTheUpload()** (5 connections) — `internal/proxy/handlers/object/object_test.go`
- **TestWriteGetObjectResponse_EmitsOnlyTheAllowlist()** (5 connections) — `internal/proxy/handlers/object/object_test.go`
- **TestObjGetWriteGetObjectResponseMinimalOutput()** (4 connections) — `internal/proxy/handlers/object/getobject_coverage_test.go`
- **Handler** (4 connections)
- **TestUnimplementedObjectOperationsAnswer501()** (4 connections) — `internal/proxy/handlers/object/object_test.go`
- **TestWriteRangeResponse_EmitsVersionAndEntityHeaders()** (4 connections) — `internal/proxy/handlers/object/range_test.go`
- **TestObjGetWriteRangeError()** (4 connections) — `internal/proxy/handlers/object/rangeread_coverage_test.go`
- **TestObjGetWriteRangeResponseMinimal()** (4 connections) — `internal/proxy/handlers/object/rangeread_coverage_test.go`
- *... and 8 more nodes in this community*

## Relationships

- [Shutdown and Test Contexts](Shutdown_and_Test_Contexts.md) (26 shared connections)
- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (26 shared connections)
- [Object Checksum and Tagging Tests](Object_Checksum_and_Tagging_Tests.md) (10 shared connections)
- [Segment Codec and Range Planner](Segment_Codec_and_Range_Planner.md) (3 shared connections)
- [Request Middleware Plumbing](Request_Middleware_Plumbing.md) (2 shared connections)
- [Object: Metadata Coverage Test](Object-_Metadata_Coverage_Test.md) (2 shared connections)
- [Sub-Resource Handler Tests](Sub-Resource_Handler_Tests.md) (2 shared connections)
- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (2 shared connections)
- [Manager Tests](Manager_Tests.md) (1 shared connections)
- [Multipart Handlers and Manager](Multipart_Handlers_and_Manager.md) (1 shared connections)
- [Object: Storage Headers](Object-_Storage_Headers.md) (1 shared connections)
- [Velero E2E Suite](Velero_E2E_Suite.md) (1 shared connections)

## Source Files

- `internal/proxy/handlers/object/getobject_coverage_test.go`
- `internal/proxy/handlers/object/object_test.go`
- `internal/proxy/handlers/object/range_test.go`
- `internal/proxy/handlers/object/rangeread_coverage_test.go`

## Audit Trail

- EXTRACTED: 117 (87%)
- INFERRED: 18 (13%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*