# Request Middleware Plumbing

> 62 nodes · cohesion 0.06

## Key Concepts

- **object_headers_conformance_test.go** (42 connections) — `test/integration/s3-methods/object_headers_conformance_test.go`
- **net/http.Header** (37 connections)
- **HdrNewDirectBucket()** (14 connections) — `test/integration/s3-methods/object_headers_conformance_test.go`
- **TestHdrETagIsPresentAndStableAcrossRepeatedHeads()** (12 connections) — `test/integration/s3-methods/object_headers_conformance_test.go`
- **TestHdrHeadReturnsTheSameHeaderSetAsGet()** (12 connections) — `test/integration/s3-methods/object_headers_conformance_test.go`
- **HdrGetHeaders()** (11 connections) — `test/integration/s3-methods/object_headers_conformance_test.go`
- **HdrHeadHeaders()** (11 connections) — `test/integration/s3-methods/object_headers_conformance_test.go`
- **TestHdrUserMetadataRoundTripsLikeTheBackend()** (11 connections) — `test/integration/s3-methods/object_headers_conformance_test.go`
- **TestHdrEncryptionMetadataIsNeverVisibleToTheClient()** (10 connections) — `test/integration/s3-methods/object_headers_conformance_test.go`
- **TestHdrEntityHeadersSurvivePutGetAndHead()** (10 connections) — `test/integration/s3-methods/object_headers_conformance_test.go`
- **HdrPutWithEntityHeaders()** (9 connections) — `test/integration/s3-methods/object_headers_conformance_test.go`
- **TestHdrStorageHeadersReachTheBackend()** (8 connections) — `test/integration/s3-methods/object_headers_conformance_test.go`
- **TestHdrSequentialWhitespaceInASignedHeaderIsAccepted()** (7 connections) — `test/integration/s3-methods/object_headers_conformance_test.go`
- **MwFlushErrorWriter** (6 connections) — `internal/proxy/middleware/http_middleware_coverage_test.go`
- **MonFlushErrorWriter** (6 connections) — `internal/monitoring/middleware_coverage_test.go`
- **ObjMiscfailWriter** (6 connections) — `internal/proxy/handlers/object/deleteobjects_coverage_test.go`
- **UtlFailingWriter** (6 connections) — `internal/proxy/response/errors_coverage_test.go`
- **HdrCleanupBucket()** (6 connections) — `test/integration/s3-methods/object_headers_conformance_test.go`
- **HdrObjectHeaderNames()** (6 connections) — `test/integration/s3-methods/object_headers_conformance_test.go`
- **BktfailingWriter** (5 connections) — `internal/proxy/handlers/bucket/operations_coverage_test.go`
- **MpuFailingWriter** (5 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **ObjIntfailingWriter** (5 connections) — `internal/proxy/handlers/object/integrity_report_test.go`
- **HdrCaptureResponseHeaders()** (5 connections) — `test/integration/s3-methods/object_headers_conformance_test.go`
- **HdrUserMetadata()** (5 connections) — `test/integration/s3-methods/object_headers_conformance_test.go`
- **github.com/aws/aws-sdk-go-v2/service/s3.Options** (4 connections)
- *... and 37 more nodes in this community*

## Relationships

- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (27 shared connections)
- [Chunked Encoding Tests](Chunked_Encoding_Tests.md) (21 shared connections)
- [Shutdown and Test Contexts](Shutdown_and_Test_Contexts.md) (14 shared connections)
- [Delete and Checksum Integration](Delete_and_Checksum_Integration.md) (8 shared connections)
- [Streaming Integration Helpers](Streaming_Integration_Helpers.md) (7 shared connections)
- [Misc (15)](Misc_15.md) (4 shared connections)
- [Encryption At Rest Tests](Encryption_At_Rest_Tests.md) (3 shared connections)
- [Health: Handler Coverage Test](Health-_Handler_Coverage_Test.md) (2 shared connections)
- [Monitoring: Server Coverage Test](Monitoring-_Server_Coverage_Test.md) (2 shared connections)
- [Response: Error Mapping Coverage Test](Response-_Error_Mapping_Coverage_Test.md) (2 shared connections)
- [Keyencryption: Aes Test](Keyencryption-_Aes_Test.md) (2 shared connections)
- [Object Checksum and Tagging Tests](Object_Checksum_and_Tagging_Tests.md) (2 shared connections)

## Source Files

- `internal/monitoring/middleware_coverage_test.go`
- `internal/proxy/handlers/bucket/operations_coverage_test.go`
- `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- `internal/proxy/handlers/object/deleteobjects_coverage_test.go`
- `internal/proxy/handlers/object/integrity_report_test.go`
- `internal/proxy/middleware/http_middleware_coverage_test.go`
- `internal/proxy/response/errors_coverage_test.go`
- `test/integration/s3-methods/object_headers_conformance_test.go`

## Audit Trail

- EXTRACTED: 209 (97%)
- INFERRED: 6 (3%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*