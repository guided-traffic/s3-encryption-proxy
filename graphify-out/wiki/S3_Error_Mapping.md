# S3 Error Mapping

> 70 nodes · cohesion 0.06

## Key Concepts

- **MapError()** (26 connections) — `internal/proxy/response/error_mapping.go`
- **error_mapping_coverage_test.go** (22 connections) — `internal/proxy/response/error_mapping_coverage_test.go`
- **RespCapturingLogger()** (19 connections) — `internal/proxy/response/error_mapping_coverage_test.go`
- **response/error_mapping_test.go** (16 connections) — `internal/proxy/response/error_mapping_test.go`
- **xml_coverage_test.go** (16 connections) — `internal/proxy/response/xml_coverage_test.go`
- **sdkError()** (10 connections) — `internal/proxy/response/error_mapping_test.go`
- **RespFindEntry()** (9 connections) — `internal/proxy/response/error_mapping_coverage_test.go`
- **discardLogger()** (9 connections) — `internal/proxy/response/error_mapping_test.go`
- **errors_test.go** (8 connections) — `internal/proxy/response/errors_test.go`
- **RespNewFailingWriter()** (7 connections) — `internal/proxy/response/error_mapping_coverage_test.go`
- **RespStatusOnlyError()** (7 connections) — `internal/proxy/response/error_mapping_coverage_test.go`
- **TestRespWriteErrorDocumentSurvivesFailedWrite()** (7 connections) — `internal/proxy/response/error_mapping_coverage_test.go`
- **TestRespWriteS3ErrorLogLevels()** (7 connections) — `internal/proxy/response/error_mapping_coverage_test.go`
- **TestRespWriteS3ErrorSurvivesFailedWrite()** (7 connections) — `internal/proxy/response/error_mapping_coverage_test.go`
- **TestMapError_NeverProducesInvalidStatus()** (6 connections) — `internal/proxy/response/error_mapping_test.go`
- **TestErrorWriter_ControlCharacterStaysWellFormed()** (6 connections) — `internal/proxy/response/errors_test.go`
- **TestErrorWriter_HostileInputStaysWellFormedXML()** (6 connections) — `internal/proxy/response/errors_test.go`
- **TestRespWriteXMLLogsWriteFailure()** (6 connections) — `internal/proxy/response/xml_coverage_test.go`
- **RespFailingWriter** (6 connections) — `internal/proxy/response/error_mapping_coverage_test.go`
- **TestRespWriteS3ErrorNilErrorLogsNoDetail()** (5 connections) — `internal/proxy/response/error_mapping_coverage_test.go`
- **TestWriteS3Error_BucketOnlyResource()** (5 connections) — `internal/proxy/response/error_mapping_test.go`
- **TestWriteS3Error_ResponseDocument()** (5 connections) — `internal/proxy/response/error_mapping_test.go`
- **decodeErrorDocument()** (5 connections) — `internal/proxy/response/errors_test.go`
- **TestRespWriteXMLCommitsStatusBeforeMarshalCanFail()** (5 connections) — `internal/proxy/response/xml_coverage_test.go`
- **RespAPIErrorNoResponse()** (4 connections) — `internal/proxy/response/error_mapping_coverage_test.go`
- *... and 45 more nodes in this community*

## Relationships

- [Config Accessor Tests](Config_Accessor_Tests.md) (49 shared connections)
- [Bucket Sub-Resource Tests](Bucket_Sub-Resource_Tests.md) (27 shared connections)
- [Multipart Handler Tests](Multipart_Handler_Tests.md) (4 shared connections)
- [Multipart Handler Construction](Multipart_Handler_Construction.md) (2 shared connections)
- [License Logging](License_Logging.md) (2 shared connections)
- [Object Header Conformance Tests](Object_Header_Conformance_Tests.md) (2 shared connections)
- [Proxy Utils Tests](Proxy_Utils_Tests.md) (1 shared connections)
- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (1 shared connections)
- [SigV4 Pre-Signed URL Auth](SigV4_Pre-Signed_URL_Auth.md) (1 shared connections)

## Source Files

- `internal/proxy/response/error_mapping.go`
- `internal/proxy/response/error_mapping_coverage_test.go`
- `internal/proxy/response/error_mapping_test.go`
- `internal/proxy/response/errors_test.go`
- `internal/proxy/response/xml_coverage_test.go`

## Audit Trail

- EXTRACTED: 166 (71%)
- INFERRED: 68 (29%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*