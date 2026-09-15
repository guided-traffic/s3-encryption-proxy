# Error Mapping Coverage Tests

> 27 nodes · cohesion 0.15

## Key Concepts

- **error_mapping_coverage_test.go** (22 connections) — `internal/proxy/response/error_mapping_coverage_test.go`
- **RespCapturingLogger()** (9 connections) — `internal/proxy/response/error_mapping_coverage_test.go`
- **RespFindEntry()** (8 connections) — `internal/proxy/response/error_mapping_coverage_test.go`
- **RespNewFailingWriter()** (7 connections) — `internal/proxy/response/error_mapping_coverage_test.go`
- **RespStatusOnlyError()** (7 connections) — `internal/proxy/response/error_mapping_coverage_test.go`
- **TestRespWriteErrorDocumentSurvivesFailedWrite()** (7 connections) — `internal/proxy/response/error_mapping_coverage_test.go`
- **TestRespWriteS3ErrorLogLevels()** (7 connections) — `internal/proxy/response/error_mapping_coverage_test.go`
- **TestRespWriteS3ErrorSurvivesFailedWrite()** (7 connections) — `internal/proxy/response/error_mapping_coverage_test.go`
- **TestRespWriteS3Document()** (6 connections) — `internal/proxy/response/xml_coverage_test.go`
- **RespFailingWriter** (6 connections) — `internal/proxy/response/error_mapping_coverage_test.go`
- **TestRespWriteS3ErrorNilErrorLogsNoDetail()** (5 connections) — `internal/proxy/response/error_mapping_coverage_test.go`
- **RespAPIErrorNoResponse()** (4 connections) — `internal/proxy/response/error_mapping_coverage_test.go`
- **TestRespMapErrorBackend5xxKeepsReasonPhrase()** (4 connections) — `internal/proxy/response/error_mapping_coverage_test.go`
- **TestRespMapErrorCodeForStatusFallback()** (4 connections) — `internal/proxy/response/error_mapping_coverage_test.go`
- **TestRespMapErrorCodeStatusTableMatchesAWS()** (4 connections) — `internal/proxy/response/error_mapping_coverage_test.go`
- **TestRespMapErrorEmptyMessageFallback()** (4 connections) — `internal/proxy/response/error_mapping_coverage_test.go`
- **TestRespMapErrorMarkerPrecedenceIsTextual()** (4 connections) — `internal/proxy/response/error_mapping_coverage_test.go`
- **TestRespMapErrorNonErrorStatusesBecome500()** (4 connections) — `internal/proxy/response/error_mapping_coverage_test.go`
- **TestRespMapErrorNotModifiedIsForwarded()** (4 connections) — `internal/proxy/response/error_mapping_coverage_test.go`
- **TestRespMapErrorUnknownCodeWithoutResponseIs500()** (4 connections) — `internal/proxy/response/error_mapping_coverage_test.go`
- **TestRespMapErrorEmptyCodeWithoutResponseStaysOpaque()** (3 connections) — `internal/proxy/response/error_mapping_coverage_test.go`
- **TestRespMapErrorEmptyCodeWithResponseStatus()** (3 connections) — `internal/proxy/response/error_mapping_coverage_test.go`
- **TestRespMapErrorResponseStatusBeatsTable()** (3 connections) — `internal/proxy/response/error_mapping_coverage_test.go`
- **.Header()** (3 connections) — `internal/proxy/response/error_mapping_coverage_test.go`
- **RespWrapMarker()** (2 connections) — `internal/proxy/response/error_mapping_coverage_test.go`
- *... and 2 more nodes in this community*

## Relationships

- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (17 shared connections)
- [S3 Error Mapping](S3_Error_Mapping.md) (11 shared connections)
- [Copy and Delete Object Handlers](Copy_and_Delete_Object_Handlers.md) (4 shared connections)
- [Multipart Handler Constructors](Multipart_Handler_Constructors.md) (2 shared connections)
- [Object GET Coverage Tests](Object_GET_Coverage_Tests.md) (2 shared connections)
- [XML Document Marshalling](XML_Document_Marshalling.md) (2 shared connections)
- [S3 Method Error Mapping Tests](S3_Method_Error_Mapping_Tests.md) (2 shared connections)
- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (1 shared connections)

## Source Files

- `internal/proxy/response/error_mapping_coverage_test.go`
- `internal/proxy/response/xml_coverage_test.go`

## Audit Trail

- EXTRACTED: 72 (78%)
- INFERRED: 20 (22%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*