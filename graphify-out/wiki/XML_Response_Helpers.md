# XML Response Helpers

> 26 nodes · cohesion 0.17

## Key Concepts

- **NewXMLWriter()** (61 connections) — `internal/proxy/response/xml.go`
- **RespCapturingLogger()** (18 connections) — `internal/proxy/response/error_mapping_coverage_test.go`
- **xml_coverage_test.go** (15 connections) — `internal/proxy/response/xml_coverage_test.go`
- **RespFindEntry()** (9 connections) — `internal/proxy/response/error_mapping_coverage_test.go`
- **RespNewFailingWriter()** (7 connections) — `internal/proxy/response/error_mapping_coverage_test.go`
- **TestRespWriteErrorDocumentSurvivesFailedWrite()** (7 connections) — `internal/proxy/response/error_mapping_coverage_test.go`
- **TestRespWriteS3ErrorLogLevels()** (7 connections) — `internal/proxy/response/error_mapping_coverage_test.go`
- **TestRespWriteS3ErrorSurvivesFailedWrite()** (7 connections) — `internal/proxy/response/error_mapping_coverage_test.go`
- **TestRespWriteXMLLogsWriteFailure()** (6 connections) — `internal/proxy/response/xml_coverage_test.go`
- **RespFailingWriter** (6 connections) — `internal/proxy/response/error_mapping_coverage_test.go`
- **TestRespWriteS3ErrorNilErrorLogsNoDetail()** (5 connections) — `internal/proxy/response/error_mapping_coverage_test.go`
- **TestRespWriteXMLCommitsStatusBeforeMarshalCanFail()** (5 connections) — `internal/proxy/response/xml_coverage_test.go`
- **TestRespNewXMLWriter()** (4 connections) — `internal/proxy/response/xml_coverage_test.go`
- **TestRespWriteRawXML()** (4 connections) — `internal/proxy/response/xml_coverage_test.go`
- **TestRespWriteRawXMLDoesNotEscape()** (4 connections) — `internal/proxy/response/xml_coverage_test.go`
- **TestRespWriteRawXMLLargeBodyIsByteExact()** (4 connections) — `internal/proxy/response/xml_coverage_test.go`
- **TestRespWriteXML()** (4 connections) — `internal/proxy/response/xml_coverage_test.go`
- **TestRespWriteXMLEscapesMarkup()** (4 connections) — `internal/proxy/response/xml_coverage_test.go`
- **TestRespWriteXMLHasNoXMLDeclaration()** (4 connections) — `internal/proxy/response/xml_coverage_test.go`
- **TestRespWriteXMLNilPayload()** (4 connections) — `internal/proxy/response/xml_coverage_test.go`
- **TestRespWriteXMLUsesGoTypeNameWithoutXMLName()** (4 connections) — `internal/proxy/response/xml_coverage_test.go`
- **.Header()** (3 connections) — `internal/proxy/response/error_mapping_coverage_test.go`
- **response/xml.go** (2 connections) — `internal/proxy/response/xml.go`
- **.Write()** (1 connections) — `internal/proxy/response/error_mapping_coverage_test.go`
- **.WriteHeader()** (1 connections) — `internal/proxy/response/error_mapping_coverage_test.go`
- *... and 1 more nodes in this community*

## Relationships

- [Bucket NotImplemented Tests](Bucket_NotImplemented_Tests.md) (19 shared connections)
- [Config Env Expansion](Config_Env_Expansion.md) (16 shared connections)
- [Backend Error Mapping](Backend_Error_Mapping.md) (10 shared connections)
- [Multipart Handler](Multipart_Handler.md) (7 shared connections)
- [Bucket Website Handler](Bucket_Website_Handler.md) (6 shared connections)
- [Bucket Notification Handler](Bucket_Notification_Handler.md) (5 shared connections)
- [Bucket Replication Handler](Bucket_Replication_Handler.md) (5 shared connections)
- [Error Response Tests](Error_Response_Tests.md) (4 shared connections)
- [Bucket Versioning Handler](Bucket_Versioning_Handler.md) (4 shared connections)
- [Multipart XML Documents](Multipart_XML_Documents.md) (3 shared connections)
- [Bucket CRUD Tests](Bucket_CRUD_Tests.md) (3 shared connections)
- [License Logging](License_Logging.md) (2 shared connections)

## Source Files

- `internal/proxy/response/error_mapping_coverage_test.go`
- `internal/proxy/response/xml.go`
- `internal/proxy/response/xml_coverage_test.go`

## Audit Trail

- EXTRACTED: 114 (80%)
- INFERRED: 29 (20%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*