# Response: Error Mapping Coverage Test

> 9 nodes · cohesion 0.42

## Key Concepts

- **RespCapturingLogger()** (9 connections) — `internal/proxy/response/error_mapping_coverage_test.go`
- **RespFindEntry()** (8 connections) — `internal/proxy/response/error_mapping_coverage_test.go`
- **RespNewFailingWriter()** (7 connections) — `internal/proxy/response/error_mapping_coverage_test.go`
- **TestRespWriteS3ErrorLogLevels()** (7 connections) — `internal/proxy/response/error_mapping_coverage_test.go`
- **TestRespWriteS3ErrorSurvivesFailedWrite()** (7 connections) — `internal/proxy/response/error_mapping_coverage_test.go`
- **TestRespWriteErrorDocumentSurvivesFailedWrite()** (6 connections) — `internal/proxy/response/error_mapping_coverage_test.go`
- **TestRespWriteS3Document()** (6 connections) — `internal/proxy/response/xml_coverage_test.go`
- **TestRespWriteS3ErrorNilErrorLogsNoDetail()** (5 connections) — `internal/proxy/response/error_mapping_coverage_test.go`
- **TestRespNewXMLWriter()** (4 connections) — `internal/proxy/response/xml_coverage_test.go`

## Relationships

- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (9 shared connections)
- [Shutdown and Test Contexts](Shutdown_and_Test_Contexts.md) (7 shared connections)
- [Sub-Resource Handler Tests](Sub-Resource_Handler_Tests.md) (6 shared connections)
- [Multipart Handlers and Manager](Multipart_Handlers_and_Manager.md) (2 shared connections)
- [Object Checksum and Tagging Tests](Object_Checksum_and_Tagging_Tests.md) (2 shared connections)
- [Error Mapping](Error_Mapping.md) (2 shared connections)
- [Request Middleware Plumbing](Request_Middleware_Plumbing.md) (1 shared connections)

## Source Files

- `internal/proxy/response/error_mapping_coverage_test.go`
- `internal/proxy/response/xml_coverage_test.go`

## Audit Trail

- EXTRACTED: 34 (77%)
- INFERRED: 10 (23%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*