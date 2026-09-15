# S3 Error Document Writer

> 22 nodes · cohesion 0.24

## Key Concepts

- **errors_coverage_test.go** (16 connections) — `internal/proxy/response/errors_coverage_test.go`
- **UtlCaptureLogger()** (12 connections) — `internal/proxy/response/errors_coverage_test.go`
- **UtlDecodeLog()** (10 connections) — `internal/proxy/response/errors_coverage_test.go`
- **UtlParseErrorBody()** (10 connections) — `internal/proxy/response/errors_coverage_test.go`
- **TestRespWriteS3Error_DoesNotLeakBackendDetail()** (8 connections) — `internal/proxy/response/errors_coverage_test.go`
- **TestRespWriteS3Error_StatusDrivesLogLevel()** (8 connections) — `internal/proxy/response/errors_coverage_test.go`
- **UtlFindLog()** (8 connections) — `internal/proxy/response/errors_coverage_test.go`
- **TestRespWriteS3Error_InternalTextStaysInternal()** (7 connections) — `internal/proxy/response/errors_coverage_test.go`
- **TestRespWriteS3Error_NilError()** (7 connections) — `internal/proxy/response/errors_coverage_test.go`
- **TestRespWriteS3Error_ResourceComposition()** (7 connections) — `internal/proxy/response/errors_coverage_test.go`
- **TestRespWriteS3Error_WriteFailureIsLogged()** (7 connections) — `internal/proxy/response/errors_coverage_test.go`
- **TestRespErrorDocumentCarriesTheResponseRequestID()** (6 connections) — `internal/proxy/response/errors_coverage_test.go`
- **UtlFailingWriter** (6 connections) — `internal/proxy/response/errors_coverage_test.go`
- **TestRespWriteS3Error_EscapesResource()** (5 connections) — `internal/proxy/response/errors_coverage_test.go`
- **s3Error** (4 connections) — `internal/proxy/response/errors.go`
- **errors.go** (3 connections) — `internal/proxy/response/errors.go`
- **UtlNewFailingWriter()** (3 connections) — `internal/proxy/response/errors_coverage_test.go`
- **UtlSDKError()** (3 connections) — `internal/proxy/response/errors_coverage_test.go`
- **.Header()** (3 connections) — `internal/proxy/response/errors_coverage_test.go`
- **UtlLogEntry** (3 connections) — `internal/proxy/response/errors_coverage_test.go`
- **.Write()** (1 connections) — `internal/proxy/response/errors_coverage_test.go`
- **.WriteHeader()** (1 connections) — `internal/proxy/response/errors_coverage_test.go`

## Relationships

- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (10 shared connections)
- [Copy and Delete Object Handlers](Copy_and_Delete_Object_Handlers.md) (9 shared connections)
- [Exec](Exec.md) (2 shared connections)
- [S3 Method Error Mapping Tests](S3_Method_Error_Mapping_Tests.md) (2 shared connections)
- [Multipart Handler Constructors](Multipart_Handler_Constructors.md) (1 shared connections)
- [Object GET Coverage Tests](Object_GET_Coverage_Tests.md) (1 shared connections)
- [SigV4 Service Coverage Tests](SigV4_Service_Coverage_Tests.md) (1 shared connections)
- [XML Document Marshalling](XML_Document_Marshalling.md) (1 shared connections)
- [Bucket Website and Create/Delete](Bucket_Website_and_Create-Delete.md) (1 shared connections)

## Source Files

- `internal/proxy/response/errors.go`
- `internal/proxy/response/errors_coverage_test.go`

## Audit Trail

- EXTRACTED: 75 (90%)
- INFERRED: 8 (10%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*