# S3 Error Document Writer

> 20 nodes · cohesion 0.28

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
- **UtlNewFailingWriter()** (3 connections) — `internal/proxy/response/errors_coverage_test.go`
- **UtlSDKError()** (3 connections) — `internal/proxy/response/errors_coverage_test.go`
- **.Header()** (3 connections) — `internal/proxy/response/errors_coverage_test.go`
- **UtlLogEntry** (3 connections) — `internal/proxy/response/errors_coverage_test.go`
- **.Write()** (1 connections) — `internal/proxy/response/errors_coverage_test.go`
- **.WriteHeader()** (1 connections) — `internal/proxy/response/errors_coverage_test.go`

## Relationships

- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (10 shared connections)
- [Copy and Delete Object Handlers](Copy_and_Delete_Object_Handlers.md) (8 shared connections)
- [Exec](Exec.md) (2 shared connections)
- [Integration Failing Writer Fixtures](Integration_Failing_Writer_Fixtures.md) (2 shared connections)
- [Object GET Coverage Tests](Object_GET_Coverage_Tests.md) (1 shared connections)
- [SigV4 Header and Presign Tests](SigV4_Header_and_Presign_Tests.md) (1 shared connections)
- [Bucket ACL and Accelerate Handlers](Bucket_ACL_and_Accelerate_Handlers.md) (1 shared connections)

## Source Files

- `internal/proxy/response/errors_coverage_test.go`

## Audit Trail

- EXTRACTED: 70 (90%)
- INFERRED: 8 (10%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*