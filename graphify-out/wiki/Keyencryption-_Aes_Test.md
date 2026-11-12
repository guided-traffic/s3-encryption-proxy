# Keyencryption: Aes Test

> 24 nodes · cohesion 0.16

## Key Concepts

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
- **bytes.Buffer** (6 connections)
- **RtPxfailingWriter** (6 connections) — `internal/proxy/handlers/root/listbuckets_coverage_test.go`
- **TestRespErrorDocumentCarriesTheResponseRequestID()** (5 connections) — `internal/proxy/response/errors_coverage_test.go`
- **TestRespWriteS3Error_EscapesResource()** (5 connections) — `internal/proxy/response/errors_coverage_test.go`
- **teeBuffer** (4 connections) — `test/e2e/harness/exec.go`
- **s3Error** (4 connections) — `internal/proxy/response/errors.go`
- **io2()** (4 connections) — `test/e2e/harness/exec.go`
- **UtlNewFailingWriter()** (3 connections) — `internal/proxy/response/errors_coverage_test.go`
- **UtlSDKError()** (3 connections) — `internal/proxy/response/errors_coverage_test.go`
- **UtlLogEntry** (3 connections) — `internal/proxy/response/errors_coverage_test.go`
- **github.com/sirupsen/logrus.Level** (2 connections)
- **.Write()** (1 connections) — `test/e2e/harness/exec.go`
- **.Write()** (1 connections) — `internal/proxy/handlers/root/listbuckets_coverage_test.go`
- **.WriteHeader()** (1 connections) — `internal/proxy/handlers/root/listbuckets_coverage_test.go`

## Relationships

- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (19 shared connections)
- [Shutdown and Test Contexts](Shutdown_and_Test_Contexts.md) (12 shared connections)
- [Sub-Resource Handler Tests](Sub-Resource_Handler_Tests.md) (8 shared connections)
- [Request Middleware Plumbing](Request_Middleware_Plumbing.md) (2 shared connections)
- [Checksum Verifier](Checksum_Verifier.md) (1 shared connections)
- [Object Checksum and Tagging Tests](Object_Checksum_and_Tagging_Tests.md) (1 shared connections)
- [Bucket XML Documents](Bucket_XML_Documents.md) (1 shared connections)
- [Request Documents and Owner Guard](Request_Documents_and_Owner_Guard.md) (1 shared connections)
- [Harness: Exec](Harness-_Exec.md) (1 shared connections)

## Source Files

- `internal/proxy/handlers/root/listbuckets_coverage_test.go`
- `internal/proxy/response/errors.go`
- `internal/proxy/response/errors_coverage_test.go`
- `test/e2e/harness/exec.go`

## Audit Trail

- EXTRACTED: 81 (91%)
- INFERRED: 8 (9%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*