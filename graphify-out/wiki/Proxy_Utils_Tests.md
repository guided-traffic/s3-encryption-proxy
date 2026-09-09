# Proxy Utils Tests

> 20 nodes · cohesion 0.32

## Key Concepts

- **utils_coverage_test.go** (22 connections) — `internal/proxy/utils/utils_coverage_test.go`
- **HandleS3Error()** (18 connections) — `internal/proxy/utils/utils.go`
- **UtlCaptureLogger()** (13 connections) — `internal/proxy/utils/utils_coverage_test.go`
- **UtlDecodeLog()** (12 connections) — `internal/proxy/utils/utils_coverage_test.go`
- **UtlFindLog()** (9 connections) — `internal/proxy/utils/utils_coverage_test.go`
- **UtlParseErrorBody()** (9 connections) — `internal/proxy/utils/utils_coverage_test.go`
- **TestUtlHandleS3Error_DoesNotLeakBackendDetail()** (8 connections) — `internal/proxy/utils/utils_coverage_test.go`
- **TestUtlHandleS3Error_StatusDrivesLogLevel()** (8 connections) — `internal/proxy/utils/utils_coverage_test.go`
- **TestUtlHandleS3Error_InternalTextStaysInternal()** (7 connections) — `internal/proxy/utils/utils_coverage_test.go`
- **TestUtlHandleS3Error_NilError()** (7 connections) — `internal/proxy/utils/utils_coverage_test.go`
- **TestUtlHandleS3Error_ResourceComposition()** (7 connections) — `internal/proxy/utils/utils_coverage_test.go`
- **TestUtlHandleS3Error_WriteFailureIsLogged()** (7 connections) — `internal/proxy/utils/utils_coverage_test.go`
- **TestUtlReadRequestBody_ErrorIsLoggedWithContext()** (6 connections) — `internal/proxy/utils/utils_coverage_test.go`
- **TestUtlHandleS3Error_EscapesResource()** (5 connections) — `internal/proxy/utils/utils_coverage_test.go`
- **TestUtlReadRequestBody_LargeBodyRoundTrip()** (5 connections) — `internal/proxy/utils/utils_coverage_test.go`
- **bytes.Buffer** (4 connections)
- **TestUtlCleanupContext()** (3 connections) — `internal/proxy/utils/utils_coverage_test.go`
- **UtlSDKError()** (3 connections) — `internal/proxy/utils/utils_coverage_test.go`
- **UtlLogEntry** (3 connections) — `internal/proxy/utils/utils_coverage_test.go`
- **UtlCtxKey** (1 connections) — `internal/proxy/utils/utils_coverage_test.go`

## Relationships

- [Config Accessor Tests](Config_Accessor_Tests.md) (12 shared connections)
- [Proxy Utility Functions](Proxy_Utility_Functions.md) (9 shared connections)
- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (4 shared connections)
- [Failing Writer Test Fake](Failing_Writer_Test_Fake.md) (3 shared connections)
- [Proxy Server Auth Error Tests](Proxy_Server_Auth_Error_Tests.md) (3 shared connections)
- [ListBuckets Root Handler](ListBuckets_Root_Handler.md) (1 shared connections)
- [Chunk Framing Test Helpers](Chunk_Framing_Test_Helpers.md) (1 shared connections)
- [Broken Reader Test Fake](Broken_Reader_Test_Fake.md) (1 shared connections)
- [License Logging](License_Logging.md) (1 shared connections)
- [SigV4 Pre-Signed URL Auth](SigV4_Pre-Signed_URL_Auth.md) (1 shared connections)
- [S3 Error Mapping](S3_Error_Mapping.md) (1 shared connections)

## Source Files

- `internal/proxy/utils/utils.go`
- `internal/proxy/utils/utils_coverage_test.go`

## Audit Trail

- EXTRACTED: 85 (88%)
- INFERRED: 12 (12%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*