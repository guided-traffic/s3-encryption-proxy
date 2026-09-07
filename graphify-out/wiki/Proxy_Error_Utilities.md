# Proxy Error Utilities

> 51 nodes · cohesion 0.08

## Key Concepts

- **HandleS3Error()** (34 connections) — `internal/proxy/utils/utils.go`
- **utils_coverage_test.go** (22 connections) — `internal/proxy/utils/utils_coverage_test.go`
- **ReadRequestBody()** (13 connections) — `internal/proxy/utils/utils.go`
- **TestUtlHandleS3Error_DoesNotLeakBackendDetail()** (11 connections) — `internal/proxy/utils/utils_coverage_test.go`
- **UtlCaptureLogger()** (11 connections) — `internal/proxy/utils/utils_coverage_test.go`
- **TestUtlHandleS3Error_StatusDrivesLogLevel()** (10 connections) — `internal/proxy/utils/utils_coverage_test.go`
- **UtlDecodeLog()** (10 connections) — `internal/proxy/utils/utils_coverage_test.go`
- **TestUtlHandleS3Error_InternalTextStaysInternal()** (9 connections) — `internal/proxy/utils/utils_coverage_test.go`
- **TestUtlHandleS3Error_ResourceComposition()** (9 connections) — `internal/proxy/utils/utils_coverage_test.go`
- **TestUtlHandleS3Error_WriteFailureIsLogged()** (9 connections) — `internal/proxy/utils/utils_coverage_test.go`
- **TestUtlReadRequestBody_ErrorIsLoggedWithContext()** (8 connections) — `internal/proxy/utils/utils_coverage_test.go`
- **UtlFindLog()** (8 connections) — `internal/proxy/utils/utils_coverage_test.go`
- **utils_test.go** (7 connections) — `internal/proxy/utils/utils_test.go`
- **TestUtlHandleS3Error_NilError()** (7 connections) — `internal/proxy/utils/utils_coverage_test.go`
- **UtlParseErrorBody()** (7 connections) — `internal/proxy/utils/utils_coverage_test.go`
- **utils.go** (6 connections) — `internal/proxy/utils/utils.go`
- **TestHandleS3Error_EncryptionKeyMissing()** (6 connections) — `internal/proxy/utils/utils_test.go`
- **Item 3: two implementations of one error document** (5 connections) — `docs/tickets/022-s3-surface-fidelity.md`
- **TestUtlHandleS3Error_EscapesResource()** (5 connections) — `internal/proxy/utils/utils_coverage_test.go`
- **GetQueryParam()** (5 connections) — `internal/proxy/utils/utils.go`
- **S3ErrorResponse** (5 connections) — `internal/proxy/utils/utils.go`
- **TestReadRequestBody()** (5 connections) — `internal/proxy/utils/utils_test.go`
- **TestUtlParseMaxKeys_Boundaries()** (4 connections) — `internal/proxy/utils/utils_coverage_test.go`
- **TestUtlReadRequestBody_LargeBodyRoundTrip()** (4 connections) — `internal/proxy/utils/utils_coverage_test.go`
- **UtlSDKError()** (4 connections) — `internal/proxy/utils/utils_coverage_test.go`
- *... and 26 more nodes in this community*

## Relationships

- No strong cross-community connections detected

## Source Files

- `docs/architecture/callgraph_proxy_layer.svg`
- `docs/tickets/022-s3-surface-fidelity.md`
- `internal/proxy/server_test.go`
- `internal/proxy/utils/utils.go`
- `internal/proxy/utils/utils_coverage_test.go`
- `internal/proxy/utils/utils_test.go`

## Audit Trail

- EXTRACTED: 218 (79%)
- INFERRED: 57 (21%)
- AMBIGUOUS: 1 (0%)

---

*Part of the graphify knowledge wiki. See [[index]] to navigate.*