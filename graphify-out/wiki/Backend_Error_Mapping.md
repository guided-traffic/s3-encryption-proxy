# Backend Error Mapping

> 36 nodes · cohesion 0.12

## Key Concepts

- **MapError()** (26 connections) — `internal/proxy/response/error_mapping.go`
- **error_mapping_coverage_test.go** (22 connections) — `internal/proxy/response/error_mapping_coverage_test.go`
- **response/error_mapping_test.go** (16 connections) — `internal/proxy/response/error_mapping_test.go`
- **sdkError()** (10 connections) — `internal/proxy/response/error_mapping_test.go`
- **discardLogger()** (9 connections) — `internal/proxy/response/error_mapping_test.go`
- **RespStatusOnlyError()** (7 connections) — `internal/proxy/response/error_mapping_coverage_test.go`
- **TestMapError_NeverProducesInvalidStatus()** (6 connections) — `internal/proxy/response/error_mapping_test.go`
- **TestWriteS3Error_BucketOnlyResource()** (5 connections) — `internal/proxy/response/error_mapping_test.go`
- **TestWriteS3Error_ResponseDocument()** (5 connections) — `internal/proxy/response/error_mapping_test.go`
- **RespAPIErrorNoResponse()** (4 connections) — `internal/proxy/response/error_mapping_coverage_test.go`
- **TestRespMapErrorBackend5xxKeepsReasonPhrase()** (4 connections) — `internal/proxy/response/error_mapping_coverage_test.go`
- **TestRespMapErrorCodeForStatusFallback()** (4 connections) — `internal/proxy/response/error_mapping_coverage_test.go`
- **TestRespMapErrorCodeStatusTableMatchesAWS()** (4 connections) — `internal/proxy/response/error_mapping_coverage_test.go`
- **TestRespMapErrorEmptyMessageFallback()** (4 connections) — `internal/proxy/response/error_mapping_coverage_test.go`
- **TestRespMapErrorMarkerPrecedenceIsTextual()** (4 connections) — `internal/proxy/response/error_mapping_coverage_test.go`
- **TestRespMapErrorNonErrorStatusesBecome500()** (4 connections) — `internal/proxy/response/error_mapping_coverage_test.go`
- **TestRespMapErrorNotModifiedIsForwarded()** (4 connections) — `internal/proxy/response/error_mapping_coverage_test.go`
- **TestRespMapErrorUnknownCodeWithoutResponseIs500()** (4 connections) — `internal/proxy/response/error_mapping_coverage_test.go`
- **TestMapError_ConditionalGetKeepsIts304()** (4 connections) — `internal/proxy/response/error_mapping_test.go`
- **TestMapError_DoesNotLeakBackendDetail()** (4 connections) — `internal/proxy/response/error_mapping_test.go`
- **TestMapError_ErrorBehindANonErrorStatusBecomes500()** (4 connections) — `internal/proxy/response/error_mapping_test.go`
- **TestMapError_SDKErrorChains()** (4 connections) — `internal/proxy/response/error_mapping_test.go`
- **TestWriteS3Error_InternalErrorIsOpaque()** (4 connections) — `internal/proxy/response/error_mapping_test.go`
- **TestWriteS3Error_NilError()** (4 connections) — `internal/proxy/response/error_mapping_test.go`
- **error_mapping.go** (3 connections) — `internal/proxy/response/error_mapping.go`
- *... and 11 more nodes in this community*

## Relationships

- [Config Env Expansion](Config_Env_Expansion.md) (25 shared connections)
- [XML Response Helpers](XML_Response_Helpers.md) (10 shared connections)
- [Error Response Tests](Error_Response_Tests.md) (9 shared connections)
- [Proxy Server Tests](Proxy_Server_Tests.md) (1 shared connections)
- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (1 shared connections)
- [SigV4 Header Authentication](SigV4_Header_Authentication.md) (1 shared connections)

## Source Files

- `internal/proxy/response/error_mapping.go`
- `internal/proxy/response/error_mapping_coverage_test.go`
- `internal/proxy/response/error_mapping_test.go`

## Audit Trail

- EXTRACTED: 92 (75%)
- INFERRED: 31 (25%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*