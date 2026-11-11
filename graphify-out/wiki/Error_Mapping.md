# Error Mapping

> 41 nodes · cohesion 0.07

## Key Concepts

- **MapError()** (31 connections) — `internal/proxy/response/error_mapping.go`
- **sdkError()** (10 connections) — `internal/proxy/response/error_mapping_test.go`
- **discardLogger()** (9 connections) — `internal/proxy/response/error_mapping_test.go`
- **RespStatusOnlyError()** (7 connections) — `internal/proxy/response/error_mapping_coverage_test.go`
- **checksumVerdict()** (6 connections) — `internal/proxy/response/error_mapping.go`
- **TestMapError_NeverProducesInvalidStatus()** (6 connections) — `internal/proxy/response/error_mapping_test.go`
- **TestErrorWriter_ControlCharacterStaysWellFormed()** (6 connections) — `internal/proxy/response/errors_test.go`
- **TestErrorWriter_HostileInputStaysWellFormedXML()** (6 connections) — `internal/proxy/response/errors_test.go`
- **TestWriteS3Error_BucketOnlyResource()** (5 connections) — `internal/proxy/response/error_mapping_test.go`
- **TestWriteS3Error_ResponseDocument()** (5 connections) — `internal/proxy/response/error_mapping_test.go`
- **decodeErrorDocument()** (5 connections) — `internal/proxy/response/errors_test.go`
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
- *... and 16 more nodes in this community*

## Relationships

- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (40 shared connections)
- [Shutdown and Test Contexts](Shutdown_and_Test_Contexts.md) (29 shared connections)
- [Sub-Resource Handler Tests](Sub-Resource_Handler_Tests.md) (7 shared connections)
- [Request Documents and Owner Guard](Request_Documents_and_Owner_Guard.md) (2 shared connections)
- [Response: Error Mapping Coverage Test](Response-_Error_Mapping_Coverage_Test.md) (2 shared connections)
- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (2 shared connections)
- [ADR Corpus and Release History](ADR_Corpus_and_Release_History.md) (1 shared connections)
- [S3 API Behaviour](S3_API_Behaviour.md) (1 shared connections)
- [Exit Provider and Session Lifecycle](Exit_Provider_and_Session_Lifecycle.md) (1 shared connections)
- [Bucket XML Documents](Bucket_XML_Documents.md) (1 shared connections)

## Source Files

- `docs/developer/errors.md`
- `internal/proxy/request/checksum.go`
- `internal/proxy/response/error_mapping.go`
- `internal/proxy/response/error_mapping_coverage_test.go`
- `internal/proxy/response/error_mapping_test.go`
- `internal/proxy/response/errors_test.go`

## Audit Trail

- EXTRACTED: 106 (75%)
- INFERRED: 35 (25%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*