# Multipart Handler Tests

> 93 nodes · cohesion 0.07

## Key Concepts

- **multipart/multipart_coverage_test.go** (63 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **MpuNewEnv()** (48 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **MpuVars()** (35 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **encoding/xml.Name** (30 connections)
- **.MpuInitiate()** (27 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **MpuParseError()** (18 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **MpuEnv** (18 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **.MpuUploadPart()** (16 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **.complete()** (15 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **.Header()** (13 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **MpuCompleteBody()** (11 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **.upload()** (11 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **MpuNewEnvWithProvider()** (10 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **writeXMLDocument()** (10 connections) — `internal/proxy/handlers/multipart/xml.go`
- **MpuPayload()** (9 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **TestMpuCompleteAcceptsFewerPartsThanWereUploaded()** (9 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **TestMpuCompleteBackendErrorsMapToS3Codes()** (9 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **TestMpuCompleteSelfCopyFailureIsReportedAsFailure()** (9 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **.create()** (9 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **TestMpuCompleteSelfCopyRunsWhenHeadObjectFails()** (8 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **TestMpuCompleteWithoutMetadataSkipsSelfCopy()** (8 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **TestMpuListPartsNeverReportsAnyPart()** (8 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **TestMpuUploadOutOfOrderPartParksTheRequestGoroutine()** (8 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **TestMpuUploadStoresCiphertextNotPlaintext()** (8 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **MpuAPIError()** (7 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- *... and 68 more nodes in this community*

## Relationships

- [Config Accessor Tests](Config_Accessor_Tests.md) (52 shared connections)
- [Multipart Handler Construction](Multipart_Handler_Construction.md) (19 shared connections)
- [S3 Error Mapping](S3_Error_Mapping.md) (4 shared connections)
- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (4 shared connections)
- [Multipart Create Handler Tests](Multipart_Create_Handler_Tests.md) (4 shared connections)
- [DeleteObjects Handler Tests](DeleteObjects_Handler_Tests.md) (3 shared connections)
- [DeleteObjects Batch Tests](DeleteObjects_Batch_Tests.md) (3 shared connections)
- [Bucket Sub-Resource Tests](Bucket_Sub-Resource_Tests.md) (3 shared connections)
- [Bucket Handler Test Fakes](Bucket_Handler_Test_Fakes.md) (2 shared connections)
- [ListBuckets Root Handler](ListBuckets_Root_Handler.md) (2 shared connections)
- [Bucket Sub-Resource Registry](Bucket_Sub-Resource_Registry.md) (2 shared connections)
- [Configuration Accessors](Configuration_Accessors.md) (2 shared connections)

## Source Files

- `internal/proxy/handlers/bucket/logging.go`
- `internal/proxy/handlers/bucket/subresource_matrix_coverage_test.go`
- `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- `internal/proxy/handlers/multipart/multipart_test.go`
- `internal/proxy/handlers/multipart/xml.go`
- `internal/proxy/response/xml_coverage_test.go`

## Audit Trail

- EXTRACTED: 401 (97%)
- INFERRED: 14 (3%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*