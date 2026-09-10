# Multipart Handler Tests

> 80 nodes · cohesion 0.10

## Key Concepts

- **multipart_coverage_test.go** (67 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **MpuNewEnv()** (51 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **MpuVars()** (28 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **.MpuInitiate()** (28 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **.MpuUploadPart()** (28 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **MpuPayload()** (24 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **MpuEnv** (22 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **MpuParseError()** (21 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **.MpuComplete()** (17 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **.Header()** (16 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **TestMpuCompleteStoresAChainThatReadsBack()** (12 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **.MpuCaptureParts()** (12 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **TestMpuCompleteRefusesAPartListThatIsNotTheUpload()** (11 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **TestMpuUploadOutOfOrderPartIsStoredImmediately()** (11 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **MpuNewEnvWithProvider()** (10 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **TestMpuCompleteBackendErrorsMapToS3Codes()** (10 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **TestMpuCompleteLocationPointsAtTheProxy()** (10 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **writeXMLDocument()** (10 connections) — `internal/proxy/handlers/multipart/xml.go`
- **.create()** (10 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **TestMpuCompleteAbortsTheUploadItRefuses()** (9 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **TestMpuCompleteForwardsBackendResponseHeaders()** (9 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **TestMpuCompleteTrailerFailureIsReportedAsFailure()** (9 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **TestMpuListPartsNeverReportsAnyPart()** (9 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **TestMpuUnderTheExitProviderPassesThrough()** (9 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **TestMpuUploadRetryOfAPartIsSealedAgain()** (9 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- *... and 55 more nodes in this community*

## Relationships

- [Config Env Expansion](Config_Env_Expansion.md) (57 shared connections)
- [Multipart Handler](Multipart_Handler.md) (16 shared connections)
- [Multipart XML Documents](Multipart_XML_Documents.md) (6 shared connections)
- [Config Structure](Config_Structure.md) (2 shared connections)
- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (2 shared connections)
- [Object Helper Functions](Object_Helper_Functions.md) (2 shared connections)
- [Multipart Handler Unit Tests](Multipart_Handler_Unit_Tests.md) (2 shared connections)
- [Object Dispatch and Metadata Tests](Object_Dispatch_and_Metadata_Tests.md) (2 shared connections)
- [Object Header Conformance](Object_Header_Conformance.md) (2 shared connections)
- [Orchestration Manager](Orchestration_Manager.md) (1 shared connections)
- [XML Response Helpers](XML_Response_Helpers.md) (1 shared connections)
- [Error Response Tests](Error_Response_Tests.md) (1 shared connections)

## Source Files

- `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- `internal/proxy/handlers/multipart/xml.go`

## Audit Trail

- EXTRACTED: 411 (97%)
- INFERRED: 13 (3%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*