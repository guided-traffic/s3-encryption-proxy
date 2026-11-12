# Multipart Checksum Answers

> 101 nodes · cohesion 0.06

## Key Concepts

- **multipart_coverage_test.go** (173 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **MpuNewEnv()** (71 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **MpuPayload()** (50 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **MpuVars()** (40 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **MpuParseError()** (27 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **MpuNewExitEnv()** (15 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **MpuNewEnvWithProvider()** (9 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **writeXMLDocument()** (9 connections) — `internal/proxy/handlers/multipart/xml.go`
- **MpuDigest()** (8 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **MpuCrcwant()** (7 connections) — `internal/proxy/handlers/multipart/checksum_echo_test.go`
- **TestMpuCompleteRefusesAPartListThatIsNotTheUpload()** (7 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **TestMpuCompleteStoresAChainThatReadsBack()** (7 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **TestMpuUploadOversizedShortPartIsRefusedBeforeItIsRead()** (7 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **MpuTagacceptParts()** (6 connections) — `internal/proxy/handlers/multipart/etag_marker_test.go`
- **TestMpuTagListPartsAnswersTheMarker()** (6 connections) — `internal/proxy/handlers/multipart/etag_marker_test.go`
- **MpuAPIError()** (6 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **TestMpuAbortBackendErrorsMapToS3Codes()** (6 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **TestMpuCompleteBackendErrorsMapToS3Codes()** (6 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **TestMpuCompleteRejectsMalformedRequests()** (6 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **TestMpuCompleteTrailerFailureIsReportedAsFailure()** (6 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **TestMpuCreateBackendErrorsMapToS3Codes()** (6 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **TestMpuUploadBackendErrorsMapToS3Codes()** (6 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **TestMpuUploadOutOfOrderPartIsStoredImmediately()** (6 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **TestMpuUploadPartCopyRefusesEveryVariant()** (6 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **TestMpuUploadStoresCiphertextNotPlaintext()** (6 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- *... and 76 more nodes in this community*

## Relationships

- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (91 shared connections)
- [Shutdown and Test Contexts](Shutdown_and_Test_Contexts.md) (83 shared connections)
- [Misc (19)](Misc_19.md) (10 shared connections)
- [Bucket XML Documents](Bucket_XML_Documents.md) (5 shared connections)
- [Sub-Resource Handler Tests](Sub-Resource_Handler_Tests.md) (3 shared connections)
- [Multipart Handlers and Manager](Multipart_Handlers_and_Manager.md) (3 shared connections)
- [Dataencryption: Segmented Gcm Range](Dataencryption-_Segmented_Gcm_Range.md) (2 shared connections)
- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (2 shared connections)
- [Request Documents and Owner Guard](Request_Documents_and_Owner_Guard.md) (2 shared connections)
- [Configuration Loading](Configuration_Loading.md) (1 shared connections)
- [Segment Codec and Range Planner](Segment_Codec_and_Range_Planner.md) (1 shared connections)
- [Request Middleware Plumbing](Request_Middleware_Plumbing.md) (1 shared connections)

## Source Files

- `internal/proxy/handlers/multipart/checksum_echo_test.go`
- `internal/proxy/handlers/multipart/etag_marker_test.go`
- `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- `internal/proxy/handlers/multipart/xml.go`

## Audit Trail

- EXTRACTED: 483 (94%)
- INFERRED: 33 (6%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*