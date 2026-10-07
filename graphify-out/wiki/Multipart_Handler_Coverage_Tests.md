# Multipart Handler Coverage Tests

> 97 nodes · cohesion 0.09

## Key Concepts

- **multipart_coverage_test.go** (91 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **MpuNewEnv()** (71 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **MpuPayload()** (50 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **MpuVars()** (40 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **.MpuInitiate()** (39 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **.MpuUploadPart()** (33 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **MpuParseError()** (27 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **MpuEnv** (24 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **.MpuComplete()** (19 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **.upload()** (16 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **MpuNewExitEnv()** (15 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **.MpuCaptureParts()** (15 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **.Header()** (15 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **TestMpuCompleteStoresAChainThatReadsBack()** (12 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **.MpuExitUpload()** (12 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **TestMpuCompleteRefusesAPartListThatIsNotTheUpload()** (11 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **TestMpuUploadOutOfOrderPartIsStoredImmediately()** (11 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **.create()** (11 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **MpuNewEnvWithProvider()** (10 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **TestMpuCompleteBackendErrorsMapToS3Codes()** (10 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **TestMpuCompleteLocationPointsAtTheProxy()** (10 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **TestMpuCompleteAbortsTheUploadItRefuses()** (9 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **TestMpuCompleteForwardsBackendResponseHeaders()** (9 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **TestMpuCompleteRefusesAListOutOfOrder()** (9 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **TestMpuCompleteTrailerFailureIsReportedAsFailure()** (9 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- *... and 72 more nodes in this community*

## Relationships

- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (79 shared connections)
- [Multipart Checksum Echo Tests](Multipart_Checksum_Echo_Tests.md) (14 shared connections)
- [Multipart Handler Wiring](Multipart_Handler_Wiring.md) (13 shared connections)
- [Etag Marker](Etag_Marker.md) (10 shared connections)
- [XML Document Marshalling](XML_Document_Marshalling.md) (6 shared connections)
- [Bucket ACL and Accelerate Handlers](Bucket_ACL_and_Accelerate_Handlers.md) (4 shared connections)
- [Multipart Counting Readers](Multipart_Counting_Readers.md) (3 shared connections)
- [Object Dispatch Coverage Tests](Object_Dispatch_Coverage_Tests.md) (3 shared connections)
- [Multipart](Multipart.md) (2 shared connections)
- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (2 shared connections)
- [Configuration Struct and Accessors](Configuration_Struct_and_Accessors.md) (2 shared connections)
- [Segmented Manager Streaming IO](Segmented_Manager_Streaming_IO.md) (2 shared connections)

## Source Files

- `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- `internal/proxy/handlers/multipart/xml.go`

## Audit Trail

- EXTRACTED: 547 (94%)
- INFERRED: 35 (6%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*