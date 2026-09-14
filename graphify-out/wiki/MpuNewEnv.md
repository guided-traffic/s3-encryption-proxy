# MpuNewEnv()

> God node · 51 connections · `internal/proxy/handlers/multipart/multipart_coverage_test.go`

**Community:** [Multipart Handler Tests](Multipart_Handler_Tests.md)

## Connections by Relation

### calls
- TestMpuCompleteStoresAChainThatReadsBack() `EXTRACTED`
- TestMpuCompleteRefusesAPartListThatIsNotTheUpload() `EXTRACTED`
- TestMpuUploadOutOfOrderPartIsStoredImmediately() `EXTRACTED`
- MpuNewEnvWithProvider() `EXTRACTED`
- TestMpuCompleteBackendErrorsMapToS3Codes() `EXTRACTED`
- TestMpuCompleteLocationPointsAtTheProxy() `EXTRACTED`
- TestMpuCompleteAbortsTheUploadItRefuses() `EXTRACTED`
- TestMpuCompleteForwardsBackendResponseHeaders() `EXTRACTED`
- TestMpuCompleteTrailerFailureIsReportedAsFailure() `EXTRACTED`
- TestMpuListPartsNeverReportsAnyPart() `EXTRACTED`
- TestMpuUploadRetryOfAPartIsSealedAgain() `EXTRACTED`
- TestMpuUploadStoresCiphertextNotPlaintext() `EXTRACTED`
- TestMpuCompleteBuildsThePartListItself() `EXTRACTED`
- TestMpuUploadBackendErrorsMapToS3Codes() `EXTRACTED`
- TestMpuAbortBackendErrorsMapToS3Codes() `EXTRACTED`
- TestMpuCompleteForwardsTheStoredETags() `EXTRACTED`
- TestMpuCompleteRejectsMalformedRequests() `EXTRACTED`
- TestMpuCreateBackendErrorsMapToS3Codes() `EXTRACTED`
- TestMpuUploadDropsBackendEncryptionHeaders() `EXTRACTED`
- TestMpuUploadOversizedShortPartNeverReachesTheBackend() `EXTRACTED`
- *…and 28 more `calls` connection(s) not listed (lowest-degree first to go)*

### contains
- multipart_coverage_test.go `EXTRACTED`

### references
- testing.T `EXTRACTED`
- MpuEnv `EXTRACTED`

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*