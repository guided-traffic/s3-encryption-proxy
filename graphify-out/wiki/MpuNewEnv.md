# MpuNewEnv()

> God node · 71 connections · `internal/proxy/handlers/multipart/multipart_coverage_test.go`

**Community:** [Multipart Handler Coverage Tests](Multipart_Handler_Coverage_Tests.md)

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
- TestMpuCompleteRefusesAListOutOfOrder() `EXTRACTED`
- TestMpuCompleteTrailerFailureIsReportedAsFailure() `EXTRACTED`
- TestMpuListPartsAnswersFromThePartTable() `EXTRACTED`
- TestMpuUploadKeepsAStoredPartWhenALaterAttemptFails() `EXTRACTED`
- TestMpuUploadOversizedShortPartIsRefusedBeforeItIsRead() `EXTRACTED`
- TestMpuUploadRetryOfAPartIsSealedAgain() `EXTRACTED`
- TestMpuUploadStoresCiphertextNotPlaintext() `EXTRACTED`
- TestMpuCompleteBuildsThePartListItself() `EXTRACTED`
- TestMpuListPartsPaginates() `EXTRACTED`
- TestMpuUploadBackendErrorsMapToS3Codes() `EXTRACTED`
- TestMpuAbortBackendErrorsMapToS3Codes() `EXTRACTED`
- TestMpuCompleteForwardsTheStoredETags() `EXTRACTED`
- *…and 48 more `calls` connection(s) not listed (lowest-degree first to go)*

### contains
- multipart_coverage_test.go `EXTRACTED`

### references
- testing.T `EXTRACTED`
- MpuEnv `EXTRACTED`

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*