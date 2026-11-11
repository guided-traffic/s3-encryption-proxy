# MpuNewEnv()

> God node · 71 connections · `internal/proxy/handlers/multipart/multipart_coverage_test.go`

**Community:** [Multipart Checksum Answers](Multipart_Checksum_Answers.md)

## Connections by Relation

### calls
- MpuNewEnvWithProvider() `EXTRACTED`
- TestMpuCompleteRefusesAPartListThatIsNotTheUpload() `EXTRACTED`
- TestMpuCompleteStoresAChainThatReadsBack() `EXTRACTED`
- TestMpuUploadOversizedShortPartIsRefusedBeforeItIsRead() `EXTRACTED`
- TestMpuAbortBackendErrorsMapToS3Codes() `EXTRACTED`
- TestMpuCompleteBackendErrorsMapToS3Codes() `EXTRACTED`
- TestMpuCompleteRejectsMalformedRequests() `EXTRACTED`
- TestMpuCompleteTrailerFailureIsReportedAsFailure() `EXTRACTED`
- TestMpuCreateBackendErrorsMapToS3Codes() `EXTRACTED`
- TestMpuUploadBackendErrorsMapToS3Codes() `EXTRACTED`
- TestMpuUploadOutOfOrderPartIsStoredImmediately() `EXTRACTED`
- TestMpuUploadPartCopyRefusesEveryVariant() `EXTRACTED`
- TestMpuUploadStoresCiphertextNotPlaintext() `EXTRACTED`
- TestMpuTagListPartsAnswersTheMarker() `INFERRED`
- TestMpuAbortMissingUploadIDIsInvalidArgument() `EXTRACTED`
- TestMpuCompleteAbortsTheUploadItRefuses() `EXTRACTED`
- TestMpuCompleteLocationPointsAtTheProxy() `EXTRACTED`
- TestMpuCompleteRefusesAListOutOfOrder() `EXTRACTED`
- TestMpuCompleteUnreadableBodyIsRejected() `EXTRACTED`
- TestMpuHandlerFacadeWiresEverySubHandler() `EXTRACTED`
- *…and 48 more `calls` connection(s) not listed (lowest-degree first to go)*

### contains
- multipart_coverage_test.go `EXTRACTED`

### references
- testing.T `EXTRACTED`
- MpuEnv `EXTRACTED`

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*