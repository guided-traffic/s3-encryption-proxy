# EnsureMinIOAndProxyAvailable()

> God node · 109 connections · `test/integration/minio_test_helper.go`

**Community:** [AWS-Chunked Reader Tests](AWS-Chunked_Reader_Tests.md)

## Connections by Relation

### calls
- TestMpuThreePartRoundTrip() `EXTRACTED`
- TestComprehensiveMultipartUpload() `EXTRACTED`
- TestMpuPartsUploadedOutOfOrder() `EXTRACTED`
- TestComprehensiveSinglePartUpload() `EXTRACTED`
- TestDelBatchDeleteThreeExistingKeys() `EXTRACTED`
- TestMpuHeldPartResentAtStreamingSize() `EXTRACTED`
- TestSinglePartUploadCornerCases() `EXTRACTED`
- TestSegmentChainRefusesTamperedBytes() `EXTRACTED`
- TestDelBatchDeleteIntegrityHeaderIsEnforced() `EXTRACTED`
- TestDelBatchDeleteKeysNeedingXMLEscaping() `EXTRACTED`
- TestDelBatchDeleteMixOfExistingAndMissingKeys() `EXTRACTED`
- TestDelBatchDeleteQuietMode() `EXTRACTED`
- lstNewRefFixture() `EXTRACTED`
- TestLstListingDocumentOnTheWire() `EXTRACTED`
- TestMpuAbortRemovesTheUpload() `EXTRACTED`
- TestMpuCompleteWithBadPartReferences() `EXTRACTED`
- TestMpuCompleteWithPartsOutOfOrder() `EXTRACTED`
- TestHdrETagIsPresentAndStableAcrossRepeatedHeads() `EXTRACTED`
- TestHdrHeadReturnsTheSameHeaderSetAsGet() `EXTRACTED`
- TestDelBatchDeleteRemovesLargeEncryptedObjects() `EXTRACTED`
- *…and 87 more `calls` connection(s) not listed (lowest-degree first to go)*

### contains
- minio_test_helper.go `EXTRACTED`

### references
- testing.T `EXTRACTED`

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*